# postgres-mitm

Test whether your Postgres connections are vulnerable to MitM attacks.


## Steps to test your exposure

* Run the script with the IP of the database you want to impersonate:
  `postgres_mitm.py <IP of actual database>`
* Replace your database hostname with the IP of the machine running the script
* See if your app works.

If your app successfully connects to the database, it didn't validate certficates and accepted whatever was presented. The credentials for the database will be printed by the script. If you're seeing connection errors that's good, and means you're probably not vulnerable.


### Heroku

Since changing the database hostname used by Heroku is hard, to test your connection against the database find it's IP (just extract it from the hostname), and start the script with that, then locally point the DNS of the database host to 127.0.0.1:

```
# Terminal 1
$ echo "127.0.0.1 $(heroku config:get DATABASE_URL | grep -o ec2-[^:]*)" | sudo tee -a /etc/hosts
127.0.0.1 ec2-54-163-238-215.compute-1.amazonaws.com
$ heroku pg:psql
---> Connecting to DATABASE_URL
psql (9.4.5)
SSL connection (protocol: TLSv1.2, cipher: ECDHE-ECDSA-AES256-GCM-SHA384, bits: 256, compression: on)
Type "help" for help.

mega-mitm::DATABASE=> select user;
  current_user
----------------
 fxutzshsavlfyj
(1 row)

mega-mitm::DATABASE=>

# Terminal 2
$ ./postgres_mitm.py 54.163.238.215
2016-06-06 10:28:47,634 [INFO] Listening for connections
2016-06-06 10:28:56,383 [INFO] Intercepted auth: postgres://fxutzshsavlfyj:Yp1DA<..>eJfAtu@54.163.238.215:5432/d4ajdorhb758hq
```

You could pin the database certificate, but note that this will break your app once it's moved to a different host for maintenance by Heroku. Not much we can do about that until they sign their certificates with their own CA.

```
# Terminal 1 again, pin the certificate
$ ./postgres_get_server_cert.py 54.163.238.215 > ~/.postgresql/root.crt
$ heroku pg:psql
---> Connecting to DATABASE_URL
psql: SSL error: certificate verify failed
# Good, MitM now fails, remove line we added to /etc/hosts and try again
# against actual database
$ heroku pg:psql
--> Connecting to DATABASE_URL
psql (9.4.5)
SSL connection (protocol: TLSv1.2, cipher: ECDHE-RSA-AES256-GCM-SHA384, bits: 256, compression: off)
Type "help" for help.

mega-mitm::DATABASE=>
# Winning
```

## If you're vulnerable

If you only have one database you can add its certificate to your trust store to prevent attacks like this one. The default trust store is `~/.postgresql/root.crt`, but you can customize this with the connection parameter `sslrootcert`.

If you're connecting to a database pool or are hosting many databases you should probably create your own Certificate Authority (CA) that can sign certificates for each database. Then the clients only need to trust the CA certificate and will have a secure connection to any of the databases signed by the CA.

As always, consult the [excellent documentation](https://www.postgresql.org/docs/9.0/static/libpq-connect.html#LIBPQ-CONNECT-SSLMODE) for details.
