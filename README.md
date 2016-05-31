# postgres-mitm

Test whether your Postgres connections are vulnerable to MitM attacks.


## Steps to test your exposure

* Run the script with the IP of the database you want to impersonate:
  `postgres_mitm.py <IP of actual database>`
* Replace your database hostname with the IP of the machine running the script
* See if your app works.

If your app successfully connects to the database, it didn't validate certficates and accepted whatever was presented. The credentials for the database will be printed by the script. If you're seeing connection errors that's good, and means you're probably not vulnerable.

## If you're vulnerable

If you only have one database you can add its certificate to your trust store to prevent attacks like this one. The default trust store is `~/.postgresql/root.crt`, but you can customize this with the connection parameter `sslrootcert`.

If you're connecting to a database pool or are hosting many databases you should probably create your own Certificate Authority (CA) that can sign certificates for each database. Then the clients only need to trust the CA certificate and will have a secure connection to any of the databases signed by the CA.

As always, consult the [excellent documentation](https://www.postgresql.org/docs/9.0/static/libpq-connect.html#LIBPQ-CONNECT-SSLMODE) for details.
