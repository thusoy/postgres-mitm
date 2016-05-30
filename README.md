# postgres-mitm

Test whether your Postgres connections are vulnerable to MitM attacks.


## Steps to test your exposure

* Run the script with the IP of the database you want to impersonate:
  `postgres_mitm.py <IP of actual database>`
* Replace your database hostname with the IP of the machine running the script
* See if your app works.

If your app successfully connects to the database, it didn't validate certficates and accepted whatever was presented. The credentials for the database will be printed by the script. If you're seeing connection errors that's good, and means you're probably not vulnerable.
