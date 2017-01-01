## pam_mariadb
A PAM module for authentication with user information from a MariaDB database

The following packages are required to build pam_mariadb:
```
mariadb-devel, pam-devel, openssl-devel
```

### Configuration options

* config_file - Location of the config file
* debug - Enables debug logging to the syslog. yes to enable (Default: no)
* dbserver - The hostname to the database server (Default: localhost)
* dbuser - Username for the database connection
* dbpassword - Password for the database connection
* dbname - Name of the database in which the user information is located (Default: userdb)
* pwdalgo - Password hash algorithm (Default: sha512)
  * sha512
  * sha256
  * sha1
  * md5
* pwdstyle - Style in which the hash is stored (Default: hex)
  * hex - Hex-encoded value of the hash
  * curlyb64 - Hash-algorithm inside curly braces and b64-encoded hash (Suitable for use with proftpd/mod_mysql)
* useridcolumn - Column where the username is stored (Default: userid)
* pwdcolumn - Column where the password hash is stored (Default: passwd)
* usertable - Name of the table where the user data is stored (Default: users)
* userwhere - Extra conditions to use when selecting the user. Optional.

### How to enable

Here's an example on how to enable authentication with pam_mariadb

```
#%PAM-1.0
auth	required	pam_mariadb.so	config_file=/etc/pamtest.conf
```
