Ephemeral
=========

[![SSL Rating](http://sslbadge.org/?domain=ephemeral.pw)](https://www.ssllabs.com/ssltest/analyze.html?d=ephemeral.pw)

## https://ephemeral.pw

Ephemeral lets you send temporary, encrypted messages. After creating a message, you are given a URL that allows the recipient to read the message. The message is destroyed upon being read.

### MySQL

* Configure db_name, username, password in ```mysql.priv```
* run ```./message_reaper.sh <num_minutes>```.  The message reaper is a MySQL event that runs every ```<num_minutes>``` minutes.  It reaps (deletes) the souls of expired messages.
* To reset the database, run ```./reset_db.sh```
