Ephemeral
=========

## https://ephemeral.pw


Ephemeral lets you send messages that are destroyed when read.  After you create the message, you are given a URL that allows the recipient to read the message.  The message is destroyed upon being read.


Messages are encrypted with a 128 bit [symmetric AES cipher](http://en.wikipedia.org/wiki/Advanced_Encryption_Standard).  The key is never persistently stored on the server.  The key is saved only in the message's URL, not the database.  An attacker with database access would see only encrypted data.

Ephemeral uses SSL/TLS.  The maximum message length is 16000 characters.

### MySQL

* Configure db_name, username, password in ```mysql.priv```
* run ```./message_reaper.sh <num_minutes>```.  The message reaper is a MySQL event that runs every ```<num_minutes>``` minutes.  It reaps (deletes) the souls of expired messages.
* To reset the database, run ```./reset_db.sh```.
