Ephemeral
=========

## www.ephemeral.pw


Ephemeral lets you send messages that are destroyed when read.  After you create the message, we give you a URL that allows the recipient to read the message.  Upon being read, the note is destroyed.


Messages are encrypted with a 128 bit [symmetric AES cipher](http://en.wikipedia.org/wiki/Advanced_Encryption_Standard).  The key is in the URL, and we throw away they key so it is never stored in our database.  If the database was stolen, there would be no way to decrypt the messages.  We use SSL/TLS.  The maximum message length is 16000 characters.

### MySQL

* Configure db_name, username, password in ```mysql.priv```
* run ```./message_reaper.sh <num_minutes>```.  The message reaper is a MySQL event that runs every ```<num_minutes>``` minutes.  It reaps (deletes) the souls of expired messages.
* To reset the database, run ```./reset_db.sh```.
