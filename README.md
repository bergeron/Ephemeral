Ephemeral
=========

## www.ephemeral.pw


Ephemeral lets you send messages that are destroyed when read.  After you create the message, we give you a URL that allows the recipient to read the message.  Upon being read, the note is destroyed.


Messages are encrypted with a 128 bit [symmetric AES cipher] (http://en.wikipedia.org/wiki/Advanced_Encryption_Standard).  The key is in the URL, and we throw away they key so it is never stored in our database.  If the database was stolen, there would be no way to decrypt the messages.  We use SSL/TLS.  The maximum message length is 16000 characters.

Written in Go.

### MySQL

* Configure tablename, username, password in ```mysql.priv```
* Set the MySQL system variable [```event_scheduler```](http://dev.mysql.com/doc/refman/5.1/en/server-system-variables.html#sysvar_event_scheduler) to ```ON```.  The auto-deletion of message runs as a MySQL event.
* To run the auto-deleter, run ```./start_auto_delete.sh```

