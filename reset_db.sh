#!/bin/bash

# Drops and recreates the messaging table with the given schema.

messages_schema="(id VARBINARY(32) NOT NULL,encrypted_text VARBINARY(43688) NOT NULL,salt VARCHAR(255),dt_created_epoch BIGINT NOT NULL,expire_minutes INT,server_encrypted BOOLEAN NOT NULL)"
chats_schema="(chatId VARBINARY(32) NOT NULL,dt_created DATETIME NOT NULL)"
chat_msgs_schema="(chatId VARBINARY(32),encrypted_text VARBINARY(43688) NOT NULL,username VARCHAR(255),dt_created DATETIME NOT NULL,dt_delete DATETIME NOT NULL)"


# Get db_name, username, password from mysql.priv
db_name=$(sed -n '1p' < mysql.priv)
username=$(sed -n '2p' < mysql.priv)
password=$(sed -n '3p' < mysql.priv)

echo "Warning! This will drop tables {messages, chats} in database $db_name."
echo "They will be recreated with schema:"
echo ""
echo "messages:"
echo $messages_schema | tr , "\n"
echo ""
echo "chats:"
echo $chats_schema | tr , "\n"
echo ""
echo "chat_msgs:"
echo $chat_msgs_schema | tr , "\n"
echo "Continue? (y/n)"

while true; do
    read input

    if [[ $input == "n" ]]
    then
        exit
    elif [[ $input == "y" ]]
    then
        break
    else
        echo "Continue? (y/n)"
    fi
done

# $1 = the command
run_mysql_cmd (){
    echo $(mysql --user=$username --password=$password $db_name -e "$1")
}


`run_mysql_cmd "drop table messages;"`
`run_mysql_cmd "create table messages $messages_schema;"`
`run_mysql_cmd "drop table chats;"`
`run_mysql_cmd "create table chats $chats_schema;"`
`run_mysql_cmd "drop table chat_msgs;"`
`run_mysql_cmd "create table chat_msgs $chat_msgs_schema;"`
echo "Database reset."
