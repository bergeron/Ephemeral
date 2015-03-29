#!/bin/bash

# Drops and recreates tables according to schema.

messages_schema="(id VARBINARY(32) NOT NULL,encrypted_text VARBINARY(43688) NOT NULL,salt VARCHAR(255),dt_created_epoch BIGINT NOT NULL,expire_minutes INT,server_encrypted BOOLEAN NOT NULL)"
chatrooms_schema="(id VARBINARY(32) NOT NULL,salt VARCHAR(255) NOT NULL,dt_created DATETIME NOT NULL)"
nicknames_schema="(id VARBINARY(32) NOT NULL,chatroom_id VARBINARY(32) NOT NULL,encrypted_nickname VARCHAR(255) NOT NULL,dt_created DATETIME NOT NULL)"
invites_schema="(id VARBINARY(32) NOT NULL,chatroom_id VARBINARY(32) NOT NULL,dt_created DATETIME NOT NULL)"

db_name=$(sed -n '1p' < mysql.priv)
username=$(sed -n '2p' < mysql.priv)
password=$(sed -n '3p' < mysql.priv)

echo "Warning! This will drop tables {messages, chatrooms, nicknames, invites} in database $db_name."
echo "They will be recreated with schema:"
echo ""
echo "messages:"
echo $messages_schema | tr , "\n"
echo ""
echo "chatrooms:"
echo $chatrooms_schema | tr , "\n"
echo ""
echo "nicknames:"
echo $nicknames_schema | tr , "\n"
echo ""
echo "invites:"
echo $invites_schema | tr , "\n"
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
`run_mysql_cmd "drop table chatrooms;"`
`run_mysql_cmd "create table chatrooms $chatrooms_schema;"`
`run_mysql_cmd "drop table nicknames;"`
`run_mysql_cmd "create table nicknames $nicknames_schema;"`
`run_mysql_cmd "drop table invites;"`
`run_mysql_cmd "create table invites $invites_schema;"`
echo "Database reset."
