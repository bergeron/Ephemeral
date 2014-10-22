#!/bin/bash

# Drops and recreates the messaging table with the given schema.

schema="(secret VARBINARY(16),encryptedtext VARBINARY(43688),dt_created DATETIME,dt_delete DATETIME)"

# Get db_name, username, password from mysql.priv
db_name=$(sed -n '1p' < mysql.priv)
username=$(sed -n '2p' < mysql.priv)
password=$(sed -n '3p' < mysql.priv)

echo "Warning! This will drop table messages in database $db_name."
echo "It will be recreated with schema:"
echo ""
echo $schema | tr , "\n"
echo ""
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
`run_mysql_cmd "create table messages $schema;"`
echo "Database reset."
