#!/bin/bash

filename="mysql.priv"

i=-1
while read line
do
    ((i++))
    if [ "$i" -eq 0 ]
        then tablename=$line;

    elif [ "$i" -eq 1 ]
        then username=$line

    elif [ "$i" -eq 2 ]
        then password=$line
    else
        break
    fi
done < $filename

out="$(mysql --user=$username --password=$password $tablename -e "show events;")"

if [[ "$out" == *"auto_delete"* ]]
then
    echo "auto_delete event already running in MySQL"
else
    echo "starting auto_delete event in MySQL"
    cmd="create event auto_delete on schedule every 9999 minute do delete from messages;"
    `(mysql --user=$username --password=$password $tablename -e "$cmd" )`
fi