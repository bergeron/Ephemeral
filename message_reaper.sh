#!/bin/bash

# The reaper comes every <num_minutes> minutes to 
# reap (delete) the souls of expired messages.

usage="Usage: (message_reaper.sh kill) or (message_reaper.sh <num_minutes>)"

# Must have 1 parameter. Must be "kill" or positive integer
if [[ $2 != "" || $1 != "kill" && ! $1 =~ ^[0-9]+$ ]]
then
    echo $usage
    exit
fi

# Get db_name, username, password from mysql.priv
db_name=$(sed -n '1p' < mysql.priv)
username=$(sed -n '2p' < mysql.priv)
password=$(sed -n '3p' < mysql.priv)

# $1 is the command
run_mysql_cmd (){
    echo $(mysql --disable-column-names --user=$username --password=$password $db_name -e "$1")
}

# Enable event scheduler
`run_mysql_cmd "SET GLOBAL event_scheduler = ON;"`

# Delete job
dt_curr=`date -u +"%Y-%m-%d %H:%M:%S"`
job="delete from messages where dt_delete <= '$dt_curr'"

curr_interval=`run_mysql_cmd "select INTERVAL_VALUE from INFORMATION_SCHEMA.EVENTS where EVENT_NAME = \"message_reaper\";"`
if [[ $curr_interval ]]  # Reaper already running.
then
    if [[ $1 == "kill" ]]
    then #Kill the reaper.
        `run_mysql_cmd "drop event message_reaper;"`
        echo "Killed the reaper (interval was $curr_interval minutes)."
    else #Override existing reaper ?
        echo "There is alreaedy a reaper coming every $curr_interval minutes."
        echo "Do you want to override this interval to $1? (y/n)"

        while true; do
            read input
            if [[ $input == "n" ]]
            then
                exit
            elif [[ $input == "y" ]]
            then #Kill old reaper, make new one
                `run_mysql_cmd "drop event message_reaper;"`
                `run_mysql_cmd "create event message_reaper on schedule every $1 minute do $job;"`
                echo "Created a new message reaper to run every $1 minutes."
                break
            else
                echo "Continue? (y/n)"
            fi
        done
    fi
else #No existing reaper
    if [[ $1 == "kill" ]]
    then
         echo "No reaper to kill."
    else #Create new reaper.
        `run_mysql_cmd "create event message_reaper on schedule every $1 minute do $job;"`
        echo "Created a new message reaper to run every $1 minutes."
    fi
fi
