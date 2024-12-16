#!/bin/bash

# This script is used to transfer files to Grid5000

# First parameter is the login of the user
# Second paramater is the server to connect to
# Third parameter is y or not exists

# Check if the user has entered a LOGIN
if [ -z $1 ]; then
    echo "Please enter the login to connect to Grid5000"
    exit 1
fi

# Check if the user has entered a server
if [ -z $2 ]; then
    echo "Please enter the place to connect to"
    exit 1
fi

scp -r src/ $1@access.grid5000.fr:$2/MITM/
scp run.sh $1@access.grid5000.fr:$2/MITM/
scp Makefile $1@access.grid5000.fr:$2/MITM/
scp commands.txt $1@access.grid5000.fr:$2/MITM/

# Connect to Grid5000 if the user has entered y
if [ $3 = "y" ]; then
    ssh $1@access.grid5000.fr
fi
