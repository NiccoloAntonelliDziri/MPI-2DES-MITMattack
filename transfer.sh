#!/bin/bash

# This script is used to transfer files to grid5000

# Usage function

usage() {
    echo "Usage: $0 [flags] <login> <place>"
    echo "Flags:"
    echo "  -h, --help: Display this help message"
    echo "  -c, --connect: Automatically connect to Grid5000"
}


# Flags

while getopts ":hc" opt; do
    case $opt in
        h)
            usage
            exit 0
            ;;
        c)
            connect=true
            ;;
    esac
done

# Transfer files with positional arguments

shift $((OPTIND -1))

# Argument validation

if [ "$#" -ne 2 ]; then
    echo "Error: Invalid number of arguments"
    usage
    exit 1
fi

login=$1
place=$2

scp -r src/ $login@access.grid5000.fr:$place/MITM/
scp run.sh $login@access.grid5000.fr:$place/MITM/
scp Makefile $login@access.grid5000.fr:$place/MITM/
scp commands.txt $login@access.grid5000.fr:$place/MITM/

# Connect to Grid5000 if the user has entered -c

if [ "$connect" = true ]; then
    ssh $place.g5k
fi

