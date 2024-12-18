#!/bin/bash

COMMANDS=commands.txt

# Get the number of nodes to execute on
if [ -z "$1" ]; then
    echo "Usage: $0 <number of nodes>"
    exit 1
fi

# Check if the file exists
if [ ! -f "$COMMANDS" ]; then
    echo "File not found!"
    exit 1
fi

# Remove empty lines
sed -e '/^$/d' $COMMANDS > temp.txt

# Compile the source code
make

# Read file line by line and call ./src/mitm_paral2.cpp
while IFS= read -r line
do
    mpiexec --n $1 -- ./bin/pr_golden2 $line
    # echo $line
done < temp.txt

# Remove temporary file
rm temp.txt
