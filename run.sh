#!/bin/bash

# This script is used to run the parallel version of the MITM attack

COMMANDS=commands.txt # default file containing the commands
ONGRID5000=false # Set to true if running on Grid5000
OUTPUT=output.csv # default output file

# Usage function

usage() {
    echo "Usage: $0 [flags] <number of nodes>"
    echo "Flags:"
    echo "  -h, --help: Display this help message"
    echo "  -f, --file: Specify the file containing the commands"
    echo "           Default: commands.txt"
    echo "  -g, --grid: If set, the script will run on Grid5000"
    echo "           Default: false"
    echo "  -c, --compile: If set, the script will compile the source code"
    echo "  -o, --output: Specify the output file"
    echo "           Default: output.csv"
}

# Flags

while getopts ":hf:gn:co:" opt; do
    case $opt in
        h)
            usage
            exit 0
            ;;
        f)
            COMMANDS=${OPTARG}
            ;;
        g)
            ONGRID5000=true
            ;;
        c)
            make
            ;;
        o)
            OUTPUT=${OPTARG}
            ;;
    esac
done

# Check if the file exists
if [ ! -f "$COMMANDS" ]; then
    echo "File $COMMANDS not found"
    usage
    exit 1
fi

# Get the number of nodes to execute on
shift $((OPTIND -1))

if [ "$#" -ne 1 ]; then
    echo "Error: Number of nodes not specified"
    usage
    exit 1
fi
NODES=$1

# Write the headers of the output File
echo "world size,n,dict size,tbq1,taq1,tm,te,ttot" > $OUTPUT

# Remove empty lines
sed -e '/^$/d' $COMMANDS > temp.txt

# number if lines in file
nb_lines=$(wc -l < temp.txt)

if [ "$ONGRID5000" = false ]; then
    # Read file line by line and call ./src/mitm_paral2.cpp
    for i in $(seq 1 $nb_lines);
    do
        line=$(sed -n "$i"p temp.txt)
        mpiexec --n $1 -- ./bin/pr_golden2 $line --o $OUTPUT
        # echo $line
    done
else
    # Check if resources are available
    # if $OAR_NODEFILE is empty no resources are available
    if [ -z "$OAR_NODEFILE" ]; then
        echo "Error: Please request resources using oarsub"
        exit 1
    fi

    # Read file line by line and call ./src/mitm_paral2.cpp
    for i in $(seq 1 $nb_lines);
    do
        line=$(sed -n "$i"p temp.txt)
        mpiexec --n $NODES --hostfile $OAR_NODEFILE -- ./bin/pr_golden2 $line
    done
fi

# Remove temporary file
rm temp.txt
