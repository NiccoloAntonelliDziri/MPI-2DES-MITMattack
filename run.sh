#!/bin/bash

# This script is used to run the parallel version of the MITM attack

COMMANDS=commands.txt # default file containing the commands
COEURS=coeurs.txt
ONGRID5000=false # Set to true if running on Grid5000
OUTPUT=output.csv # default output file

# Usage function

usage() {
    echo "Usage: $0 [flags] <number of nodes>"
    echo "Flags:"
    echo "  -h, --help: Display this help message"
    echo "  -f, --file: Specify the file containing the commands"
    echo "           Default: commands.txt"
    echo "  -p, --file: Specify the file containing the number of processors"
    echo "           Default: coeurs.txt"
    echo "  -g, --grid: If set, the script will run on Grid5000"
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
        p)
            COEURS=${OPTARG}
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
    if [ ! -f "$COEURS" ]; then
    echo "Error: Number of nodes not specified in parameters or File $COEURS not found"
    usage
    exit 1
    fi
fi
NODES=$1

# Write the headers of the output File
echo "world size,n,dict size,tps_avant_q1,tps_pour_q1,tps_pour_mpialltoall,tps_avant_q2,tps_pour_q2,tps_probe,tot" > $OUTPUT

# Remove empty lines
sed -e '/^$/d' $COMMANDS > temp.txt
sed -e '/^$/d' $COEURS > temp2.txt

# number if lines in file
nb_lines=$(wc -l < temp.txt)
nb_lines2=$(wc -l < temp2.txt)

if [ "$ONGRID5000" = false ]; then
    # Read file line by line and call ./src/mitm_paral2.cpp
    for i in $(seq 1 $nb_lines);
    do
        line=$(sed -n "$i"p temp.txt)
        mpiexec --n $1 -- ./bin/pr_golden $line --o $OUTPUT
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
    if [ "$#" -ne 1 ]; then
        for i in $(seq 1 $nb_lines);
        do
            for j in $(seq 1 $nb_lines2);
                do
                    line=$(sed -n "$i"p temp.txt)
                    line2=$(sed -n "$j"p temp2.txt)
                    mpiexec --n $line2 --hostfile $OAR_NODEFILE -- ./bin/pr_golden $line
                done
        done  
    else
        for i in $(seq 1 $nb_lines);
        do
            line=$(sed -n "$i"p temp.txt)
            mpiexec --n $NODES --hostfile $OAR_NODEFILE -- ./bin/pr_golden $line
        done
    fi
fi

# Remove temporary file
rm temp.txt
rm temp2.txt
