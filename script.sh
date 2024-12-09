#!/bin/bash

set -e

# arguments:
# $1: "par" ou "seq" pour executer le programme en parallèle ou séquentiel
# $2: Si $1 vaut "par", contient le nombre de processus sur lequel l'executer
# $3: pour lui dire de l'executer sur grid5000

if [ $# -eq 0 ]
then
    echo "Aucun argument fourni"
    exit 1

COMMANDS_FILE="commands.txt"

make

while IFS= read -r line; do
    echo "a"
done < "$COMMANDS_FILE"

exit 0
