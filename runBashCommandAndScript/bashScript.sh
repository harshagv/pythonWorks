#!/bin/bash

echo "All Bash Arguments: " $*
echo "All Bash Arguments: " $@

echo "Bash Arguments Count: " $#

echo "First Argument: " $1


numValue=$1

a=0
b=1
i=2

echo "Fibonacci Series up to $numValue terms :"
echo "$a"
echo "$b"

for (( i=0; i<numValue; i++ ))
do
    echo -n "$a "
    fn=$((a + b))
    a=$b
    b=$fn
done
