#!/bin/bash

echo "#############"
echo "A for loop in Bash:"
echo "#############"

keywords=(  #create array
    "a"
    "b"
    "c")

for v in "${keywords[@]}"
do
    echo "This is keyword ${v}"    
done

echo "all done"
