#!/bin/bash

for name in $(cat aa.txt)
do
    echo $name
    rm -rf $name
done
