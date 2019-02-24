#!/bin/bash
for name in $(cat zzz.txt)
do
    rm -rf $name
done
