#!/usr/bin/python2.7
import os
import uuid

rand_value = int(os.urandom(4).encode('hex'), 16) % 500 
UUID = "-" + str(uuid.uuid4())

SRC = "/home/guess/guess.c"
OUT = "/tmp/guess" + UUID

os.system(("gcc -DLENGTH={} -mpreferred-stack-boundary=4  -fno-stack-protector -o " + OUT + " " + SRC).format(rand_value))
os.system(OUT)
os.system("rm -rf " + OUT)
