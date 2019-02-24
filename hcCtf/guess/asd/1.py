import os
import uuid

rand_value = int(os.urandom(4).encode('hex'), 16) % 500
UUID = "-" + str(uuid.uuid4())

SRC = "/home/minsuck/Desktop/pwnable/hcCtf/guess/asd/guess.c"
OUT = "/home/minsuck/Desktop/pwnable/hcCtf/guess/asd/" + UUID
print UUID
os.system(("gcc -DLENGTH={} -mpreferred-stack-boundary=4  -fno-stack-protector -o " + OUT + " " + SRC).format(rand_value))
print str(rand_value)
os.system(OUT)
print OUT
os.system("rm -rf " + OUT)
