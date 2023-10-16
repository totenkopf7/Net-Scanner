#!usr/bin/env python

# import os
# currentDir=os.getcwd() #Shows Current Directory

import argparse
import itertools
import threading
import time
import sys
import subprocess
import scapy.all as scapy
import colorama
from colorama import Fore, Back, Style
colorama.init(autoreset=True)


subprocess.call("clear")
logo = """


 _   _      _                      _      _____                                 
| \ | |    | |                    | |    /  ___|                                
|  \| | ___| |___      _____  _ __| | __ \ `--.  ___ __ _ _ __  _ __   ___ _ __ 
| . ` |/ _ \ __\ \ /\ / / _ \| '__| |/ /  `--. \/ __/ _` | '_ \| '_ \ / _ \ '__|
| |\  |  __/ |_ \ V  V / (_) | |  |   <  /\__/ / (_| (_| | | | | | | |  __/ |   
\_| \_/\___|\__| \_/\_/ \___/|_|  |_|\_\ \____/ \___\__,_|_| |_|_| |_|\___|_|   
                                                                                                                                                       
"""



print(f"{Fore.RED}{logo}")
print(f"[+]-[+]-[+]-[+]-[+]-[+]-[+]-[+]-[+]-[+]-[+]-[+]-[+]-[+]-[+]-[+]-[+]-[+]-[+]-[+]-[+] *** Created by: {Fore.RED}Totenkopf\n")

done = False
#here is the animation
def animate():
    for c in itertools.cycle(['|', '/', '-', '\\']):
        if done:
            break
        sys.stdout.write('\r[+] Scanning the network ' + c)
        sys.stdout.flush()
        time.sleep(0.1)
    sys.stdout.write('\r')

t = threading.Thread(target=animate)
t.start()
time.sleep(9)





def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="target IP / IP range.")
    options = parser.parse_args()

    return options

def scan(ip):

    arp_request = scapy.ARP(pdst=ip)
    # print(arp_request.summary())
    # scapy.ls(scapy.ARP())
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    # print(arp_request_broadcast.summary()) #Shows a summary
    # scapy.ls(scapy.Ether()) #lists
    # arp_request_broadcast.show()     #Shows in more details
    answered_list = scapy.srp(arp_request_broadcast, timeout=7, verbose=False)[0] #Send a packet and receive response, verbose makes the beginning text disappear
    print("\n\nScan completed")
    print(" ")
    clients_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)
    return clients_list


def print_result(results_list):
    line = "|"
    print("\n- - - - - - - - - - - - - - - - - - - - - - -")
    print(f"{Fore.LIGHTGREEN_EX}IP\t\t{Fore.WHITE}    |{Fore.LIGHTBLUE_EX}   Mac address {Fore.WHITE}        |\n{Fore.WHITE}- - - - - - - - - - - - - - - - - "
          f"- - - - - -")
    for client in results_list:
        print(f'{Fore.LIGHTGREEN_EX}{client["ip"]}\t    {Fore.WHITE}|   {Fore.LIGHTBLUE_EX}{client["mac"]}{Fore.WHITE}   |')
    print(f"- - - - - - - - - - - - - - - - - - - - - - -\n\n")


ip_range = "192.168.1.1/24"
options = get_arguments()

if not options.target:
    scan_result = scan(ip_range)
else:
    scan_result = scan(options.target)


print_result(scan_result)
done = True