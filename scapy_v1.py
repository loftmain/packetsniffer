# -*- coding: utf-8 -*-
"""
Created on Thu Nov  7 10:05:33 2019

@author: shyoo
"""

import sys
from scapy.all import sniff
from scapy.all import conf as scapyconf

scapyconf.sniff_promisc = 1

packet_list = []

def frame_capture(packet):
    try:
    # 작업들
        value = packet.show(dump=True)
        if f_option in value:
            packet_list.append(value)
            print(value)

    except KeyboardInterrupt:
        # Ctrl+C 입력시 예외 발생
        sys.exit(1)
            
def menu():
    
    print('1. Start the http protocol capture')
    print('2. Start the DNS protocol capture')
    print('3. Start the ICMP protocol capture')
    print('4. exit')
    
def capture_agency(p_option):
    
    if p_option == 'HTTP':
        sniff(filter=b_option, prn=frame_capture, count=0)
        # tcp port 80 and host 210.93.48.51
    if p_option == 'DNS': # port 53
        sniff(filter=b_option, prn=frame_capture, count=0)
        # udp dst port 53 and udp[10:2] & 0x8000 = 0
        # Is the DNS packet a Query or a Response
        # Detecting a query or response has to do with using bitmask 
        # to find the first bit of udp[10]. 
        # If the first bit is 0 the DNS packet is a Query and 
        # first bit is 1 dns packet is a Response.
    if p_option == 'ICMP':
        sniff(filter=b_option, prn=frame_capture, count=0)
        # proto ICMP
        
while True:
    menu()
    
    p_option = input('select : ')
    
    if p_option == '1': 
        b_option = input('berceley packet filter option : ')
        f_option = input('filter option (special keyword in raw data): ')
        capture_agency('HTTP')
    
    elif p_option == '2': 
        b_option = input('berceley packet filter option : ')
        f_option = input('filter option (special keyword in raw data): ')
        capture_agency('DNS')
    
    elif p_option == '3': 
        b_option = input('berceley packet filter option : ')
        f_option = input('filter option (special keyword in raw data): ')
        capture_agency('ICMP')
        
    elif p_option == '4':
        print('shutdown...')
        break
    
    else:
        print('invalid select')

index = 0

for packet in packet_list:
    f = open('packet_log'+str(index)+'.txt', 'w')
    f.write(packet)
    index += 1
    


    
    