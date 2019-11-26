# -*- coding: utf-8 -*-
"""
Created on Wed Nov 20 18:25:46 2019

@author: shyoo
"""

from socket import *
import os
import struct
import textwrap

def recvData(sock):
    data = ''
    try:
        data = sock.recvfrom(65565)
    except timeout:
        data = ''
    return data[0]

if __name__ == '__main__':
    
    host = "192.168.123.112"
    
    if os.name == 'nt':
        sock_protocol = IPPROTO_IP
    else:
        sock_protocol = IPPROTO_ICMP

    sniffer = socket(AF_INET, SOCK_RAW, sock_protocol)
    #sniffer = socket(AF_PACKET, SOCK_RAW, ntohs(3))
    sniffer.bind((host, SOCK_RAW))
    sniffer.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)

    if os.name == 'nt':
        sniffer.ioctl(SIO_RCVALL, RCVALL_ON)
    
    filter_option = input('input filter option : ')    
        
    try:
        while True:
            
            raw_data = recvData(sniffer)
            
            #raw_data = sniffer.recvfrom(65565)      
            #Ethdest, Ethsrc, Ethprototype = struct.unpack('! 6s 6s H', raw_data[:14])

            #Ethbyte_str = map('{:02x}'.format, Ethdest)
            #Ethdest_mac = ':'.join(Ethbyte_str).upper() # destination mac addr
            
            #Ethbyte_str = map('{:02x}'.format, Ethsrc)
            #Ethsrc_mac = ':'.join(Ethbyte_str).upper() # destination src addr
            
            #Ethproto = htons(Ethprototype)
            IPv4data = raw_data[0:]
            
            #print('###[ Ethernet ]###')
            #print('\tdst: {}, \n \tsrc: {}, \n \ttype: {}'.format(Ethdest_mac, Ethsrc_mac, Ethproto))
            #proto = map('{:x}'.format, raw_data[9:10])
            #IPv4proto = ':'.join(proto).upper()
            
            (ver,) = struct.unpack('!B', raw_data[0:1])
            IPv4ver = ver >> 4
            (IPv4len,) = struct.unpack('!B', raw_data[0:1])
            (IPv4service,) = struct.unpack('!B', raw_data[1:2])
            (IPv4total,) = struct.unpack('!H', raw_data[2:4])
            (IPv4id,) = struct.unpack('!H', raw_data[4:6])
            (flag,) = struct.unpack('!H', raw_data[6:8])
            IPv4flag = flag >> 13
            (offset,) = struct.unpack('!H', raw_data[6:8])
            IPv4offset = (offset & 0x1FFF) << 2
            (IPv4ttl,) = struct.unpack('!B', raw_data[8:9])
            (IPv4type,) = struct.unpack('!B', raw_data[9:10])
            (IPv4check_sum,) = struct.unpack('!H', raw_data[10:12])
            src = struct.unpack('!4B', raw_data[12:16])
            IPv4src = '%d.%d.%d.%d' % src
            dst = struct.unpack('!4B', raw_data[16:20])
            IPv4dst = '%d.%d.%d.%d' % dst
            
            IPv4version_header_length = IPv4data[0]
            #IPv4version = IPv4version_header_length >> 4
            IPv4header_length = (IPv4version_header_length & 15) * 4
            #IPv4ttl, IPv4proto, IPv4src, IPv4target = struct.unpack('! 8x B B 2x 4s 4s', IPv4data[:20])
            #IPv4src = '.'.join(map(str, IPv4src))
            #IPv4target = '.'.join(map(str, IPv4target))
            ETCdata = IPv4data[IPv4header_length:]
            
            print('\n###[ IP ]###')
            print('\tver: {} \n \tlen: {} \n \tserv: {}'.format(IPv4ver, IPv4len, IPv4service))
            print('\ttotal: {} \n \tid: {} \n \tflag: {}'.format(IPv4total, IPv4id, IPv4flag))
            print('\toffset: {} \n \tttl: {} \n \ttype: {}'.format(IPv4offset, IPv4ttl, IPv4type))
            print('\tchksum: {} \n \tsrc: {} \n \tdst: {}'.format(IPv4check_sum, IPv4src, IPv4dst))
            
            # ICMP
            if IPv4type == 1:
                ICMPtype, ICMPcode, ICMPchecksum = struct.unpack('! B B H', ETCdata[:4])
                TEMPdata = ETCdata[4:]
                
                print('\n###[ ICMP ]###')
                print('\tType: {} \n \tCode: {} \n \tChecksum: {}'.format(ICMPtype, ICMPcode, ICMPchecksum))
                print('\tICMP Data:')
                size = 80
                size -= len('\t')
                if isinstance(TEMPdata, bytes):
                    TEMPdata = ''.join(r'\x{:02x}'.format(byte) for byte in TEMPdata)
                    if size % 2:
                        size -= 1
                print('\n'.join(['\t' + line for line in textwrap.wrap(TEMPdata, size)]))
                
            # TCP
            elif IPv4type == 6: 
                TCPsrc_port, TCPdest_port, TCPsequence, TCPacknowledgment, \
                TCPoffset_reserved_flags = struct.unpack('! H H L L H', ETCdata[:14])
                TCPoffset = (TCPoffset_reserved_flags >> 12) * 4
                TCPflag_urg = (TCPoffset_reserved_flags & 32) >> 5
                TCPflag_ack = (TCPoffset_reserved_flags & 16) >> 4
                TCPflag_psh = (TCPoffset_reserved_flags & 8) >> 3
                TCPflag_rst = (TCPoffset_reserved_flags & 4) >> 2
                TCPflag_syn = (TCPoffset_reserved_flags & 2) >> 1
                TCPflag_fin = TCPoffset_reserved_flags & 1
                TEMPdata = ETCdata[TCPoffset:]
                
                print('\n###[ TCP ]###')
                print('\tSource Port: {} \n \tDestination Port: {}'.format(TCPsrc_port, TCPdest_port))
                print('\tSequence: {} \n \tAcknowledgment: {}'.format(TCPsequence, TCPacknowledgment))
                print('\tFlags:')
                print('\tURG: {} \n \tACK: {} \n \tPSH: {}'.format(TCPflag_urg, TCPflag_ack, TCPflag_psh))
                print('\tRST: {} \n \tSYN: {} \n \tFIN:{}'.format(TCPflag_rst, TCPflag_syn, TCPflag_fin))
                print('\tRAW: {}'.format(TEMPdata))
                
                if len(TEMPdata) > 0:
                    
                    if TCPsrc_port == 80 or TCPdest_port == 80 \
                    or TCPsrc_port == 443 or TCPdest_port == 443:
                        
                        #print('\n###[ HTTP ]###')
                        try:          
                            try:
                                HTTPdata = TEMPdata.decode('utf-8')
                            except:
                                HTTPdata = TEMPdata
                            http_info = str(HTTPdata).split('\n')
                            for line in http_info:
                                print('\t' + str(line))
                        except:
                            size = 80
                            size -= len('\t')
                            if isinstance(TEMPdata, bytes):
                                joinPdata = ''.join(r'\x{:02x}'.format(byte) for byte in TEMPdata)
                                if size % 2:
                                    size -= 1
                            print('\n'.join(['\t' + line for line in textwrap.wrap(joinPdata, size)]))
                            print('HTTPS:' + str(TEMPdata))
                        
                    else:
                        
                        print('###[ TCP Data ]###')
                        size = 80
                        size -= len('\t')
                        if isinstance(TEMPdata, bytes):
                            TEMPdata = ''.join(r'\x{:02x}'.format(byte) for byte in TEMPdata)
                            if size % 2:
                                size -= 1
                        print('\n'.join(['\t' + line for line in textwrap.wrap(TEMPdata, size)]))
                        
            elif IPv4type == 17:
                (UDPsrc_port,) = struct.unpack('! H', ETCdata[0:2])
                (UDPdest_port,) = struct.unpack('! H', ETCdata[2:4])
                (UDPsize,) = struct.unpack('! H', ETCdata[4:6])
                (UDPcheck_sum,) = struct.unpack('! H', ETCdata[6:8])
                UDPcheck_sum = hex(UDPcheck_sum)
                TEMPdata = ETCdata[8:]
                
                print('\n###[ UDP ]###')
                print('\tSource Port: {} \n \tDestination Port: {} \n \tLength: {}'.format(UDPsrc_port, UDPdest_port, UDPsize))
                print('\tchksum: {} \n \tData: {}'.format(UDPcheck_sum, TEMPdata))
                
        
        print('\n')
    except KeyboardInterrupt:
        if os.name == 'nt':
            sniffer.ioctl(SIO_RCVALL, RCVALL_OFF)