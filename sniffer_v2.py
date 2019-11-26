# -*- coding: utf-8 -*-
"""
Created on Wed Nov 20 18:25:46 2019

@author: shyoo

현재 상황
seq, ack 숫자가 안맞음 ( 표기방식의 차이일수도 있음 )
ICMP 미완성
HTTP, DNS 완성
DNS Query type, class가 알파벳으로 나와야함, 현재는 숫자
filter_option 미완성

"""
from time import gmtime, strftime
from socket import *
import os
import struct
import textwrap
import re

DNS_QUERY_SECTION_FORMAT = struct.Struct("!2H")

def decode_labels(message, offset):
    labels = []

    while True:
        length, = struct.unpack_from("!B", message, offset)

        if (length & 0xC0) == 0xC0:
            pointer, = struct.unpack_from("!H", message, offset)
            offset += 2

            return labels + decode_labels(message, pointer & 0x3FFF), offset

        if (length & 0xC0) != 0x00:
            raise StandardError("unknown label encoding")

        offset += 1

        if length == 0:
            return labels, offset

        labels.append(*struct.unpack_from("!%ds" % length, message, offset))
        offset += length


DNS_QUERY_SECTION_FORMAT = struct.Struct("!2H")

def decode_question_section(message, offset, qdcount):
    questions = []

    for _ in range(qdcount):
        qname, offset = decode_labels(message, offset)

        qtype, qclass = DNS_QUERY_SECTION_FORMAT.unpack_from(message, offset)
        offset += DNS_QUERY_SECTION_FORMAT.size

        question = {"domain_name": qname,
                    "query_type": qtype,
                    "query_class": qclass}

        questions.append(question)

    return questions, offset


DNS_QUERY_MESSAGE_HEADER = struct.Struct("!6H")

def decode_dns_message(message):

    id, misc, qdcount, ancount, nscount, arcount = DNS_QUERY_MESSAGE_HEADER.unpack_from(message)

    qr = (misc & 0x8000) != 0
    opcode = (misc & 0x7800) >> 11
    aa = (misc & 0x0400) != 0
    tc = (misc & 0x200) != 0
    rd = (misc & 0x100) != 0
    ra = (misc & 0x80) != 0
    z = (misc & 0x70) >> 4
    rcode = misc & 0xF

    offset = DNS_QUERY_MESSAGE_HEADER.size
    questions, offset = decode_question_section(message, offset, qdcount)

    result = {"id": id,
              "is_response": qr,
              "opcode": opcode,
              "is_authoritative": aa,
              "is_truncated": tc,
              "recursion_desired": rd,
              "recursion_available": ra,
              "reserved": z,
              "response_code": rcode,
              "question_count": qdcount,
              "answer_count": ancount,
              "authority_count": nscount,
              "additional_count": arcount,
              "questions": questions}
    
# =============================================================================
#     print('\n\t\t###[ DNS ]###')
# =============================================================================
    print('\t\t\tid: {}'.format(hex(id)))
    print('\t\t\tIs response: {}'.format(qr))
    print('\t\t\tOpcode: {}'.format(opcode))
    print('\t\t\tIs authoritative: {}'.format(aa))
    print('\t\t\tIs truncated: {}'.format(tc))
    print('\t\t\tRecursion desired: {}'.format(rd))
    print('\t\t\tRecursion available: {}'.format(ra))
    print('\t\t\tReserved: {}'.format(z))
    print('\t\t\tResponse code: {}'.format(rcode))
    print('\t\t\tQuestion count: {}'.format(qdcount))
    print('\t\t\tAnswer count: {}'.format(ancount))
    print('\t\t\tAuthority count: {}'.format(nscount))
    print('\t\t\tAdditional count: {}'.format(arcount))
    #print('\t\t\tquestions: {}'.format(questions))
# =============================================================================
# =============================================================================
    return questions
if __name__ == '__main__':
    
    #host = "192.168.181.199"
    
    #if os.name == 'nt':
    #    sock_protocol = IPPROTO_IP
    #else:
    #    sock_protocol = IPPROTO_ICMP
    s = socket(AF_INET, SOCK_DGRAM)
    s.connect(('8.8.8.8', 1))
    ipAddress = s.getsockname()[0]
    RawSocket = socket(AF_INET, SOCK_RAW)
    #sniffer = socket(AF_PACKET, SOCK_RAW, ntohs(3))
    RawSocket.bind((ipAddress, SOCK_RAW))
    #sniffer.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)

    if os.name == 'nt':
        RawSocket.ioctl(SIO_RCVALL, RCVALL_ON)
    
    filter_option = input('input filter option : ')    
        
    try:
        while True:
            
            #raw_data = recvData(sniffer)
            Packet = RawSocket.recvfrom(65565)
            #EthernetHeader = Packet[0][0:14]
            #Ethernet_Header = struct.unpack('!6s6sH', EthernetHeader)
            raw_data = Packet[0]
            #raw_data = sniffer.recvfrom(65565)      
            #Ethdest, Ethsrc, Ethprototype = struct.unpack('! 6s 6s H', Ethernet_Header)

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
            IPv4len = (raw_data[0] & 15) * 4
            (IPv4service,) = struct.unpack('!B', raw_data[1:2])
            IPv4service = hex(IPv4service)
            (IPv4total,) = struct.unpack('!H', raw_data[2:4])
            (IPv4id,) = struct.unpack('!H', raw_data[4:6])
            IPv4id = hex(IPv4id)
            (flag,) = struct.unpack('!H', raw_data[6:8])
            #IPv4flag = flag >> 13 # 플래그 조금다
            IPv4flag = hex(flag) 
            (offset,) = struct.unpack('!H', raw_data[6:8])
            IPv4offset = (offset & 0x1FFF) << 2
            (IPv4ttl,) = struct.unpack('!B', raw_data[8:9])
            (IPv4type,) = struct.unpack('!B', raw_data[9:10])
            (check_sum,) = struct.unpack('!H', raw_data[10:12])
            IPv4check_sum = hex(check_sum)
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
            
            # ICMP
            if IPv4type == 1 and filter_option.find('icmp') != -1:
                print('\n###[ IP ]###')
                print('\tVersion: {} \n \tHeader Length: {} \n \tDifferentiated Services Field: {}'.format(IPv4ver, IPv4len, IPv4service))
                print('\tTotal Length: {} \n \tIdentification: {} \n \tFlags: {}'.format(IPv4total, IPv4id, IPv4flag))
                print('\tFragment offset: {} \n \tTime to live: {} \n \tProtocol: {}'.format(IPv4offset, IPv4ttl, IPv4type))
                print('\tHeader checksum status: {} \n \tSource: {} \n \tDestination: {}'.format(IPv4check_sum, IPv4src, IPv4dst))
            
                #ICMPtype, ICMPcode, ICMPchecksum = struct.unpack('! B B H', ETCdata[:4])


                (ICMPtype,) = struct.unpack('!B', ETCdata[0:1])
                (ICMPcode,) = struct.unpack('!B', ETCdata[1:2])
                (ICMPchecksum,) = struct.unpack('!H', ETCdata[2:4])
                ICMPchecksum = hex(ICMPchecksum)
                (ICMPidentifier_be,) = struct.unpack('!H', ETCdata[4:6])
                ICMPidentifier_le = int(hex(ICMPidentifier_be) + '00',16)
                (ICMPsequence_be,) = struct.unpack('!H', ETCdata[6:8])
                ICMPsequence_le = int(hex(ICMPsequence_be) + '00',16)
                #(ICMPpointer,) = struct.unpack('!B', ETCdata[4:5])
                #(ICMPidentifier,) = struct.unpack('!H', ETCdata[5:7])
                #(ICMPsequence,) = struct.unpack('!H', ETCdata[7:9])
                #(ICMPgateway,) = struct.unpack('!2H', ETCdata[9:13])
                #(ICMPmask,) = struct.unpack('!2H', ETCdata[13:17])
                TEMPdata = ETCdata[8:]
                # 빠진거 identifier be,le / sequence number be,le / data, length
                
                print('\n###[ ICMP ]###')
                print('\tType: {} \n \tCode: {} \n \tChecksum: {}'.format(ICMPtype, ICMPcode, ICMPchecksum))
                print('\tIdentifier (BE): {} \n \tSequence number (BE): {}'.format(ICMPidentifier_be, ICMPidentifier_le))
                print('\tIdentifier (LE): {} \n \tSequence number (LE): {}'.format(ICMPsequence_be, ICMPsequence_le))
                
                print('\tData: {}'.format(TEMPdata.decode('utf-8')))
                
                
                #print('\tICMP Data:')
            
            # TCP
            elif IPv4type == 6 and filter_option.find('tcp') != -1:
                
                print('\n###[ IP ]###')
                print('\tVersion: {} \n \tHeader Length: {} \n \tDifferentiated Services Field: {}'.format(IPv4ver, IPv4len, IPv4service))
                print('\tTotal Length: {} \n \tIdentification: {} \n \tFlags: {}'.format(IPv4total, IPv4id, IPv4flag))
                print('\tFragment offset: {} \n \tTime to live: {} \n \tProtocol: {}'.format(IPv4offset, IPv4ttl, IPv4type))
                print('\tHeader checksum status: {} \n \tSource: {} \n \tDestination: {}'.format(IPv4check_sum, IPv4src, IPv4dst))
            
                #TCPsrc_port, TCPdest_port, TCPsequence, TCPacknowledgment, \
                #TCPoffset_reserved_flags = struct.unpack('! H H L L H', ETCdata[:14])
                # 시퀀스넘버, 애크 넘버 다틀림 (틀린건지 표기방식이 다른건지?)
                #tcp_header = struct.unpack('!HHLLBBHHH', ETCdata[0:20])
                (TCPsrc_port,) = struct.unpack('!H', ETCdata[0:2])
                (TCPdest_port,) = struct.unpack('!H', ETCdata[2:4])
                (TCPsequence,) = struct.unpack('!L', ETCdata[4:8])
                (TCPacknowledgment,) = struct.unpack('!L', ETCdata[8:12])
                TCPlength = len(ETCdata)
                #(TCPoffset,) = struct.unpack('!H', ETCdata[12:13])
                (flags,) = struct.unpack('!H', ETCdata[12:14])
                (TCPflags,) = struct.unpack('!b', ETCdata[13:14])
                TCPflags = hex(TCPflags)
                (TCPwindow,) = struct.unpack('!H', ETCdata[14:16])
                (TCPchecksum,) = struct.unpack('!H', ETCdata[16:18])
                TCPchecksum = hex(TCPchecksum)
                (TCPurgptr,) = struct.unpack('!H', ETCdata[18:20])
              
                TCPoffset = (flags >> 12) * 4
                TCPflag_res1 = (flags & 2048) >> 11
                TCPflag_res2 = (flags & 1024) >> 10
                TCPflag_res3 = (flags & 512) >> 9
                TCPflag_res = TCPflag_res1 & TCPflag_res2 & TCPflag_res3
                TCPflag_hs = (flags & 256) >> 8
                TCPflag_cwr = (flags & 128) >> 7
                TCPflag_ece = (flags & 64) >> 6
                TCPflag_urg = (flags & 32) >> 5
                TCPflag_ack = (flags & 16) >> 4
                TCPflag_psh = (flags & 8) >> 3
                TCPflag_rst = (flags & 4) >> 2
                TCPflag_syn = (flags & 2) >> 1
                TCPflag_fin = flags & 1
                # URG 최상위비트부터 FIN 최하위비트까지 flag가 2진수로 표현되어있음
                # Flag도 표시할 것
                # 빠진게 몇개있음
                # 빠져있음 reserved, nonce, congestion window reduced(CWR), ecn_echo, 
                # 표시됨 urgent ack, push, reset, syn, fin
                # 윈도우사이즈, 체크섬 urgent pointer 추가
                TEMPdata = ETCdata[TCPoffset:]
                
                print('\n###[ TCP ]###')
                print('\tSource Port: {} \n \tDestination Port: {}'.format(TCPsrc_port, TCPdest_port))
                print('\tSequence number: {} \n \tAcknowledgment number: {}'.format(TCPsequence, TCPacknowledgment))
                print('\tHeader Length: {} \n \tFlags: {}'.format(TCPlength, TCPflags))
                print('\tReserved: {} \n \tNonce: {} \n \tCongestion Window Reduced: {}'.format(TCPflag_res, TCPflag_hs, TCPflag_cwr))
                print('\tECN-Echo: {} \n \tUrgent: {} \n \tAcknowledgment:{}'.format(TCPflag_ece, TCPflag_urg, TCPflag_ack))
                print('\tPush: {} \n \tReset: {} \n \tSyn: {} \n \tFin: {}'.format(TCPflag_psh, TCPflag_rst, TCPflag_syn, TCPflag_fin))
                print('\tWindow size value: {} \n \tChecksum: {} \n \tUrgent pointer:{}'.format(TCPwindow, TCPchecksum, TCPurgptr))
                
                if len(TEMPdata) > 0:
                    
                    if (TCPsrc_port == 80 or TCPdest_port == 80 \
                    or TCPsrc_port == 443 or TCPdest_port == 443) and filter_option.find('http') != -1:
                        
                        if TCPsrc_port == 80 or TCPdest_port == 80:
                            
                            print('\n\t###[ HTTP ]###')
                                  
                        if TCPsrc_port == 443 or TCPdest_port == 443:
                            
                            print('\n\t###[ HTTPS ]###')
                        try:          
                            try:
                                HTTPdata = TEMPdata.decode('utf-8')
                            except:
                                HTTPdata = TEMPdata
                            http_info = str(HTTPdata).split('\n')
                            for line in http_info:
                                print('\t\t' + str(line))
                        except:
                            size = 80
                            size -= len('\t\t')
                            if isinstance(TEMPdata, bytes):
                                joinPdata = ''.join(r'\x{:02x}'.format(byte) for byte in TEMPdata)
                                if size % 2:
                                    size -= 1
                            print('\n'.join(['\t\t' + line for line in textwrap.wrap(joinPdata, size)]))
                            #print('HTTPS:' + str(TEMPdata))
                      
                    else:
                        
                        #print('\n###[ TCP Data ]###')
                        size = 80
                        size -= len('\t')
                        if isinstance(TEMPdata, bytes):
                            TEMPdata = ''.join(r'\x{:02x}'.format(byte) for byte in TEMPdata)
                            if size % 2:
                                size -= 1
                        #print('\n'.join(['\t' + line for line in textwrap.wrap(TEMPdata, size)]))
                    
            elif IPv4type == 17 and filter_option.find('udp') != -1:
                print('\n###[ IP ]###')
                print('\tVersion: {} \n \tHeader Length: {} \n \tDifferentiated Services Field: {}'.format(IPv4ver, IPv4len, IPv4service))
                print('\tTotal Length: {} \n \tIdentification: {} \n \tFlags: {}'.format(IPv4total, IPv4id, IPv4flag))
                print('\tFragment offset: {} \n \tTime to live: {} \n \tProtocol: {}'.format(IPv4offset, IPv4ttl, IPv4type))
                print('\tHeader checksum status: {} \n \tSource: {} \n \tDestination: {}'.format(IPv4check_sum, IPv4src, IPv4dst))
                
                (UDPsrc_port,) = struct.unpack('! H', ETCdata[0:2])
                (UDPdest_port,) = struct.unpack('! H', ETCdata[2:4])
                (UDPsize,) = struct.unpack('! H', ETCdata[4:6])
                (UDPcheck_sum,) = struct.unpack('! H', ETCdata[6:8])
                UDPcheck_sum = hex(UDPcheck_sum)
                TEMPdata = ETCdata[8:]
                
                print('\n###[ UDP ]###')
                print('\tSource Port: {} \n \tDestination Port: {} \n \tLength: {}'.format(UDPsrc_port, UDPdest_port, UDPsize))
                print('\tChecksum: {}'.format(UDPcheck_sum))
                
                if filter_option.find('dns') != -1:   
                    regDNS = re.compile('[^a-zA-Z0-9-@:%._\+~#=]')
                    
                    now = strftime("%Y-%m-%d %H:%M:%S", gmtime())
                    recvHeader = struct.unpack_from('!HHHHHH', TEMPdata)
                    #recvData = TEMPdata[13:].split(b'\x00', 1)
                    flag_QnA = recvHeader[1] & 0b1000000000000000
                    if flag_QnA == 0 : 
                        print('\n\t###[ DNS Query ]###')
                    else : 
                        print('\n\t###[ DNS Response ]###')
                    print('\t\tTime : ' + now)
                    print('\t\tTransaction ID : ' + str(hex(recvHeader[0])))
                    print('\t\tFlags : ' + str(hex(recvHeader[1])))
                    print('\t\tQuestions : ', recvHeader[2])
                    print('\t\tAnswer RR : ', recvHeader[3])
                    print('\t\tAuthority RRs: ', recvHeader[4])
                    print('\t\tAdditional RRs: ', recvHeader[5])
                    # ㅡㅡㅡㅡ 여기까지 Domain Name System
                    
                    if (UDPsrc_port == 53 or UDPdest_port == 53) and filter_option.find('dns') != -1:
                        print('\n\t\t###[ DNS ]###')
                        dnsquery = decode_dns_message(TEMPdata)
                        print('\n\t\t\t###[ DNS Queries ]###')
                        domain_name = [dnsquery[0]['domain_name'][i].decode('utf-8') for i, _ in enumerate(dnsquery[0]['domain_name'])]
                        print('\t\t\t\tDomain name: ', end='')
                        for i, v in enumerate(domain_name):
                            if i+1 == len(domain_name):
                                print(v, end='')
                            else:
                                print(v, end='.')
                            
                        print('\n\t\t\t\tQuery type: {}'.format(dnsquery[0]['query_type']))
                        print('\t\t\t\tQuery class: {}'.format(dnsquery[0]['query_class']))
                        #print('\t\t\t',str(TEMPdata))
                        # Queries랑 Authoritative nameservers를 추가로 추출해야됨
                        
        print('\n')
    except KeyboardInterrupt:
        if os.name == 'nt':
            RawSocket.ioctl(SIO_RCVALL, RCVALL_OFF)