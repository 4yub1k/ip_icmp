#!/bin/python3
import socket
from random import randrange


s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) #socket.IPPROTO_ICMP for ICMP
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1) #we are assigning the IP

soucre_ip='192.168.242.133' 
destination_ip='142.250.181.46'

#- Must be between 49152 - 65535 //0-1024--> Reserved ports(well-known ports) //1024-49151--> are Registered ports
destination_port=hex(randrange(49152,65535,1))[2:] #Random port from dynamic ports

#-------check sum------------------------------------------------------------------

def chkk(values):
	for i in values:
		x=bin(int(i,16))[2:].zfill(16) #ignore this only for representaion in binary
		sum+=int(i,16)
		print("\n","0x"+i,x," --> ","sum :",hex(sum))
	#- Removing Carryover 15912 , we need it in range FFFF #Do it in binary to understand carryover
	#- print(sum,0xFFFF)
	carry='0'
	if sum > 0xFFFF: #- if sum value is greater then 0xFFFF then slice the carry
		carry=hex(sum)[2:3] #0x15912 --> slice get 0x[1]5912
		sum=hex(sum)[3:]# 0x15912 --> 5912 in hex
	else:
		sum=hex(sum)[2:]# 0x15912 --> 5912 in hex
		
	sum=int(sum,16) + int(carry,16)#- convert to int base 16 (HEX) and add carryover

	#- negagtion-- total 0xFFFF as 16 bit
	sum=0xFFFF - sum #0xFFFF-sum
	sum=format(sum,'04x')
	print('\tchecksum :',sum+"\n")
	return sum # value 0000 formate
#- IP to HEX --------------------------------------------------------------------------------
def iptohex(ip):
	#- let ip = 192.168.1.1
	first='' #- 192.168 --> 16 bit
	second=''#- 1.1 --> 16 bit
	
	for index,value in enumerate(map(int,ip.split("."))): #- map will change the type from string to int
		#- index start from 0 -> 0,1,2,3
		if index <2:
			first+=format(value,'02x') #format always fill remaing with zero upto 2 values, 0x1 --> 01, x for converting to hex.
		else:
			second+=format(value,'02x')
	#returns hex values of ['192168','11']
	return first,second

#-------------IP-----------
version='4' #verion and ihl makes 1 byte, So don't add 0's to it foor checksum
ihl='5'
typeOfServices='00'
TotalLength='001c' #length of packet in bytes IP +ICMP in bytes --> hex
#Identification='abcd'#random hex value, 16 bit
Identification='a20a'#format(randrange(0,65535,1),'04x') #format 04x convert input int to hex with 4 digit place 0000. //format(value,'04x')
#- as flag+fragment is 3 & 13 bits so we will can write them combine 
Flags='00' #000 3bit
FragmentOffset='00' #00000 00000000 13 bit
ttl='40'
protocol='01' #01 --> ICMP , 06 --> IPv4
#- zero in calculation.
ipChecksum='0000'
sourceIP=iptohex(soucre_ip)
destIP=iptohex(destination_ip)

#----List of Varibales of IP Checksums----
#- version + ihl + typeOfServices because the packet is divided into 16 bits. if it was to be divided in 8 bits then version and ihl would be seperated.Follow rules.
#- See packet format for details

#- you can also do the same by dividing the sum of all values and then make their 16 bit chunks.
ip_checksum=[version+ihl+typeOfServices, TotalLength, Identification,Flags+FragmentOffset,ttl+protocol,ipChecksum,sourceIP[0],sourceIP[1],destIP[0],destIP[1]]

ip_header=version+ihl+ typeOfServices+ TotalLength+ Identification+ Flags+ FragmentOffset+ ttl+ protocol+ chkk(ip_checksum)+sourceIP[0]+sourceIP[1]+destIP[0]+destIP[1]

ip_hexbytes=bytearray.fromhex(ip_header)

#-------ICMP HEADER--------------

type1='08'
code='00'
icmp_checksum='0000' #16 bit
#icmp_identification='1234' #select random
icmp_identification='1234' #format(randrange(0,65535,1),'04x') 
icmp_sequence='0000' #increases on each request

#- checksum should be addtion of HEX - 16 bit word.
icmp_check=[type1+code,icmp_checksum,icmp_identification,icmp_sequence]
icmp_header=type1+code+chkk(icmp_check)+icmp_identification+icmp_sequence
#- bytearray.fromhex(hexstring)-- converts the hex string to bytearray YOU CAN USE encode() also.
icmp_hexbytes=bytearray.fromhex(icmp_header)

print("----IP header & bytes----")
print(f"IP Header : {ip_header}")
print(f"IP Bytes : {ip_hexbytes}\n")

print("----ICMP header & bytes----")
print(f"ICMP Header : {icmp_header}")
print(f"TCMP Bytes : {icmp_hexbytes}\n")

packet=ip_hexbytes+icmp_hexbytes
print("----Packet Sent----")
#- ip_header+tcp_header -->packet hex string
packet_hex=ip_header+icmp_header
print(f"Packet : {packet_hex}")
print(f"Packet bytes: {packet}\n")
received=b''
try:
	s.sendto(packet, (destination_ip,0))
	s.settimeout(1) #wait for reply 1 second
	print("----Packet Received----")
	received=s.recv(1024)
except Exception as e:
	print(e)

received_hex=received.hex()
print(f"Packet : {received_hex}")
print(f"Received Bytes: {received}")




