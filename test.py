#!/usr/local/bin/python
import sys
import time
import random
from scapy.all import sr1,IP,TCP,Ether,UDP,sendp

intf = 'lo'
MAX_PKTS = 1

def sendWithOutput(packet, rule):
    i=0
    print '================================'
    print 'packets for the rule:'
    print '%s' % rule
    while i < MAX_PKTS:
        sendp(packet, iface = intf, verbose = False)
        time.sleep(0.1)
        i = i + 1
        print 'send %dth packet' % i

def sendWithVariablePort(rule, minPort, MaxPort):
    i=0
    print '================================'
    print 'packets for the rule:'
    print '%s' % rule
    while i < MAX_PKTS:
        packet = Ether() / IP(dst = str("192.168.1.1")) / UDP(dport = random.randrange(1, 1024))
        sendp(packet, iface = intf, verbose = False)
        time.sleep(0.1)
        i = i + 1
        print 'send %dth packet' % i

def sendHTTPPkts(rule):
    i=0
    print '================================'
    print "packets for the rle:"
    print '%s' % rule
    while i < MAX_PKTS:
        packet = Ether() / IP() / TCP(dport=80) / 'GET / HTTP/1.1\r\nUser-Agent: curl/7.35.0Host: www.google.com\r\nAccept: */*\r\n\r\n'
        sendp(packet, iface = intf, verbose = False)
        time.sleep(0.1)
        i = i + 1
        print 'send %dth packet' % i



rule = 'alert tcp 192.168.1.0/24 any -> 192.168.1.0/24 22 (content:"/bin/sh"; msg:"Remote shell execution message!")'
packet = Ether() / IP(src=str("192.168.1.5"), dst=str("192.168.1.6")) / TCP(sport=10000, dport=22) / "/bin/sh"
#sendWithOutput(packet, rule)

rule = 'alert tcp any any -> 143.248.5.153 80 (msg:"A packet destined to www.kaist.ac.kr")'
packet = Ether() / IP(dst=str("143.248.5.153")) / TCP(dport=80)
#sendWithOutput(packet, rule)

rule = 'alert udp any any -> 192.168.1.0/24 1:1024 (msg:"udp traffic from any port and destination ports ranging from 1 to 1024")'
#sendWithVariablePort(rule, 1, 1024)

rule = 'alert http any any -> any 80 (http_request:"GET"; content:"naver"; msg:"NAVER detected!")'
sendHTTPPkts(rule)
