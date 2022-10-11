#!/usr/bin/env python3
import sys
from scapy.all import *

def get_datagram(port):
    datagram = TCP()/"test\n"
    datagram.sport = 12345
    datagram.dport = port
    datagram.flags = "S"
    return datagram

def get_ip():
    ip = IP()
    ip.src = "147.210.0.2"
    ip.dst = "192.168.0.2"
    return ip

def make_query(packet):
    query = sr1(packet, timeout=1)
    return query

def answer(query):
  payload = query.payload
  data = payload.load
  syn = payload.flags.S
  ack = payload.flags.A
  rst = payload.flags.R
  return syn

def is_port_open(port):
    datagram = get_datagram(port)
    ip = get_ip()
    query = make_query(ip/datagram)
    syn = answer(query)
    return syn

def port_status(tab, min, max):
    print ("\nOPENED PORTS :\n[", end='')
    for i in range (min, max+1):
        if tab[i-1] == 1:
            print(i, ",", sep='', end='')
    print("]")

def main():
    port_min = 1
    port_max = 100
    tab = [0] * port_max
    for i in range (port_min, port_max):
        tab[i-1] = is_port_open(i)
    port_status(tab, port_min, port_max)

if __name__ == "__main__":
  exit(main())