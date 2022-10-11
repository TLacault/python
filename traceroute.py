#!/usr/bin/env python3
import sys
from scapy.all import *
from io import StringIO
import time

def ip_header(ip_dst, ttl):
    ip = IP()
    ip.src = "147.210.0.2"
    ip.dst = ip_dst
    ip.ttl = ttl
    return ip

def make_query(packet):
    ans, unans = sr(packet/ICHP(), timeout=3)
    return ans

def get_trace(output):
    ip = output.split("ICMP ", 2)[-1]
    ip = ip.split(" >", 1)[0]
    return ip

def is_target_reachable(ip_dst, ttl):
    start_time = round(time.time() * 1000)
    ip_packet = ip_header(ip_dst, ttl)
    ans = make_query(ip_packet)
    tmp = sys.stdout
    output = StringIO()
    sys.stdout = output
    ans.show()
    sys.stdout = tmp
    address = get_trace(output.getvalue())
    elapsed = round(time.time() * 1000) - start_time
    if "time-exceeded" in output.getvalue():
        return 1, address, elapsed
    return 0, address, elapsed

def display_trace(ip_dst, addresses, ttl, max, timestamp):
    print("\n\ntraceroute to ", ip_dst, " (", ip_dst, ")", max, " hops max, 60 byte packets", sep='')
    for i in range (1, ttl+1):
        time = timestamp[i-1] / 1000
        print(i, "  ", addresses[i-1], " (", addresses[i-1], ")  ", '%.2f' % time, "ms", sep='')

def traceroute(ip_dst, max = 30):
    addresses = ["none"] * max
    timestamp = [0] * max
    for i in range (1, max+1):
        icmp, addresses[i-1], timestamp[i-1] = is_target_reachable(ip_dst, i)
        if icmp == 0:
            display_trace(ip_dst, addresses, i, max, timestamp)
            return 0
    display_trace(ip_dst, addresses, i, max, timestamp)
    return 1

def main():
    if len(sys.argv) < 2:
        return 1
    if len(sys.argv) == 4 and sys.argv[2] == "-m":
        max_ttl = int(sys.argv[3])
        if max_ttl < 1:
            print("first hop out of range")
            return 1
        ttl = traceroute(sys.argv[1], max_ttl)
    else:
        traceroute(sys.argv[1])
    return 0

if __name__ == "__main__":
    exit(main())
