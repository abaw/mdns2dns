# Introduction
Host names ending in *.local* are reserved for MDNS. But they are used in some private networks as normal domain names. Some systems have problems resolving such domain names because they only query the names through MDNS. *mdns2dns* is a simple program to act like a proxy between MDNS client and DNS servers. When it receives a MDNS request, it will ask the answer from the DNS server and response to the MDNS request.


# Usage
The usage is really simple. The program accepts a list of domain name suffixes to be handled. For example, if you run *mdns2dns* as:

    mdns2dns xx.local yy.local

It will handle queries for names ending in xx.local and yy.local(e.g. a.xx.local, b.xx.local). Only queries for *A* type are handled now. Other types of queries will be ignored by the program. It will look at /etc/resolv.conf for DNS server to look up with.
