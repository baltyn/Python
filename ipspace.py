#!/usr/bin/env python3

import ipwhois
import netaddr

reserved = {'0.0.0.0': '0.255.255.255', 
'224.0.0.0': '239.255.255.255', 
'192.168.0.0': '192.168.255.255', 
'100.64.0.0': '100.127.255.255', 
'198.51.100.0': '198.51.100.255', 
'198.18.0.0': '198.19.255.255', 
'172.16.0.0': '172.31.255.255', 
'240.0.0.0': '255.255.255.255', 
'127.0.0.0': '127.255.255.255', 
'203.0.113.0': '203.0.113.255', 
'10.0.0.0': '10.255.255.255', 
'192.0.0.0': '192.0.0.7', 
'169.254.0.0': '169.254.255.255', 
'192.0.2.0': '192.0.2.255', 
'192.88.99.0': '192.88.99.255'}

startip = '0.0.0.0'
startipdec = int(netaddr.IPAddress(startip))
endip = '10.255.255.255'
endipdec = int(netaddr.IPAddress(endip))

ipint = startipdec
ipstr = startip

while ipint <= endipdec:
    if ipstr in reserved:
        ipblockend = reserved[ipstr]
        countrycode = '--'
        asn = '-'
    else:
        ipresult = ipwhois.IPWhois(ipstr).lookup()
        if len(ipresult['nets']) == 0 or '/' in ipresult['nets'][0]['range']: 
            tmpip = int(netaddr.IPAddress(ipstr)) + 65535
            ipblockend = str(netaddr.IPAddress(tmpip))            
        else:
            ipblockend = ipresult['nets'][0]['range'].partition('-')[2].strip()
        countrycode = ipresult['asn_country_code']
        if countrycode is None: countrycode = '--'
        asn = ipresult['asn']
        if asn is None: asn = '-'
        
    result = (ipstr+','+ipblockend+','+countrycode+','+asn+'\n')
    print(result.rstrip())
    f = open('/Users/wbaltyn/Desktop/ipspace.csv','a')
    f.write(result)
    f.close()
    ipint = int(netaddr.IPAddress(ipblockend))+1
    ipstr = str(netaddr.IPAddress(ipint))