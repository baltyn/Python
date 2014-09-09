#!/usr/bin/env python3

''' Scans IP address space between startip and endip and outputs
beginning and end IP of a range, country code and ASN in a csv
'''
import ipwhois
import netaddr

# Dictionary of private IP addresses
# used to prevent errors when using ipwhois.IPWhois() function
privatenet = {'192.88.99.0': '192.88.99.255', 
'192.0.2.0': '192.0.2.255', 
'192.168.0.0': '192.168.255.255', 
'0.0.0.0': '0.255.255.255', 
'192.0.0.0': '192.0.0.7', 
'169.254.0.0': '169.254.255.255', 
'198.18.0.0': '198.19.255.255', 
'240.0.0.0': '255.255.255.255', 
'100.64.0.0': '100.127.255.255', 
'10.0.0.0': '10.255.255.255', 
'198.51.100.0': '198.51.100.255', 
'203.0.113.0': '203.0.113.255', 
'172.16.0.0': '172.31.255.255', 
'224.0.0.0': '239.255.255.255', 
'127.0.0.0': '127.255.255.255'}

startip = int(netaddr.IPAddress('0.0.0.0')) # start of run
endip = int(netaddr.IPAddress('224.0.0.0')) # end of run
ip = startip

while ip <= endip:
	stringip = str(netaddr.IPAddress(ip)) # convert decimal ip to dotted decimal string
	# checks to see if IP address is private, if so, looks up blockend in
	# privatenet dictionary, adds one to the IP address and starts the loop again
	if stringip in privatenet:
		blockend = int(netaddr.IPAddress(privatenet[stringip])) # obtain last IP in private net as dec
		ip = blockend + 1 # add 1 to ip move to next block
		result=(stringip.strip()+','+str(netaddr.IPAddress(blockend))+','+'--'+','+'-'+'\n') # format result text
	else:
		try:
			result = ipwhois.IPWhois(stringip).lookup() # carry out WHOIS lookup
		except:
			result = dict() # on error create empty dictionary
			result['nets'] = '' # on error create empty entry 'nets'
		if len(result['nets']) == 0: # case where WHOIS info is empty
			minip = stringip
			tmpip = stringip
			maxip = str(netaddr.IPAddress(int(netaddr.IPAddress(stringip))+65535)) # make block a /16
			countrycode = '--'
			asn = '-'
		else:
			tmpip, _, maxip = result['nets'][0]['range'].partition('-') # carve out start, end IP addresses
			if maxip.strip() == '255.255.255.255': # case where WHOIS range is 0.0.0.0 - 255.255.255.255
				maxip = str(netaddr.IPAddress(int(netaddr.IPAddress(stringip))+16777215)) # make block a /8
			minip = stringip
			countrycode = result['asn_country_code'] # return two-letter country code
			asn = result['asn'] # return ASN
			if countrycode is None: countrycode = '--' # case where no country data
			if asn is None: asn = '-' # case where no ASN data
			
		result = (minip.strip()+','+maxip.strip()+','+countrycode+','+asn+'\n') # format result text
		if '/' in tmpip: # case where range is incorrectly stated as CIDR
			ip = ip + 65536 # assumed to be /16 - move ip to next block
		else:
			ip = int(netaddr.IPAddress(maxip.strip()))+1 # strip leading spaces from end of range address, add 1 to move to next block

	# Prints result text w/o line break, outputs result text to file
	print(result.strip())
	outputfile = open('/home/ubuntu/Desktop/IPspace_all.csv','a')
	outputfile.write(result)
	outputfile.close() # close file after each write to guard against crash
