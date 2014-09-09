# Python stuff
## ipspace.py

ipspace is designed to run through IP space from 0.0.0.0 to 255.255.255.255 and pull back
country code and ASN.

Problems identified and now solved:
* Private networks cause lookup errors; obtained and added as exception dictionary
* Some addresses provide range 0.0.0.0 - 255.255.255.255 causing false end to script
* Some ranges are shown not as start - end but cidr (e.g. 192.168.0.0/16)
* WHOIS data blank or missing
