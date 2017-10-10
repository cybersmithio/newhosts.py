#!/usr/bin/python
#
# Gets a list of all the new hosts within the last number of hours specified
#
# Example usage with environment variables:
# TIOACCESSKEY="********************"; export TIOACCESSKEY
# TIOSECRETKEY="********************"; export TIOSECRETKEY
# TIOHOURS="24"; export TIOHOURS
# ./newhosts.py 
#



import json
import os
import csv
import sys
import datetime
from tenable_io.api.models import Folder
from tenable_io.client import TenableIOClient
from tenable_io.exceptions import TenableIOApiException
from tenable_io.api.models import AssetList, AssetInfo, VulnerabilityList, VulnerabilityOutputList

#
# Query Tenable.io for the asset list 
# and find all the hosts discovered within the past number of specified hours
#
def FindNewHosts(accesskey,secretkey,searchhours):
	DEBUG=False

	#Start counting the number of new assets
	newcount=0

	#Connect to Tenable.io
	client = TenableIOClient(access_key=accesskey, secret_key=secretkey)

	#Send API call to gather the list of assets
	resp=client.get("workbenches/assets")
	respdata=json.loads(resp.text)
	if DEBUG:
		print "Response",respdata
		print "\n\n"

	#Figure out the time delta based on the supplied hours.  This will be used
	# as the cut-off time.
	hoursago=datetime.datetime.now()-datetime.timedelta(hours=int(searchhours))


	#Open a CSV file
	with open("newhosts.csv","w") as csvfile:
        	fieldnames=['id','first_seen','FQDNs','IP Addresses','NetBIOS Names']
        	writer=csv.DictWriter(csvfile,fieldnames=fieldnames)
       		writer.writeheader()

		#Parse the data from Tenable.io
		for i in respdata['assets']:
			if DEBUG:
				print "Asset ID:",i['id']
				for x in i['sources']:
					print "First seen",x['first_seen'],'by a',x['name']
				for x in i['fqdn']:
					print "FQDN:",x
				for x in i['ipv4']:
					print "IPv4:",x
				for x in i['netbios_name']:
					print "NetBIOS name:",x

			#For this asset, go through all the vulnerability data sources and determine the
			# first time this asset was seen.
			first_seen=datetime.datetime.now()
			for x in i['sources']:
				this_time=datetime.datetime.strptime(x['first_seen'][0:19], '%Y-%m-%dT%H:%M:%S')
				if first_seen > this_time:
					first_seen=this_time
			if DEBUG:
				print "First seen:",first_seen

			#See if the first time the asset was seen is within the time range we are looking for.
			# If it is within the range, it is a new host and will be written to the CSV file.
			if first_seen >= hoursago:
				newcount+=1
				fqdns=""
				ipv4=""
				netbios=""
				if DEBUG:
					print "New host!!!"
					print "First seen:",first_seen
					print "Asset ID:",i['id']
				for x in i['sources']:
					if DEBUG:
						print "First seen",x['first_seen'],'by a',x['name']
				for x in i['fqdn']:
					if DEBUG:
						print "FQDN:",x
					if fqdns == "":
						fqdns=x
					else:
						fqdns=fqdns+","+x
				for x in i['ipv4']:
					if DEBUG:
						print "IPv4:",x
					if ipv4 == "":
						ipv4=x
					else:
						ipv4=ipv4+","+x
				for x in i['netbios_name']:
					if DEBUG:
						print "NetBIOS name:",x
					if netbios == "":
						netbios=x
					else:
						netbios=netbios+","+x
				if DEBUG:
					print
       		         	rowdict={'id':i['id'], 'first_seen': first_seen, 'FQDNs': fqdns,'IP Addresses': ipv4, 'NetBIOS Names': netbios}
                		writer.writerow(rowdict)
		csvfile.close()

		print "Total new hosts in the specified time range:",newcount

		#If there were no new assets, then delete the CSV file.
		if newcount == 0:
			os.remove("newhosts.csv")
	return(newcount)

################################################################
# Start of program 
################################################################
#Set debugging on or off
DEBUG=True

#Pull as much information from the environment variables
# as possible, and where missing then initialize the variables.
if os.getenv('TIOACCESSKEY') is None:
        accesskey=""
else:
        accesskey=os.getenv('TIOACCESSKEY')

if os.getenv('TIOSECRETKEY') is None:
        secretkey=""
else:
        secretkey=os.getenv('TIOSECRETKEY')

if os.getenv('TIOHOURS') is None:
        hours=""
else:
        hours=os.getenv('TIOHOURS')

if DEBUG:
        print "Connecting to cloud.tenable.com with access key",accesskey,"to report on new assets seen in the past",hours,"hours"

#Pull information from command line.  If nothing there,
# and there was nothing in the environment variables, then ask user.
if len(sys.argv) > 1:
        accesskey=sys.argv[1]
if accesskey == "":
	accesskey=raw_input("Access key:")

if len(sys.argv) > 2:
        hours=sys.argv[2]
if hours == "":
	hours=raw_input("Hours:")

if len(sys.argv) > 3:
	secretkey=sys.argv[3]
if secretkey == "":
	secretkey=raw_input("Secret key:")

if( FindNewHosts(accesskey,secretkey,hours) > 0 ):
	#Hosts were found for the time range specified, so return 1
	exit(1)
else:
	#No hosts were found in the time range specified, so return 0
	exit(0)

