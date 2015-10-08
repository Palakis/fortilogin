#!/usr/bin/env python
import sys
import httplib
import urllib2
import ssl
import re
from urllib import urlencode
from urlparse import urlparse
from getpass import getpass

# Show usage info and exit if not arguments are given
if len(sys.argv) < 2:
	print "Usage : " + __file__+ " username [password]"
	exit()

username = sys.argv[1]

# Get the password from the arguments if specified, prompt for it otherwise
if len(sys.argv) >= 3:
	password = sys.argv[2]
else:
	password = getpass('Password for ' + username + ' :')

# The script will try to match testRegex against the data returned by testHost
testHost = "ipv4.icanhazip.com"
testRegex = "^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$\n" # ICHI has a line return after the IP address 

# Initial request to know if I'm behind a Fortinet captive portal
# I'm using httplib to detect and avoid the automatic redirection performed by urllib
conn = httplib.HTTPConnection(testHost)
conn.request('GET', '/')
rep = conn.getresponse()

# The captive portal responds with HTTP rep code 303
if rep.status == 303:
	# So I can extract the magic token embedded in the value of the Location header.
	# This value is something like this : http://10.151.0.1:1000/fgtauth?0004610d63757532
	
	locationUrl = rep.getheader('Location')
	portalUrl = urlparse(locationUrl)
	magic = portalUrl.query

	postUrl = portalUrl.scheme + "://" + portalUrl.netloc + "/"

	print "Not authenticated !"
	print "Redirected to " + locationUrl
	print "------"
	print "Captive portal url : " + postUrl 
	print "Magic token : " + magic
	print "------"
	
	print "Authenticating as " + username

	# Step 1 - call the full URL returned by the captive portal	
	rep = urllib2.urlopen(locationUrl)	
	print "Step 1 : " + str(rep.getcode())

	# Step 2 - send a POST request to the "Yes, I agree" form
	rep = urllib2.urlopen(postUrl, urlencode({'4Tredir': 'http://' + testHost, 'magic': magic, 'answer': 1}))
	print "Step 2 : " + str(rep.getcode())

	# Step 3 - send a POST request with your credentials to the Authentication form
	rep = urllib2.urlopen(postUrl, urlencode({'4Tredir': 'http://' + testHost, 'magic': magic, 'username': username, 'password': password}))
	print "Step 3 : " + str(rep.getcode())

	testResponse = rep.read()
	if re.compile(testRegex).match(testResponse) != None:
		print "Authenticated !"
	else:
		print "Seems like something went wrong. Here's what I received :\n"
		print testReponse
else:
	print "Already authenticated"
