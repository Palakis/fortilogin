#!/usr/bin/env python
import sys
import httplib
import urllib
import ssl
from urlparse import urlparse

if len(sys.argv) < 3:
	print "Usage : " + __file__+ " username password"	
	exit()

username = sys.argv[1]
password = sys.argv[2]

testHost = "ipv4.icanhazip.com"

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

	# Used by urlopen calls to ignore SSL certification verification
	gcontext = ssl.SSLContext(ssl.PROTOCOL_TLSv1)

	# Step 1 - call the full URL returned by the captive portal	
	rep = urllib.urlopen(locationUrl, context=gcontext)	
	print "Step 1 : " + str(rep.getcode())

	# Step 2 - send a POST request to the "Yes, I agree" form
	params = urllib.urlencode({'4Tredir': 'http://' + testHost, 'magic': magic, 'answer': 1})
	rep = urllib.urlopen(postUrl, params, context=gcontext)
	print "Step 2 : " + str(rep.getcode())

	# Step 3 - send a POST request with your credentials to the Authentication form
	params = urllib.urlencode({'4Tredir': 'http://' + testHost, 'magic': magic, 'username': username, 'password': password})
	rep = urllib.urlopen(postUrl, params, context=gcontext)
	print "Step 3 : " + str(rep.getcode())

	# The HTTP response of the third step should be your IP address returned by icanhazip.com
	print "Final response (should be your public IP address) : " + rep.read()
else:
	print "Already authenticated"
