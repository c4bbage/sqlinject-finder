#!/usr/bin/env python

####################################################################################
#
# sqlinject-finder.py
#
# Author: Tyler Dean
# Date  : 11/19/2010
# Description: Simple python script that parses through a pcap and looks at the 
#              GET and POST request data for suspicious and possible SQL injects.
#
####################################################################################

import dpkt, re, urllib, sys, getopt

#removes inline comments that can sometimes be used for obfuscating the sql
def removeComments(val):
	while True:
			index = val.find("/*")
			index2 = val.find("*/")
			if index != -1 and index2 != -1:
				#looks like there is some type of SQL obfuscation, let's remove the comments
				remove = val[index:index2+2]
				val = val.replace(remove, "")
			else:
				break
	
	return val

#checks for common sql injection tactics using all the variables from post or get data
def checkSQL(vals):
	for pair in vals:
		var = pair[0] #the variable, i.e. in id=1, the var is id
		val = pair[1] #the value, i.e. in id=1, the val is 1
		val = val.decode('ascii') #not sure if this is really doing anything, but we need to deal with non ascii characters for analysis
		val = urllib.unquote(val) #removes url encodings like %20 for space, etc
		val = val.replace("+", " ") #sometimes in urls, instead of a space you can have a + . So, we want to remove those for analysis
		#print val
		
		##### Look for obfuscation techniques ######
		index = val.find("/*")
		if index != -1:
			print var + "=" + val
			print "Might be attempting to obfuscate a SQL statement with a comment"
			val = removeComments(val)

		##### Look for commenting out the end of a MSSQL statement ######
		index = val.rfind("--")
		if index != -1:
			print var + "=" + val
			print "Might be attempting to end a SQL statement by commenting out the remaining statement"
		
		##### Look for commenting out the end of a MySQL statement #####
		index = val.rfind("#")
		if index != -1:
			print var + "=" + val
			print "Might be attempting to end a SQL statement by commenting out the remaining statement"
		
		##### Look for common SQL syntax in the values of a param #####
		sqlvals = ("cast(", "declare ", "select ", "union ", "varchar", "set(", "create ", " or ", " NULL,", " concat(")
		for sql in sqlvals:
			index = val.lower().find(sql)
			if index != -1:
				print var + "=" + val
				print "Possible use of SQL syntax in variable"
				break

#reads the pcap file and parses out get and post requests for analysis
def parsepcap(filename):
	try:
		f = open(filename, 'rb')
	except:
		print "Error reading file. Please make sure the file exists"
		sys.exit()
		
	try:
		pcap = dpkt.pcap.Reader(f)
	except:
		print "Error reading file. Please make sure the file is a valid pcap file."
		sys.exit()
		
	for ts, buf in pcap:
		eth = dpkt.ethernet.Ethernet(buf)
		ip = eth.data
		#make sure we are dealing with ip (2048) and tcp (proto=6)
		if eth.type ==2048 and ip.p == 6: 
			tcp = ip.data
			#assuming http is running on port 80
			if tcp.dport == 80 and len(tcp.data) > 0:
				index = 1
				try:
					http = dpkt.http.Request(tcp.data)
					#deal with post data
					if http.method == "POST":
						getvals=http.body
					#deal with GET data
					elif http.method == "GET":
						url = http.uri
						index = url.rfind("?")
						if index != -1:
							getvals = url[index+1:]
					else:
						index = -1
				except:
					data = tcp.data
					index = data.count("\n") #need to look into this method a little more, basically, we want to get POST data out of other streams
					if index == 0:
						index = data.find("=")
						if index != -1:
							getvals = data
					else:
						index = -1
						
				#split up each variable and its cooresponding value
				if index != -1:
					getvals = getvals.split("&")
					vals = []
					for val in getvals:
						i = val.find("=")
						val = (val[:i], val[i+1:])
						vals.append(val)
					checkSQL(vals)
				

	f.close()				

#usage stuff
def usage():
	print ""
	print "This tool parses through a pcap file and looks for potential SQL injection attempts."
	print ""
	print "usage: sqlinject-finder.py -f filename"
	print "Options and arguments (and corresponding environment variables):"
	print "-f, --filename : valid pcap file"
	print "-h, --help     : shows this screen"
	print ""
	print "Example: #python sqlinject-finder.py -f capture.pcap"
	print ""

def main():
	try:	
		opts, args = getopt.getopt(sys.argv[1:], "f:h", ["filename=","help"])
	except getopt.GetoptError, err:
		print str(err)
		usage()
		sys.exit(2)

	filename = ""
	for o, a in opts:
		if o in ("-f", "--filename"):
			filename = a
		elif o in ("-h", "--help"):
			usage()
			sys.exit()
		else:
			usage()
			sys.exit()
	if (filename == ""):
		print "please specify a filename"
		sys.exit()
	parsepcap(filename)

if __name__ == "__main__":
	main()	