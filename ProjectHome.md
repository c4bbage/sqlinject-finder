### Brief Description ###
Simple python script that parses through a pcap and looks at the GET and POST request data for suspicious and possible SQL injects. Rules to check for SQL injection can be easily added. Output can be printed neatly on the command line or in tab delimited format.

The output includes:
  * The suspicious IP address
  * The attacked webpage
  * The parameter and value used
  * The frame number of the packet within the pcap (can be used to find exactly where the packet is in Wireshark)
  * The reason why the request was flagged

### Tool Usage ###
```
This tool parses through a pcap file and looks for potential SQL injection attempts.

usage: sqlinject-finder.py -f filename [-t]
Options and arguments (and corresponding environment variables):
-f, --filename : valid pcap file
-t, --tab      : prints output in tab delimited format
-h, --help     : shows this screen

Example: #python sqlinject-finder.py -f capture.pcap
         #python sqlinject-finder.py -f capture.pcap -t > capture.tsv
```

### Sample Output ###
```
Source : 172.16.10.139
Page   : /includes/auth.php
Value  : pwd=' OR 1='1
Frame  : 256
Reason : Possible use of SQL syntax in variable

Source : 172.16.10.139
Page   : /services.php
Value  : id=1 UNION SELECT NULL, table_schema, table_name, column_name FROM info
rmation_schema.columns WHERE table_schema != 'mysql' AND table_schema != 'inform
ation_schema';
Frame  : 1432
Reason : Possible use of SQL syntax in variable
```

### Dependencies ###
This script was tested using Python 2.6.5. Other versions are not guaranteed to work.

This script depends on the dpkt libraries. They can be downloaded from here:
http://code.google.com/p/dpkt/downloads/list