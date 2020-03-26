import signal, os  
import threading
import socket
import sys
from threading import Thread
import queue
import time
import Crypto
from Crypto.Signature import PKCS1_PSS
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto import Random
import numpy as np
import math
from random import randint, randrange
import random
from Crypto.Cipher import PKCS1_v1_5 as Cipher_PKCS1_v1_5
from base64 import b64decode,b64encode
	  
#==========================================================#
#              UDP Sockets for communication               #
#==========================================================#

class SocketServer(Thread):  # Socket for data packet transmission  
	def __init__(self):
		Thread.__init__(self)
		self._stop_event = threading.Event()        
	def stop(self):
		self._stop_event.set()
	
	def loadKey(self):
		with open ("public.pem", "r") as pub_file:
			key = pub_file.read()
			self.pkey =RSA.importKey(key)

	def getsample(self,file, start = None, end = None): 
		if start is None:
			start = randint(0, len(file)-100)
		if end is None:
			end = min(len(file),start+randrange(100,800))
		return (str(start)+'_'+str(end),file[start:end]) #(b=possition+size of sample, sample)
	
	def GenProof(self, fromfile):
		self.loadKey()
		with open('chals_' + fromfile,'rb') as file:
			chals = file.readlines()
		with open(fromfile,'rb') as file:
			data = file.read()
		
		results = ""
		with open('genProof_'+fromfile, 'w+') as file:
			for chal in chals:
				tmp =chal.decode('utf-8').replace('\n','').split('_')
				start = int(tmp[0])
				end = int(tmp[1])
				block = self.getsample(data,start,end)
				hashi = SHA256.new(block[1]).hexdigest()
				results += hashi
			H = SHA256.new(results.encode('utf-8')).hexdigest()
			cipher = Cipher_PKCS1_v1_5.new(self.pkey)
			cipher_text = b64encode(cipher.encrypt(H.encode()))
			file.write(cipher_text.decode('utf-8'))
	
	def sentFile(self,filename):
		SockServer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
		SockServer.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

		try:
			SockServer.bind(("", 44445))    # :::Adapt Port#
		except SockServer.error as msg:
			print("Server: Error in bind", msg, "\n")
		
		SockServer.sendto(bytes(filename, "utf-8"), (Client_IP_Addr, 37021))

		with open(filename, 'rb') as f:
			l = f.read(1024)
			print('Sending '+filename+': ',end='')
			while (l):
				SockServer.sendto(l, (Client_IP_Addr, 37021))
				l = f.read(1024)
				print('.',end='')
		SockServer.sendto(l, (Client_IP_Addr, 37021))
		print(' Done!')
	
	def receiveFile(self):
		SockServer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) 
		SockServer.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
		try:
			SockServer.bind(("", 37021))  # :::Adapt Port#
		except SockServer.error as msg:
			print("Server: Error in bind", msg, "\n")
		filename, addr = SockServer.recvfrom(1024)
		filename = filename.decode('utf-8')

		#print(filename)
		f =  open(filename, 'wb')
		print('Receiving '+filename+': ',end='')
		while True:
			data, addr = SockServer.recvfrom(1024)
			if addr[0] == Client_IP_Addr:
				print('.',end='')
				if not data:
					break
				# write data to a file
				f.write(data)	
		f.close()
		print("Done!")
		if	'chals_' in filename:
			self.GenProof(filename[6:])
			self.sentFile('genProof_'+filename[6:])

	def run(self):
		while True:
			self.receiveFile()
			
#------------------------------------------------------#
#           *            MAIN              *           #
#------------------------------------------------------#

#------------------------------------------------------
# Wireless network setup
Server_IP_addr = '192.168.0.125'  # ::: Adapt IP address #
Broadcast_IP_Addr = '192.168.0.255'   # :::Adapt IP broadcast address #
Client_IP_Addr = '192.168.0.108' 
# Connect to wifi
#os.system("sudo ifup wlan0")
#os.system("sudo ip link set wlan0 up")
# ::: Use a Net name
#os.system("sudo iwconfig wlan0 essid NetName mode ad-hoc channel 1 enc off")
#cmd = "sudo ifconfig wlan0 " + My_IP_addr +" netmask 255.255.255.0 broadcast "+ Broadcast_IP_Addr
#os.system(cmd)
  
# Allocation of packet reception and transmission queues 
ReceptionQueue = queue.Queue(500)
TransmissionQueue = queue.Queue(500)

# Sockets declaration and opening
#PktClient = SocketClient()    # Socket for receiving packets
#PktClient.start()
PktServer = SocketServer()  # Socket for sending packets
PktServer.start()


# Stop socket threads before Quit.
#PktClient.stop()
PktServer.stop()
