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
		  
class SocketClient(Thread):  # Socket for packet reception  
	def __init__(self):
		Thread.__init__(self)
		self._stop_event = threading.Event()        
	def stop(self):
		self._stop_event.set()

	def keyGen(self, password = None):
		RSAkeyPair = RSA.generate(2048,randfunc=None, e = 5)
		PubKey = RSAkeyPair.publickey()
		self.pkey = PubKey
		self.skey = RSAkeyPair
		with open ("private.pem", "w") as prv_file:
			print("{}".format(RSAkeyPair.exportKey(passphrase=password).decode("utf-8")), file=prv_file)

		with open ("public.pem", "w") as pub_file:
			print("{}".format(PubKey.exportKey().decode("utf-8")), file=pub_file)

	def loadKey(self,password=None):
		with open ("private.pem", "r") as prv_file:
			key = prv_file.read()
			self.skey =RSA.importKey(key,passphrase=password)
		with open ("public.pem", "r") as pub_file:
			key = pub_file.read()
			self.pkey =RSA.importKey(key)
	
	def getsample(self,file, start = None, end = None): 
		if start is None:
			start = randint(0, len(file)-100)
		if end is None:
			end = min(len(file),start+randrange(100,800))
		return (str(start)+'_'+str(end),file[start:end]) #(b=possition+size of sample, sample)
	
	def tagBlock(self, fromfile, N):
		with open(fromfile,'rb') as file:
			data = file.read()
		
		blocks = [self.getsample(data) for _ in range(N)]
		with open('tagBlocks_'+fromfile, 'w+') as file:
			for key, value in blocks:
				hashi = SHA256.new(value).hexdigest()
				file.write(key+'\t'+hashi+'\n')
	
	def genChallenge(self,fromfile):
		with open('tagBlocks_'+fromfile, 'r') as file:
			block_keys = file.readlines()
		N = len(block_keys)
		k = N//4
		left = int(math.log(N,2))
		right = left*10
		if left >= k:
			m = randrange(1,k+1)
		elif k > right:
			m = randrange(left,right)
		else:
			m = randrange(left,k+1)
		rands = random.sample(block_keys,m)
		
		hashis=[]
		with open('chals_'+fromfile, 'w+') as file:
			for v in rands:
				key,value = v.split('\t')
				file.write(key+'\n')
				hashis.append(value)
		return hashis

	def CheckProof(self,fromfile,hashis):
		#read genproof
		with open('genProof_'+fromfile, 'r') as file:
			data = file.read()
		#decrypt
		cipher = Cipher_PKCS1_v1_5.new(self.skey)
		V = cipher.decrypt(b64decode(data),None)
		
		#build checkmodel from hashis
		results=""
		for hashi in hashis:
			results += hashi.replace('\n','')
		#hash results
		p = SHA256.new(results.encode('utf-8')).hexdigest().encode('utf-8')
		
		#check validate
		if V == p:
			return "success"
		return "failure"

	def sentFile(self,filename):
		SockClient = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
		SockClient.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

		try:
			SockClient.bind(("", 44445))    # :::Adapt Port#
		except SockClient.error as msg:
			print("Client: Error in bind", msg, "\n")
		
		SockClient.sendto(bytes(filename, "utf-8"), (Server_IP_addr, 37021))
		with open(filename, 'rb') as f:
			l = f.read(1024)
			print('==> Sending '+filename+': ',end='')
			
			while (l):
				SockClient.sendto(l, (Server_IP_addr, 37021))
				l = f.read(1024)
				print('.',end='')
		SockClient.sendto(l, (Server_IP_addr, 37021))
		print(' Done!')
	
	def receiveFile(self):
		SockClient = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) 
		SockClient.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
		try:
			SockClient.bind(("", 37021))  # :::Adapt Port#
		except SockClient.error as msg:
			print("Server: Error in bind", msg, "\n")
		
		filename, addr = SockClient.recvfrom(1024)
		filename = filename.decode('utf-8')
		
		with open(filename, 'wb') as f:
			print('==> Receiving '+filename+': ',end='')
			while True:
				data, addr = SockClient.recvfrom(1024)
				
				if addr[0] == Server_IP_addr:
					print('.',end='')
					if not data:
						break
					# write data to a file
					f.write(data)	
		print("Done!")

	def showmenu(self):
		print("1. Gen key and send key to server.")
		print("2. Load key.")
		print("3. Create tagblock and send file to server.")
		print("4. Request phase.")
		print("5. Exit")
	def func(self, num):
		if num == 1:
			self.keyGen(password="05041995")
			print("==> Created key!")
			self.sentFile("public.pem")
		elif num == 2:
			self.loadKey(password="05041995")
			print("==> Loaded!")
		elif num == 3:
			fromfile = input("Enter filename: ")
			N = input("Enter N: ")
			self.tagBlock(fromfile, int(N))
			self.sentFile(fromfile)
		elif num ==4:
			fromfile = input("Enter filename: ")
			hashis = self.genChallenge(fromfile)
			self.sentFile('chals_'+fromfile)
			self.receiveFile()
			print("==>",self.CheckProof(fromfile,hashis))

		
	def run(self):
		while True:
			self.showmenu()
			c = input("Enter: ")
			self.func(int(c))

		
			
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
PktClient = SocketClient()    # Socket for receiving packets
PktClient.start()
#PktServer = SocketServer()  # Socket for sending packets
#PktServer.start()

while True:
	time.sleep(3)

# Stop socket threads before Quit.
PktClient.stop()
#PktServer.stop()