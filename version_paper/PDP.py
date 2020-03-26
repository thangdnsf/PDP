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
	  
#==========================================================#
#              UDP Sockets for communication               #
#==========================================================#
def egcd(a, b):
	if a == 0:
		return (b, 0, 1)
	else:
		g, y, x = egcd(b % a, a)
		return (g, x - (b // a) * y, y)

def modinv(a, m):
	g, x, y = egcd(a, m)
	if g != 1:
		raise Exception('modular inverse does not exist')
	else:
		return x % m
def string2digt(strs):
	digit = ''
	for s in strs:
		digit+=str(ord(s))
	return int(digit)
def power(b, p):
	"""
	Calculates b^p
	Complexity O(log p)
	b -> double
	p -> integer
	res -> double
	"""
	res = 1
	while p:
		if p & 0x1: res *= b
		b *= b
		p >>= 1
	return res  
class PDP():  
	def keyGen(self):
		RSAkeyPair = RSA.generate(2048,randfunc=None, e = 5)
		PubKey = RSAkeyPair.publickey()
		#print("Secrete key =", RSAkeyPair.d,"\n")
		#print("Public key =(", RSAkeyPair.n,RSAkeyPair.e,")\n")
		a = 253465
		self.pkey = (RSAkeyPair.n, a**2)
		self.skey = (35354,RSAkeyPair.d,8676)
		
	def loadKey(self):
		with open('key.txt','rb') as file:
			n = int(file.readline()[2:])
			e = int(file.readline()[2:])
			d = int(file.readline()[2:])
			v = int(file.readline()[2:])
			g = int(file.readline()[2:])
		self.pkey=(n,g)
		self.skey=(e,d,v)
	def getsample(self,file): 
		i = randint(0, len(file)-100)
		end = min(len(file),i+randrange(100,800))
		return (str(i)+str(end),file[i:end].decode('utf-8')) #(b=possition+size of sample, sample)
	
	
	def tagBlock(self, fromfile, N):
		# tag generation for each file block
		# W(i)= v || i
		# T(i,b(i))= ( h(W(i)) * g^b[i])^d mod n = (h(W(i))^d mod n * g^(b[i]*d) mod n) mod n
		self.N = N
		with open(fromfile,'rb') as file:
			data = file.read()
		
		blocks = [self.getsample(data) for _ in range(self.N)]
		
		W = [str(self.skey[2]) +str(i) for i in range(self.N)]
		
		T = [0]*self.N
		for i in range(self.N):
			message = bytes(W[i], "utf-8")
			gb = pow(self.pkey[1],string2digt(blocks[i][0])*self.skey[1],self.skey[0])
			wb = pow(int.from_bytes(SHA256.new(message).digest(),byteorder = 'big'),self.skey[1],self.skey[0])
			T[i] = pow(gb*wb,1,self.skey[0])
		print(T)
		return T, blocks

	def genChallenge(self,N):
		#randomly an integer m
		k = N//4
		left = math.log(N,2)
		right = left*10
		if left >= k:
			m = randrange(0,k+1)
		elif k > right:
			m = randrange(left,right)
		else:
			m = randrange(left,k+1)
		
		k1 = random.getrandbits(16)
		k2 = random.getrandbits(20)

		s = random.getrandbits(16)
		g = random.getrandbits(20)

		gs = pow(g,s,self.pkey[0])

		return (m,k1,k2,gs)
	def GenProof(F, chal, gama):

	

	def main(self):
		self.loadKey()
		print("publickey:",self.pkey)
		print("privatekey:",self.skey)
		self.tagBlock('file.txt',10)
	
	def run(self):
		print("Key is generating ...")
		self.keyGen()
		print("send public key:",self.pkey)
		self.sentKey()
		print("Sent!")

a = SocketClient()
a.main()