from Crypto.Cipher import AES
import hmac
import hashlib
from hashlib import sha512

import Crypto
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Hash import MD5

import pickle
from time import time
import re

import base64
import os
import random, struct


class RSAKeyExchange(object):

	def __init__(self, socket):
		self.socket = socket
		self.KEY_LENGTH = 2048  # Key size (in bits)
	'''
	RSA key exchange for symmetric key exchange

	The server uses the server_rsa_session_key()
	The client uses the client_rsa_session_key()
	'''
	def server_rsa_session_key(self, SERVER_ADDR, addr):
		#Establish session key with the client
		#Create keys and send the public key to client
		random_gen = Random.new().read
		server_key = RSA.generate(self.KEY_LENGTH, random_gen)
		server_public  = server_key.publickey()
		self.socket.sendto(pickle.dumps(server_public), addr)

		#Receive the client's publickey later on to be used for encryption 
		client_public = pickle.loads(self.socket.recv(4096))
		print 'Received client '+str(addr)+' public key: '+str(client_public)

		#Encrypt the session key with the clien't public key and then send it to the client
		session_key = base64.b64encode(os.urandom(16))

		# Generate digital signatures using server private keys
		hash_session = MD5.new(session_key).digest()
		hash_signature = server_key.sign(hash_session, '')
		hash_encrypted = client_public.encrypt(session_key, 32) 
		tot_msg = (hash_encrypted, hash_signature)
		print 'Session key created for client '+str(addr)
		self.socket.sendto(pickle.dumps(tot_msg), SERVER_ADDR)

		return session_key

	def client_rsa_session_key(self, ADDR):
		#Establish key session with the server
		#Receive the server's publickey later on to be used for encryption 
		server_public = pickle.loads(self.socket.recv(4096))
		print 'Received server\'s public key: '+str(server_public)

		#Create keys and send the public key to server
		random_gen 		= Random.new().read
		client_key 		= RSA.generate(self.KEY_LENGTH, random_gen)
		client_public  	= client_key.publickey()
		self.socket.sendto(pickle.dumps(client_public), ADDR)

		#Receive the session key from the server
		sessionkey_data 		= pickle.loads(self.socket.recv(4096))
		encrypted_sessionkey 	= sessionkey_data[0]
		server_signature 		= sessionkey_data[1]

		#Decrypt the session key with client's private key
		sessionkey   = client_key.decrypt(encrypted_sessionkey)

		#Verify the signature with the decreypted session key
		hash_decrypted = MD5.new(sessionkey).digest()
		if not server_public.verify(hash_decrypted, server_signature):
			print 'Session key is corrupted! Ending session now.'
			sys.exit()

		return sessionkey

class SymmetricEncryption(object):

	def __init__(self, preshared_secret_key):
		self.last_time_message = -1
		self.preshared_secret_key = preshared_secret_key
		#self.socket = socket
	'''
	Sends a message:  
		- Message --> Ciphertext. Uses AES in CBC (chained) mode to protect against block switching.
		- Append a signature using HMAC (created from ciphertext) to protect message contents from tampering.

	Inputs: 
		- message: string type, unencrypted message e.g. "Hi, It is me."
		- preshared_secret_key: secret key for symmetric encryption. The receiver must have the same secret key.
		- socket: socket type object connection to the receiver
	'''
	def send_symmetric_encryption(self, message):

		#Finalize the message into a tuple object: (message, mac)
		final_message = self.encrypt_message(message)

		#Return the object
		return final_message

	def pad_msg(self, raw_message):
		#Pad the message to make the length a 16 character multiple. Append | to distinguish paadding and actual message
		raw_message = raw_message + '|'
		padding = (int)(float(16*(int)(len(raw_message)/16+1))) 	# e.g. float(16*(int)(100/16+1)) = 112
		message = raw_message.ljust(padding)
		return message

	def encrypt_message(self, message):
		iv = os.urandom(16)

		#Pad the message to make the length a 16 character multiple
		message = self.pad_msg("["+str(time())+"]"+message)
		#Encrypt the message
		encryption_suite = AES.new(self.preshared_secret_key, AES.MODE_CBC, 'This is an IV456')
		cipher_text = encryption_suite.encrypt(message)
		cipher_text = base64.b16encode(cipher_text)

		#Append signature
		digest_maker = hmac.new(self.preshared_secret_key,cipher_text,hashlib.sha512)

		return (cipher_text, digest_maker.hexdigest())

	'''
	Corresponding receiving end for send_symmetric_encryption
	Inputs:
		- raw_message: the raw message received
		- preshared_secret_key: secret key for symmetric encryption. The receiver must have the same secret key.
	Returns:
		- If the signature doesn't match, return None
		- If there are no problems: Returns the decrypted message
	'''
	def receive_symmetric_decryption(self, raw_message):

		#Authenticate the user. Decrypt with the session_key
		message = self.split_message(raw_message)
		
		#Compute hash to check for tampering
		if not self.is_verified(self.preshared_secret_key, message[0], message[1]):
			print "Message is tampered! MAC signature doesn't match."
			#The message has been tampered with
			return None

		cipher_text = base64.b16decode(message[0])
		#iv = cipher_text[0:16]
		#cipher_text = cipher_text[16:]
		decryption_suite = AES.new(self.preshared_secret_key, AES.MODE_CBC, 'This is an IV456')
		original_message = decryption_suite.decrypt(cipher_text)
		print original_message

		#Check timestamps for replay attacks
		matchObj = re.match( r'\[([0-9]+)\.*[0-9]*\](.*)', original_message)
		if matchObj:
			#If the last time a message was received is greater than this message timestamp, then the message was replayed
			if long(matchObj.group(1))<self.last_time_message :
				print "The message was replayed."
				return None
			else:
				self.last_time_message = long(matchObj.group(1))
				original_message = matchObj.group(2)

		# Remove the padding
		matchObj1 = re.match( r'(.+)\|\s+$', original_message)
		if matchObj1:
			original_message = matchObj1.group(1)

		print original_message
		return original_message		
		
	def is_verified(self, preshared_secret_key, received_message, received_mac):
		expected_mac = hmac.new(preshared_secret_key, received_message, hashlib.sha512)
		if hmac.compare_digest(expected_mac.hexdigest(), received_mac):
			return True
		return False

	def split_message(self, raw_message):
		split = raw_message
		message = split[0]
		mac = split[1]
		return (message, mac)

	'''
	The following methods sends and receives arbitrary length messages. Used for messages containing file metadata including filecontent
	'''
	def send_message(self, socket, message):
		# Send a message with arbitrary length. This method is fit for long messages containing the whole file
		# message is a tuple from encrypt_message()
		pickled_message = pickle.dumps(message)
		length = len(pickled_message)

		# Prefix each message with a 4-byte length (network byte order)
		tot_msg = struct.pack('>I', length) + pickled_message
		socket.sendall(tot_msg)

	def recieve_message(self, socket):
		# Receive a message with an arbitrary message length
		# Read message length and unpack it into an integer
		raw_msglen = self.recvall(socket, 4)
		if not raw_msglen:
			return None
		msglen = struct.unpack('>I', raw_msglen)[0]

		# Read the message data
		return pickle.loads(self.recvall(socket, msglen))
	 
	def recvall(self, socket, n):
		# Helper function to recv n bytes or return None if EOF is hit
		data = ''
		while len(data) < n:
			packet = socket.recv(n - len(data))
			if not packet:
				return None
			data += packet
		return data


class FileSecurity(object):

	def encrypt_file(self, key, in_filename, out_filename=None, chunksize=64*1024):
		""" Encrypts a file using AES (CBC mode) with the
			given key.

			key:
				The encryption key - a string that must be
				either 16, 24 or 32 bytes long. Longer keys
				are more secure.

			in_filename:
				Name of the input file

			out_filename:
				If None, '<in_filename>.enc' will be used.

			chunksize:
				Sets the size of the chunk which the function
				uses to read and encrypt the file. Larger chunk
				sizes can be faster for some files and machines.
				chunksize must be divisible by 16.
		"""
		if not out_filename:
			out_filename = in_filename + '.enc'

		iv = ''.join(chr(random.randint(0, 0xFF)) for i in range(16))
		#encryptor = AES.new(key, AES.MODE_CBC, iv)
		encryptor = SymmetricEncryption(key)
		filesize = os.path.getsize(in_filename)

		with open(in_filename, 'rb') as infile:
			with open(out_filename, 'wb') as outfile:
				outfile.write(struct.pack('<Q', filesize))
				outfile.write(iv)

				while True:
					chunk = infile.read(chunksize)
					if len(chunk) == 0:
						break
					elif len(chunk) % 16 != 0:
						chunk += ' ' * (16 - len(chunk) % 16)

					#outfile.write(encryptor.encrypt(chunk))
					outfile.write(pickle.dumps(encryptor.send_symmetric_encryption(chunk)))


	def decrypt_file(self, key, in_filename, out_filename=None, chunksize=24*1024):
		""" Decrypts a file using AES (CBC mode) with the
			given key. Parameters are similar to encrypt_file,
			with one difference: out_filename, if not supplied
			will be in_filename without its last extension
			(i.e. if in_filename is 'aaa.zip.enc' then
			out_filename will be 'aaa.zip')
		"""
		if not out_filename:
			out_filename = os.path.splitext(in_filename)[0]

		with open(in_filename, 'rb') as infile:
			origsize = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]
			iv = infile.read(16)
			#decryptor = AES.new(key, AES.MODE_CBC, iv)
			decryptor = SymmetricEncryption(key)

			with open(out_filename, 'wb') as outfile:
				while True:
					chunk = infile.read(chunksize)
					if len(chunk) == 0:
						break
					#outfile.write(decryptor.decrypt(chunk))
					outfile.write(decryptor.receive_symmetric_decryption(pickle.loads(chunk)))
				outfile.truncate(origsize)
