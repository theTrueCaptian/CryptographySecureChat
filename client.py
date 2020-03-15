from socket import *
import socket
import sys
import string
import thread
import select
import time
import re
import pickle
import json
from securitymodule import *
from dropbox_client import *
import base64

HOST = '127.0.0.1'
PORT = 8900
ADDR = (HOST, PORT)

#Folder containing temporary files of the client
TEMP_FOLDER = os.getcwd()+'/client_temp/'

# Respond to commands
def client_commands(command, sym_security_module, dbx_inst, socket):	
	
	try:
		
		if command.startswith('/shareto'):
			match_obj = re.match( r'\/shareto\s+(\S*)\s+(\S*)', command)

			if match_obj:
				full_filename = match_obj.group(1)
				user = match_obj.group(2)

				# Get the filename from fullpath
				filename = full_filename
				match_obj1 = re.search( r"([^\\\/]*$)", full_filename)
				if match_obj:
					filename = match_obj1.group(1)
				
				# Get filecontent 
				filecontent = ''
				with open(full_filename, 'r') as f:
					filecontent = f.read()
				f.close()


				# /upload <metadata>, where metadata = {'filename', 'filecontent'}
				metadata_jsondump = json.dumps({'filename':filename, 'filecontent':filecontent})
				encrypted_message = sym_security_module.send_symmetric_encryption('/upload '+metadata_jsondump)

				# Inform the server of the buffer size				
				#size = pickle.dumps(sym_security_module.send_symmetric_encryption('/buffersize '+str(len(encrypted_message))))

				# Send the server the encrypted metadata 
				#socket.send(size)
				sym_security_module.send_message(socket, encrypted_message)
				#socket.send(encrypted_message)

			else:
				print 'Can\'t find the file. Please send a valid file!'
		'''
		if command.startswith('/sendto'):
			# Get the public key of the reciever from the server
			# Then send the encrypted file to the server
			# Encrypt the file and send it to the server
			match_obj = re.match(r'\/sendto\s*(\S*)\s*(\S*)', command)
			if match_obj:

				receiver = match_obj.group(1)
				full_filename = match_obj.group(0)

				# Get public key
				encrypted_message = pickle.dumps(sym_security_module.send_symmetric_encryption('/publickey '+receiver))
				socket.send(encrypted_message)
				receiver_public_key = wait_server(sym_security_module, socket)
				if receiver_public_key != '/invalid':
					receiver_public_key = re.match(r'\/publickey\s*(\S*)\s*', command).group(1)
					print 'public key of '+receiver+': '+receiver_public_key
				else:
					print receiver+' doesn\'t exist! '
					return
				reciever_security_module = SymmetricEncryption(receiver_public_key)
				
				# Retrieve only the filename and encrypt the filename
				filename = full_filename
				match_obj1 = re.search( r"([^\\\/]*$)", full_filename)
				if match_obj1:
					filename = match_obj1.group(1)

				#Encrypt the filename with the reciever's key and then with the server key
				filename_encrypted_receiver = pickle.dumps(sym_security_module.encrypt_message('/filename '+filename))
				filename_encrypted_server = pickle.dumps(reciever_security_module.encrypt_message('/filename '+receiver+' '+filename_encrypted_receiver))

				# Encrypt the file with the reciever's key and then the server key

				# Send filename and file
				socket.send(filename_encrypted_server)

				
				encrypted_message = pickle.dumps(sym_security_module.send_symmetric_encryption('/filecontents '+receiver))
				socket.send(encrypted_message)
				
				filename = 
				encrypted_filename = encrypt_file(filename, sym_security_module)
				upload_file(TEMP_FOLDER+encrypted_filename, dbx_inst)
				
			else:
				print 'Rerun the command: /sento <username> <filename>'

		elif command.startswith('/users'):
			# Send the request to the server 
			encrypted_message = pickle.dumps(sym_security_module.send_symmetric_encryption('/users'))
			socket.send(encrypted_message)

		
		elif command.startswith('/files'):

			sym_security_module.receive_symmetric_decryption(raw_data)

		elif command.startswith('/onlineusers'):

		elif command.startswith('/send'):	
			# /send <filename> <username>
		'''
	except IOError as e:
		print 'IO Error!\n' + str(e)
		print e.errno


'''
	Returns the encrypted filename in the temp folder
'''
def encrypt_file(full_filename, sym_security_module):
	'''
	# Read in the contents, encrypt it and then write out the content and its signature to some temp file to server
	contents = open(filename, 'r').read()
	encrypted_content = sym_security_module.encrypt_message(contents)
	'''
	#Encrypt the filename
	match_obj = re.search( r"([^\\\/]*$)", full_filename)
	filename = full_filename
	if match_obj:
		filename = match_obj.group(1)
	filename_encrypted = str(sym_security_module.encrypt_message(filename)[0])
	print TEMP_FOLDER+filename_encrypted
	#Encode into utf-8
	#filename_encrypted = unicode(filename_encrypted)
	'''
	#Write out the encrypted contents into the temp folder
	writeout = open(TEMP_FOLDER+filename_encrypted, 'w')
	writeout.write(unicode(pickle.dumps(encrypted_content)))
	json.dump
	writeout.close()
	'''
	FileSecurity().encrypt_file(sym_security_module.preshared_secret_key, full_filename, TEMP_FOLDER+filename_encrypted)
	return filename_encrypted

def wait_server(symmetric, sock):
	# Incoming message from remote server, s
	raw_data = symmetric.recieve_message(sock)

	if raw_data == None:
		print '\nDisconnected from chat server'
		sys.exit()

	server_command = symmetric.receive_symmetric_decryption(raw_data)
		
	'''
	raw_data = sock.recv(4096)
	
	if not raw_data :
		print '\nDisconnected from chat server'
		sys.exit()
	else :
		data = pickle.loads(raw_data)
		
		# Try decrypt with key i.e. the group chat key
		# If the verification with the key didn't work, then try with session key to see if it is message from the server
		# Read in the hmac
		plain_text = symmetric.receive_symmetric_decryption(data)	

		return plain_text
	'''

def chat_client():

	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.settimeout(2)
	# Connect to remote host
	try :
		s.connect(ADDR)
	except :
		print 'Unable to connect'
		sys.exit()
	
	# Establish session key via RSA
	# Instantiate symmetric encryption security module
	sessionkey = RSAKeyExchange(s).client_rsa_session_key(ADDR) 
	symmetric = SymmetricEncryption(sessionkey)

	# Send in the authenication with symmetric encryption
	authentication_info = username + ";password=" + password + ";"
	#encrypted_message = pickle.dumps(symmetric.send_symmetric_encryption(authentication_info))
	#s.send(encrypted_message)
	encrypted_message = symmetric.send_symmetric_encryption(authentication_info)
	symmetric.send_message(s, encrypted_message)

	# Create a dropbox instance
	dbx_inst = create_dbx_inst()

	commands_info = '\nCommands: \n /shareto <filename> <username>\n /files --> Get a list of files \n '
 	print commands_info
	sys.stdout.write(''); sys.stdout.flush()

	while 1:
		socket_list = [sys.stdin, s]
		 
		# Get the list sockets which are readable
		ready_to_read, ready_to_write, in_error = select.select(socket_list , [], [])
		 
		for sock in ready_to_read:    

			if sock == s:
				plain_text = wait_server(symmetric, sock)
				if plain_text != None:
					sys.stdout.write('\n'+plain_text)
				sys.stdout.write('\n'); sys.stdout.flush()     

			else :
				# User entered a message
				# Encrypt messages with the session key if the message is for the server
				msg = sys.stdin.readline()

				client_commands(msg, symmetric, dbx_inst, s)
				
				#encrypted_message = pickle.dumps(symmetric.send_symmetric_encryption(msg))
				#s.send(encrypted_message)
				sys.stdout.write('Me>'+msg); sys.stdout.flush() 


if __name__ == "__main__":

	username = raw_input("\nUsername: ")

	# Prompt the key that will decode the messages
	# Password is the non padded versus of password
	key = raw_input("\nPassword: ")
	password = key 	
	if key != '':
		padding = (int)(float(16*(int)(len(key)/16+1)))
		key = key.ljust(padding)

	sys.exit(chat_client())

