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
import base64

HOST = '127.0.0.1'
PORT = 8001
ADDR = (HOST, PORT)

#Folder containing temporary files of the client
TEMP_FOLDER = os.getcwd()+'/client_temp/'

# Respond to commands
def client_commands(command, sym_security_module, socket):	
	
	try:
		
		if command.startswith('/shareto'):
			match_obj = re.match( r'\/shareto\s+(\S*)\s+(.*)', command)

			if match_obj:
				full_filename = match_obj.group(1)
				recievers = match_obj.group(2)

				users = filter(lambda x:x!='', recievers.split(' '))
				
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

				# Send the server the encrypted metadata 
				sym_security_module.send_message(socket, encrypted_message)

				# If the creator specifies the file is shared with some other users
				if users:
					# Add users to the file
					for new_user in users:
						encrypted_users = sym_security_module.send_symmetric_encryption('/addusers '+filename+' '+new_user)
						sym_security_module.send_message(socket, encrypted_users)

			else:
				print 'Can\'t find the file or invalid command.\n'
	
		elif command.startswith('/list'):
			encrypted_users = sym_security_module.send_symmetric_encryption('/list')
			sym_security_module.send_message(socket, encrypted_users)

		elif command.startswith('/addusers'):
			match_obj1 = re.match( r'\/addusers\s+(\S*)\s+(.*)', command)
			if match_obj1:
				full_filename = match_obj1.group(1)
				recievers = match_obj1.group(2)

				# Get the filename from fullpath
				filename = full_filename
				match_obj3 = re.search( r"([^\\\/]*$)", full_filename)
				if match_obj1:
					filename = match_obj3.group(1)

				users = filter(lambda x:x!='', recievers.split(' '))

				if len(users) > 0:
					# Add users to the file
					for new_user in users:
						encrypted_users = sym_security_module.send_symmetric_encryption('/addusers '+filename+' '+new_user)
						sym_security_module.send_message(socket, encrypted_users)
				else:
					print 'Invalid command'

			else:
				print 'Invalid command'

		elif command.startswith('/download'):
			match_obj1 = re.match( r'\/download\s+(\S*)\s+(.*)', command)
			if match_obj1:
				if match_obj1.group(2):
					print 'Invalid command'
					return 

				filename = match_obj1.group(1)
				encrypted_msg = sym_security_module.send_symmetric_encryption('/download '+filename)
				sym_security_module.send_message(socket, encrypted_msg)
			else:
				print 'Invalid command'

		elif command.startswith('/deleteusers'):
			match_obj1 = re.match( r'\/deleteusers\s+(\S*)\s+(.*)', command)
			if match_obj1:
				full_filename = match_obj1.group(1)
				recievers = match_obj1.group(2)

				# Get the filename from fullpath
				filename = full_filename
				match_obj3 = re.search( r"([^\\\/]*$)", full_filename)
				if match_obj1:
					filename = match_obj3.group(1)

				users = filter(lambda x:x!='', recievers.split(' '))

				if len(users) > 0:
					# Add users to the file
					for delete_user in users:
						encrypted_users = sym_security_module.send_symmetric_encryption('/deleteusers '+filename+' '+delete_user)
						sym_security_module.send_message(socket, encrypted_users)
				else:
					print 'Invalid command'

			else:
				print 'Invalid command'

		elif command.startswith('/deletefile'):
			match_obj1 = re.match( r'\/deletefile\s+(\S*)\s+(.*)', command)
			if match_obj1:
				if match_obj1.group(2):
					print 'Invalid command'
					return 

				full_filename = match_obj1.group(1)
				# Get the filename from fullpath
				filename = full_filename
				match_obj3 = re.search( r"([^\\\/]*$)", full_filename)
				if match_obj1:
					filename = match_obj3.group(1)

				encrypted_msg = sym_security_module.send_symmetric_encryption('/deletefile '+filename)
				sym_security_module.send_message(socket, encrypted_msg)
			else:
				print 'Invalid command'

		else:
			print 'Invalid command'

	except IOError as e:
		print 'IO Error!\n' + str(e)
		print e.errno


def wait_server(symmetric, sock):
	# Incoming message from remote server, s
	raw_data = symmetric.recieve_message(sock)

	if raw_data == None:
		print '\nDisconnected from chat server'
		sys.exit()

	server_command = symmetric.receive_symmetric_decryption(raw_data)

	return server_command

def server_response(plain_text):
	if plain_text.startswith('/download '):
		# /download <metadata>, where metadata = {'filename', 'filecontent', 'creator'}
		match_obj = re.match( r'\/download (.+)', plain_text)
		if match_obj:
			metadata_raw = match_obj.group(1)

			# Transform: raw data --> json --> pickle
			metadata = json.loads(metadata_raw)
			filename = metadata['filename']
			filecontent = metadata['filecontent']
			
			target = open(TEMP_FOLDER+filename, 'w')
			target.write(filecontent)
			target.close()

			print 'Downloaded '+filename+' to '+TEMP_FOLDER
	else:
		print plain_text

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
	encrypted_message = symmetric.send_symmetric_encryption(authentication_info)
	symmetric.send_message(s, encrypted_message)

	commands_info = '\nCommands: \n /shareto <filename> <users>\n /list --> Get a list of files \n /addusers <filename> <users> \n /download <filename> \n /deleteusers <filename> <users> \n /deletefile <filename> \n'
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
					# Respond to server command
					server_response(plain_text)
				sys.stdout.flush()     

			else :
				# User entered a message
				# Encrypt messages with the session key if the message is for the server
				msg = sys.stdin.readline()

				client_commands(msg, symmetric, s)
				
				sys.stdout.flush() 


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

