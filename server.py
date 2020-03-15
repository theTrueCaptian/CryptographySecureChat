from socket import *
import thread
import signal
import pickle
import json
import re
from securitymodule import *
from dropbox_client import *
from client_listener import *

BUFF = 1024
HOST = '127.0.0.1'
PORT = 8900
MAX_CLIENTS = 10
CONNECTION_LIST = []
block_list = []
TEMP_FOLDER = os.getcwd()+'/server_temp/'

# List of users and passwords
Users = [ 
	('Alice', 'maeda'), 
	('Bob', 'maeda'), 
	('Eve', 'evil')
]

# List of (filename, list of allowed users, unique file key)
ACL = []

def close_handler(signum, frame):
	# This is called when the terminal session is closed
	serversocket.close()
	pass

def find_user(username, password):
	for person in Users:
		if person[0] == username and person[1] == password:
			return person
	return None
'''
def get_publickey(username):
	for (person, key) in public_keys:
		if person == username:
			return key
	return None
'''
def is_logged_on(username):
	for loggedon in CONNECTION_LIST:
		if loggedon['name'] == username:
			print username + ' logged on'
			return True
	return False

def get_users_to_string():
	str_users = 'Users: \n'
	for user in Users:
		str_users = str_users + '\t' + user[0] + ' \n'
	return str_users

#def get_user_connection():

def remove_user(username):
	for loggedon in CONNECTION_LIST:
		if loggedon['name'] == username:
			CONNECTION_LIST.remove(loggedon)
			return

'''
	Return username if the user is authenicated, given the decrypted message from the client
'''
def authenticate_user(auth_decrypted):
	print "auth_decrypted:" + str(auth_decrypted)
	if auth_decrypted == None:	#Corrupted
		clientsocket.close()
	split = auth_decrypted.split(';password=')
	username = split[0]
	password = split[1].rsplit(';', 1)[0]		#Remove the padding
	if find_user(username, password) is None or is_logged_on(username):  # (str(username), str(password)) not in Users:
		return None

	return username


		
def encrypt_file(filename):
	contents = open(filename, 'r').read()
	encrypted_content = contents
	
class ClientListener(object):
	def __init__(self):
		self.username = None

	def encrypt_file(self, full_filename, sym_security_module, unique_file_key):
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
	'''
	Inputs:
		- command is the string message given from the user
		- sym_security_module is the symmetric encryption module, SymmetricEncryption
		- dbx_inst is a dropbox instance
	'''
	def server_command_response(self, socket, command, sym_security_module, dbx_inst):
		print '|'+command+'|'	
		
		'''
		elif command.startswith('/publickey'):
			# Get public key of the user
			match_obj = re.match(r'\/publickey\s*(\S*)\s*', command)
			if match_obj:
				user = match_obj.group(1)
				key = get_publickey(user)
				if key != None:
					encrypted_message = pickle.dumps(sym_security_module.send_symmetric_encryption('/publickey '+key))
					clientsocket.send(encrypted_message)

				else:
					encrypted_message = pickle.dumps(sym_security_module.send_symmetric_encryption('/invalid'))
					clientsocket.send(encrypted_message)
		elif command.startswith('/filename'):
			# Get public key of the user
			match_obj = re.match(r'\/filename\s*(\S*)\s*(\S*)\s*', command)
			if match_obj:
				reciever = match_obj.group(1)
				filename = match_obj.group(2)

				if is_logged_on(reciever):
					conn = get_user_connection(reciever)
					symmod_reciever = conn['encryption_module']
					socket_reciever = conn['socket']

					encrypted_message = pickle.dumps(symmod_reciever.send_symmetric_encryption('/filename '+filename))
					socket_reciever.send(encrypted_message)
		'''
		try:
			
			if command.startswith('/upload'):
				# /upload <metadata>, where metadata = {'filename', 'filecontent'}
				match_obj = re.match( r'\/upload (.+)', command)

				if match_obj:
					metadata_jsondump = match_obj.group(1)
					
					# Load the metadata with json
					received_metadata = json.loads(metadata_jsondump)
					filename = received_metadata['filename']

					metadata = received_metadata
					metadata['creator'] = self.username

					# Encrypt with unique file key
					unique_file_key = base64.b16encode(os.urandom(16))
					
					# Encrypt the json dump with the unique file key
					metadata_encrypted = SymmetricEncryption(unique_file_key).send_symmetric_encryption(metadata_jsondump)
					encrypted_filename = SymmetricEncryption(unique_file_key).send_symmetric_encryption(filename)
					
					# Temporary filename on server 
					tempfile = TEMP_FOLDER+encrypted_filename[0]
					print 'tempfile '+ tempfile
					# Write out the encrypted metadata to a file on server
					target = open(tempfile, 'w')
					target.write(pickle.dumps(metadata_encrypted))
					target.close()

					# Keep info in ACL
					ACL.append((encrypted_filename, [self.username], unique_file_key))
					
					# Upload to Dropbox 
					upload_result = upload_file(tempfile, '/'+encrypted_filename[0], dbx_inst)

					# Inform user of result
					encrypted_message = sym_security_module.send_symmetric_encryption(upload_result)
					sym_security_module.send_message(socket, encrypted_message)
			
		except IOError as e:
			encrypted_message = sym_security_module.send_symmetric_encryption('Can\'t find the file. Please send a valid file!')
			sym_security_module.send_message(socket, encrypted_message)
			
	'''
		A separate thread spawns and runs client_handler() when a client runs. 
	'''
	def client_handler(self, clientsocket, addr):
		# Create a dropbox instance
		dbx_inst = create_dbx_inst()

		# Establish session key via RSA
		# Instantiate symmetric encryption security module
		session_key = RSAKeyExchange(clientsocket).server_rsa_session_key(SERVER_ADDR, addr)
		symmetric = SymmetricEncryption(session_key)

		# Authenticate the user. Decrypt with the session_key
		raw_data = symmetric.recieve_message(clientsocket)
		auth_decrypted = symmetric.receive_symmetric_decryption(raw_data)
		username = authenticate_user(auth_decrypted)
		self.username = username
		if username == None:
			print 'Client ' + str(clientsocket) + ' is not authorized'
			clientsocket.close()
			return

		CONNECTION_LIST.append({'name': username, 'socket':clientsocket, 'encryption_module':symmetric})

		# Send client information on the number
		encrypted_message = symmetric.send_symmetric_encryption('Your address>' + str(addr))
		symmetric.send_message(clientsocket, encrypted_message)
		print "Connected " + username + " from: " + str(addr)

		# Listen for data from client
		while 1:
			raw_data = symmetric.recieve_message(clientsocket)
			if not raw_data or raw_data == None:
				break
			server_command = symmetric.receive_symmetric_decryption(raw_data)

			if server_command != None:
				# Respond to user
				self.server_command_response(clientsocket, server_command, symmetric, dbx_inst)
			else:
				break	

		remove_user(username)
		clientsocket.close()

	


'''
	Safely close sockets when ctrl+c happens
	Otherwise this error would happen: 
 		http://stackoverflow.com/questions/19071512/socket-error-errno-48-address-already-in-use
	run> ps -fA | grep python
	kill <2nd num, proc num>
'''
signal.signal( signal.SIGHUP, close_handler )

'''
	Setup server socket
	Add server socket to the list of readable connections to CONNECTION_LIST
'''
SERVER_ADDR 	= (HOST, PORT)
serversocket 	= socket(AF_INET, SOCK_STREAM)
serversocket.bind(SERVER_ADDR)
serversocket.listen(MAX_CLIENTS) 

CONNECTION_LIST.append({'name':'SERVER', 'socket':serversocket})
print "Listening at " + str(HOST) + ":" + str(PORT)

'''
	Continuously listen for incoming clients and then pass the handler to client_handler()
'''
while 1:
	clientsocket, addr = serversocket.accept()
	thread.start_new_thread(ClientListener().client_handler, (clientsocket, addr))


serversocket.close()