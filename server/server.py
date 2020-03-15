from socket import *
import thread
import signal
import pickle
import json
import re
from securitymodule import *
from dropbox_client import *

BUFF = 1024
HOST = '127.0.0.1'
PORT = 8001
MAX_CLIENTS = 10
CONNECTION_LIST = []
block_list = []
TEMP_FOLDER = 'server_temp/' #os.getcwd()+

# ACL file name
ACL_file = 'ACL'

# key to encrypte the ACL file
ACL_key = 'uA4UmPfugplECGoo6jQOuQ=='

# List of users and passwords
Users = [ 
	('Alice', 'maeda'), 
	('Bob', 'maeda'), 
	('Eve', 'evil')
]

# List of (filename, encrypted filename, [list of users], unique file key)
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

def is_user_exist(username):
	for person in Users:
		if person[0] == username:
			return True
	return False

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

def remove_user(username):
	for loggedon in CONNECTION_LIST:
		if loggedon['name'] == username:
			CONNECTION_LIST.remove(loggedon)
			return

# Create a new file in the ACL
def new_file_acl(filename, encrypted_filename, userlist, unique_file_key):
	ACL.append((filename, encrypted_filename, userlist, unique_file_key))

# Add a user to the file
def add_user_file_acl(filename, user):
	for filename_acl in ACL:
		if filename_acl[0] == filename:
			if user not in filename_acl[2]:
				filename_acl[2].append(user)
			return

# Return the list of files accessible to the user
def get_files_acl(username):
	files = []
	for filename_acl in ACL:
		if username in filename_acl[2]:
			files.append(filename_acl[0])
	return files

# Return the tuple related to the filename
def get_info_acl_by_filename(filename):
	files = []
	for filename_acl in ACL:
		if filename_acl[0] == filename:
			return filename_acl
	return None

# Check whether this file has already been uploaded
def is_file_exist(filename):
	for filename_acl in ACL:
		if filename in filename_acl[0]:
			return True
	return False

# Check whether user has the privilege 
def user_has_privilege(filename, username):
	for filename_acl in ACL:
		if filename in filename_acl[0] and username in filename_acl[2]:
			return True
	return False

# Delete the one user
def delete_user_file_acl(filename, delete_user):
	for filename_acl in ACL:
		if filename_acl[0] == filename:
			if delete_user in filename_acl[2]:
				del filename_acl[2][filename_acl[2].index(delete_user)]
			return

# Delete acl file entry
def delete_acl_entry(filename):
	for filename_acl in ACL:
		if filename_acl[0] == filename:
			encrypted_file_name = filename_acl[1]
			del ACL[ACL.index(filename_acl)]
			return encrypted_file_name

def read_ACL_file(ACL_file):
	try:
		#read ACL file
	    f = open(ACL_file, 'r+')
	    ACL_encrypted = pickle.load(f)
	    list1 = json.loads(SymmetricEncryption(ACL_key).receive_symmetric_decryption(ACL_encrypted))
	    if list1:
		    for i in list1:
		    	if not is_file_exist(i[0]):
		    		ACL.append(i)
	    f.close()

	except IOError:
	    # If not exists, create the file
	    f = open(ACL_file, 'w')
	    f.close()

def write_ACL_file(ACL_file):
	f = open(ACL_file, 'w')
	ACL_encrypted = SymmetricEncryption(ACL_key).send_symmetric_encryption(json.dumps(ACL))
	f.write(pickle.dumps(ACL_encrypted))
	f.close()

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


class ClientListener(object):
	def __init__(self):
		self.username = None

	'''
	Inputs:
		- command is the string message given from the user
		- sym_security_module is the symmetric encryption module, SymmetricEncryption
		- dbx_inst is a dropbox instance
	'''
	def server_command_response(self, socket, command, sym_security_module, dbx_inst):
		
		# read the local ACL file
		read_ACL_file(ACL_file)

		try:
			if command.startswith('/upload'):
				# /upload <metadata>, where metadata = {'filename', 'filecontent'}
				match_obj = re.match( r'\/upload (.+)', command)

				if match_obj:

					# Transformation of the metadata: socket --> rawdata --> json --> file --> encrypt w/ unique file key --> pickle  --> dropbox
					metadata_jsondump = match_obj.group(1)
					
					# Load the metadata with json
					received_metadata = json.loads(metadata_jsondump)
					filename = received_metadata['filename']
					print filename

					if is_file_exist(filename):
						encrypted_message = sym_security_module.send_symmetric_encryption('File '+filename+' has already existed!')
						sym_security_module.send_message(socket, encrypted_message)
						return

					metadata = received_metadata
					metadata['creator'] = self.username

					# Encrypt with unique file key
					unique_file_key = base64.b16encode(os.urandom(16))
					
					# Encrypt the json dump with the unique file key
					metadata_encrypted = SymmetricEncryption(unique_file_key).send_symmetric_encryption(metadata_jsondump)
					encrypted_filename = SymmetricEncryption(unique_file_key).send_symmetric_encryption(filename)[0]
					
					# Temporary filename on server 
					tempfile = TEMP_FOLDER+encrypted_filename
					print 'tempfile '+ tempfile
					# Write out the encrypted metadata to a file on server
					target = open(tempfile, 'w')
					target.write(pickle.dumps(metadata_encrypted))
					target.close()

					# Keep info in ACL: (filename, encrypted filename, [list of users], unique file key)
					new_file_acl(filename, encrypted_filename, [self.username], unique_file_key)

					# Upload to Dropbox 
					upload_result = upload_file(tempfile, '/'+encrypted_filename, dbx_inst)

					# Inform user of result
					encrypted_message = sym_security_module.send_symmetric_encryption(upload_result)
					sym_security_module.send_message(socket, encrypted_message)
					print ACL
			elif command.startswith('/addusers'):
				# /addusers <filename> <a user>
				match_obj = re.match( r'\/addusers (\S+) (\S+)', command)

				if match_obj:
					filename = match_obj.group(1)
					new_user = match_obj.group(2)

					if not is_user_exist(new_user):
						encrypted_message = sym_security_module.send_symmetric_encryption('User '+new_user+' doesn\'t exist!')
						sym_security_module.send_message(socket, encrypted_message)
						return

					if not is_file_exist(filename):
						encrypted_message = sym_security_module.send_symmetric_encryption('File '+filename+' doesn\'t exist!')
						sym_security_module.send_message(socket, encrypted_message)
						return

					if not user_has_privilege(filename, self.username):
						encrypted_message = sym_security_module.send_symmetric_encryption('You do not have privilege to add users!')
						sym_security_module.send_message(socket, encrypted_message)
						return

					add_user_file_acl(filename, new_user)
					
					print ACL

					encrypted_message = sym_security_module.send_symmetric_encryption('Add user ' + new_user +' successfully')
					sym_security_module.send_message(socket, encrypted_message)

				else:
					encrypted_message = sym_security_module.send_symmetric_encryption('Command '+command+' isn\'t valid!')
					sym_security_module.send_message(socket, encrypted_message)

			elif command =='/list':
				# List filenames
				file_list = get_files_acl(self.username)
				files_to_string = 'Files: ' 
				for filename in file_list:
					files_to_string += filename + ' '
				encrypted_message = sym_security_module.send_symmetric_encryption(files_to_string)
				sym_security_module.send_message(socket, encrypted_message)

			elif command.startswith('/download'):
				# /download <filename>
				match_obj = re.match( r'\/download\s+(\S+)', command)
				if match_obj:
					filename = match_obj.group(1)
					file_info = get_info_acl_by_filename(filename)
					if file_info != None:

						if not user_has_privilege(filename, self.username):
							encrypted_message = sym_security_module.send_symmetric_encryption('You do not have privilege to download the file!')
							sym_security_module.send_message(socket, encrypted_message)
							return

						# Retrieve the file: Dropbox --> Server file --> Read --> Pickle --> decrypt --> Json --> Actual file 
						# Download the file
						dropbox_filename = '/'+file_info[1]
						local_filename = TEMP_FOLDER + file_info[1]
						download_file(local_filename, dropbox_filename, dbx_inst)

						unique_file_key = str(file_info[3])

						# Read the file and decrypt it with the unique file key
						filecontent = ''
						with open(local_filename, 'r') as f:
							filecontent = f.read()
						f.close()

						# Send the metadata to the server.  
						metadata_encrypted = pickle.loads(filecontent)
						metadata = json.loads(SymmetricEncryption(unique_file_key).receive_symmetric_decryption(metadata_encrypted))
						metadata_jsondump = json.dumps(metadata)
						encrypted_message = sym_security_module.send_symmetric_encryption('/download '+metadata_jsondump)
						sym_security_module.send_message(socket, encrypted_message)

					else:
						encrypted_message = sym_security_module.send_symmetric_encryption('File '+filename+' do not exist!')
						sym_security_module.send_message(socket, encrypted_message)

			elif command.startswith('/deleteusers'):
				# /addusers <filename> <a user>
				match_obj = re.match( r'\/deleteusers (\S+) (\S+)', command)

				if match_obj:
					filename = match_obj.group(1)
					delete_user = match_obj.group(2)

					if not is_user_exist(delete_user):
						encrypted_message = sym_security_module.send_symmetric_encryption('User '+delete_user+' doesn\'t exist!')
						sym_security_module.send_message(socket, encrypted_message)
						return

					if not is_file_exist(filename):
						encrypted_message = sym_security_module.send_symmetric_encryption('File '+filename+' doesn\'t exist!')
						sym_security_module.send_message(socket, encrypted_message)
						return

					if not user_has_privilege(filename, self.username):
						encrypted_message = sym_security_module.send_symmetric_encryption('You do not have privilege to delete users!')
						sym_security_module.send_message(socket, encrypted_message)
						return

					delete_user_file_acl(filename, delete_user)
					
					print ACL

					encrypted_message = sym_security_module.send_symmetric_encryption('Delete user ' + delete_user +' successfully')
					sym_security_module.send_message(socket, encrypted_message)

				else:
					encrypted_message = sym_security_module.send_symmetric_encryption('Command '+command+' isn\'t valid!')
					sym_security_module.send_message(socket, encrypted_message)

			elif command.startswith('/deletefile'):
				# /delete <filename>
				match_obj = re.match( r'\/deletefile\s+(\S+)', command)
				if match_obj:
					filename = match_obj.group(1)

					if not is_file_exist(filename):
						encrypted_message = sym_security_module.send_symmetric_encryption('File '+filename+' doesn\'t exist!')
						sym_security_module.send_message(socket, encrypted_message)
						return

					if not user_has_privilege(filename, self.username):
						encrypted_message = sym_security_module.send_symmetric_encryption('You do not have privilege to delete users!')
						sym_security_module.send_message(socket, encrypted_message)
						return

					#delete ACL entry
					encrypted_file_name = delete_acl_entry(filename)

					#delete file in the dropbox
					delete_file(encrypted_file_name, dbx_inst)
					
					print ACL

					encrypted_message = sym_security_module.send_symmetric_encryption('Delete file '+filename+' successfully')
					sym_security_module.send_message(socket, encrypted_message)

				else:
					encrypted_message = sym_security_module.send_symmetric_encryption('Command '+command+' isn\'t valid!')
					sym_security_module.send_message(socket, encrypted_message)

		except IOError as e:
			encrypted_message = sym_security_module.send_symmetric_encryption('File error!')
			sym_security_module.send_message(socket, encrypted_message)

		# Write to the local ACL file
		write_ACL_file(ACL_file)
		
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