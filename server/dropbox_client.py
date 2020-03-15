import dropbox
from dropbox.files import WriteMode, SearchMode
from dropbox.exceptions import ApiError, AuthError

##########################################
# Credntials for the dropbox account:    #
# Email: cs9603.client1@gmail.com        #
# Password:  cs9603_client1              #
#                                        #
# Make sure to download dropbox package: #
# pip install dropbox                    #
##########################################

def create_dbx_inst():
	try:
		access_token = 'vf4CI4jfTZAAAAAAAAAACJJICcSI1NZmTM6IBx0Wsyh5adxxmQSenrpt9MTk_Qhy'
		dbx = dropbox.Dropbox(access_token)
		return dbx
	except AuthError as err:
		print "Dropbox authentication failed."

def list_all_files(dbx_inst):
	files_list = []
	for entry in dbx_inst.files_list_folder('').entries:
		files_list.append(entry.name)
	return files_list
 

def upload_file(file_path, output_filepath, dbx_inst):
	f = open(file_path)
	try:
		#file_name = get_filename_from_path(file_path)
		dbx_inst.files_upload(f, output_filepath, mode=WriteMode('overwrite'))
		return "Upload to Dropbox succeeded."
	except ApiError as err:
		print err
		return "Upload to Dropbox succeeded."

def download_file(local_filename, dropbox_file_name, dbx_inst):
	try:
		dbx_inst.files_download_to_file(local_filename, dropbox_file_name)
		print "download succeeded."
	except ApiError as err:
		print err
		print "download failed."

def get_file_metadata(file_name, dbx_inst):
	return dbx_inst.files_get_metadata('/'+file_name).client_modified

def delete_file(file_name, dbx_inst):
	try:
		dbx_inst.files_delete('/'+file_name)
		print "delete successful."
	except ApiError as err:
		print err
		print "delete failed."

def search_file(file_name, dbx_inst):
	try:
		results = dbx_inst.files_search('', file_name, mode=SearchMode('filename'))
		if file_name in [match.metadata.name for match in results.matches]:
			return True
		else:
			return False
	except ApiError as err:
		print err
		return False

def get_filename_from_path(file_path):
	file_from_path = file_path.split("/")
	return file_from_path[-1]

#dbx_inst = create_dbx_inst()
#upload_file('test.txt', dbx_inst)
#download_file('test.txt', dbx_inst)
#print list_all_files(dbx_inst)
#print get_file_metadata('test.txt', dbx_inst)
#delete_file('test.txt', dbx_inst)
#print search_file('test.txt', dbx_inst)





