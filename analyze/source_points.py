

class Sources:
# userinput variables
	V_USERINPUT = [
		'$_GET',
		'$_POST',
		'$_COOKIE',
		'$_REQUEST',
		'$_FILES',
		'$_SERVER',
		'$HTTP_GET_VARS',
		'$HTTP_POST_VARS',
		'$HTTP_COOKIE_VARS',  
		'$HTTP_REQUEST_VARS', 
		'$HTTP_POST_FILES',
		'$HTTP_SERVER_VARS',
		'$HTTP_RAW_POST_DATA',
		'$argc',
		'$argv'
	]
	
	V_SERVER_PARAMS = [
		'HTTP_ACCEPT',
		'HTTP_ACCEPT_LANGUAGE',
		'HTTP_ACCEPT_ENCODING',
		'HTTP_ACCEPT_CHARSET',
		'HTTP_CONNECTION',
		'HTTP_HOST',
		'HTTP_KEEP_ALIVE',
		'HTTP_REFERER',
		'HTTP_USER_AGENT',
		'HTTP_X_FORWARDED_FOR',
		# all HTTP_ headers can be tainted
		'PHP_AUTH_DIGEST',
		'PHP_AUTH_USER',
		'PHP_AUTH_PW',
		'AUTH_TYPE',
		'QUERY_STRING',
		'REQUEST_METHOD',
		'REQUEST_URI', # partly urlencoded
		'PATH_INFO',
		'ORIG_PATH_INFO',
		'PATH_TRANSLATED',
		'REMOTE_HOSTNAME',
		'PHP_SELF'
	]
	
# file content as input
	F_FILE_INPUT = [
		'bzread',
		'dio_read',
		'exif_imagetype',
		'exif_read_data',
		'exif_thumbnail',
		'fgets',
		'fgetss',
		'file', 
		'file_get_contents',
		'fread',
		'get_meta_tags',
		'glob',
		'gzread',
		'readdir',
		'read_exif_data',
		'scandir',
		'zip_read'
	]
	
# database content as input
	F_DATABASE_INPUT = [
		'mysql_fetch_array',
		'mysql_fetch_assoc',
		'mysql_fetch_field',
		'mysql_fetch_object',
		'mysql_fetch_row',
		'pg_fetch_all',
		'pg_fetch_array',
		'pg_fetch_assoc',
		'pg_fetch_object',
		'pg_fetch_result',
		'pg_fetch_row',
		'sqlite_fetch_all',
		'sqlite_fetch_array',
		'sqlite_fetch_object',
		'sqlite_fetch_single',
		'sqlite_fetch_string'
	]
	
# other functions as input
	F_OTHER_INPUT = [
		'get_headers',
		'getallheaders',
		'get_browser',
		'getenv',
		'gethostbyaddr',
		'runkit_superglobals',
		'import_request_variables'
	]
	
#	'getenv' and 'apache_getenv' 
# will be automatically added if 'putenv' or 'apache_setenv' with userinput is found
