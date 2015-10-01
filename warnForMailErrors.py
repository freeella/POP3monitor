#!/usr/local/bin/python2.7
#!/usr/local/bin/python2.7 -O
#!/usr/bin/env python2.7

__doc__ = info = '''
A small script using file .getmail/getmailrc to alert if there are 3 or more mails on the remote POP3 server.

This script can be used as a cron job in order to receive alerts via mail.

Kai Ellinger (c) 2015 - coding@blicke.de
'''

# used modules
import os, sys
import ConfigParser # reading user configuration from .getmail/getmailrc
import argparse     # reading user arguments
import traceback    # printing stack trace
import poplib       # accessing the POP3 account
import logging      # for logging text

# DEBUG
is_debug   = False
# TODO - can't redirect stack trace to log file
#        only printing stack trace when using STDOUT
#        need to fix later
log_to_stdout = True

# Printing stack trace
def print_stack():
	if __debug__:
		'''
		This function is used for debugging only.
		'''
		if log_to_stdout:
			try:
				raise TypeError("NeedStackTrace!")
			except TypeError, err:
				print "-" * 20, "BEGIN: STACKTRACE", "-" * 20
				traceback.print_stack()
				print "-" * 20, "END: STACKTRACE", "-" * 20

# Read command line arguments
def parse_arguments():
	global is_debug, log_to_stdout
	parser = argparse.ArgumentParser(description='Checks for hanging mails')
	parser.add_argument('-v','--version', action='version', version='%(prog)s 1.0.1')
	# if not calling python with -O option
	# ORDER - having parameter INFO and DEBUG sets log level to DEBUG
	parser.add_argument('-I','--INFO', action='store_const', dest='LOGLEVEL', const=logging.INFO, help='log level set to INFO')
	# calling python with -O option disables debug information
	if __debug__:
		parser.add_argument('-D','--DEBUG', action='store_const', dest='LOGLEVEL', const=logging.DEBUG, help='log level set to DEBUG')
	parser.add_argument('-L','--logfile', type=str, dest='LOGFILE', help='sets a file name to log to' )
	parser.add_argument('-C','--config', type=str, dest='CONFIG', default="%s/%s" % ( os.environ['HOME'] , '.getmail/getmailrc' ), help='GETMAIL config file' )
	args = parser.parse_args()

	# setting log format
	# See: https://docs.python.org/2/library/logging.html#logrecord-attributes
	logging_format_string = '%(asctime)s [%(levelname)-7s][%(pathname)s:%(lineno)4d][%(funcName)s] %(message)s'
	# finish setting log level
	if not hasattr(args, 'LOGLEVEL'):
		args.LOGLEVEL = logging.WARNING
	if args.LOGLEVEL == logging.DEBUG:
		is_debug = True
	# log destination selection
	write_to_log = False
	log_file_error_msg = None
	if hasattr(args, 'LOGFILE') and args.LOGFILE is not None:
		# append existing log
		if os.path.isfile( args.LOGFILE ):
			# if existing file is writable; use it
			write_to_log = os.access( args.LOGFILE, os.W_OK )
			if not write_to_log:
				log_file_error_msg = "LOG: File '%s' exists but is not writable! Using STDOUT!" % args.LOGFILE
		# log file does not yet exist
		else:
			log_dir = os.path.dirname( args.LOGFILE )
			# if args.LOGFILE does not contain a directory name
			if '' == log_dir:
				log_dir = '.'
			# check dir permissions
			write_to_log = os.access(log_dir, os.W_OK | os.X_OK)
			if not write_to_log:
				log_file_error_msg = "LOG: Directory '%s' is not writable! Using STDOUT!" % log_dir
	# writing to STDOUT or to file?
	if write_to_log:
		logging.basicConfig(filename=args.LOGFILE, format=logging_format_string, level=args.LOGLEVEL)
		log_to_stdout = False
	else:
		logging.basicConfig(format=logging_format_string, level=args.LOGLEVEL)
		if log_file_error_msg is not None:
			logging.warn(log_file_error_msg)

	# is the config file readable?
	logging.info("CONFIG file: %s" % args.CONFIG )
	if not os.path.isfile(args.CONFIG):
		logging.error("Can NOT access file '%s'!" % args.CONFIG )
		if is_debug: print_stack()
		return None
	return args

# Read GETMAIL config file!
def read_config(config_file):
	pop3_server = pop3_username = pop3_password = None
	config = ConfigParser.ConfigParser()
	config.read( config_file )

	if config.has_section("retriever"):
		if config.has_option("retriever", "type"):
			if "MultidropPOP3SSLRetriever" == config.get("retriever", "type"):
				if config.has_option("retriever", "server"):
					pop3_server = config.get("retriever", "server")
				if config.has_option("retriever", "username"):
					pop3_username = config.get("retriever", "username")
				if config.has_option("retriever", "password"):
					pop3_password = config.get("retriever", "password")
	return (pop3_server, pop3_username, pop3_password)

# Connect to the POP3 server and count messages
def count_waiting_messages(pop3_server, pop3_username, pop3_password):
	if ( pop3_server is not None) and ( pop3_username is not None ) and ( pop3_password is not None ):
		MAIL = poplib.POP3_SSL(pop3_server)
		MAIL.user(pop3_username)
		MAIL.pass_(pop3_password)
		return MAIL.stat()[0]
	else:
		return -11

# MAIN method
def main():
	# checking command line arguments
	args = parse_arguments()
	if args is None:
		return -22
	(pop3_server, pop3_username, pop3_password) = read_config( args.CONFIG )
	message_count = count_waiting_messages(pop3_server, pop3_username, pop3_password)
	if (2 < message_count):
		logging.warn("Server %s has Message Count of (%d)!!!" % ( pop3_server, message_count ) )
	elif (0 <= message_count):
		logging.info("Server %s has Message Count of (%d)!!!" % ( pop3_server, message_count ) )
	if (0 > message_count):
		return message_count


# only call MAIN method if directly called!
if __name__ == '__main__':
	sys.exit(main())

