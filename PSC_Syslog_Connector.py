import sys
import urllib.request
import json 
import os
import argparse
import configparser
import pathlib
import logging
from logging import handlers, StreamHandler
from collections import OrderedDict
from urllib.parse import urljoin
from datetime import datetime
from sys import exit
#from subprocess import STDOUT

CONFIG_FILENAME = 'config.ini'
CONFIG_SECTION_GENERAL = 'general'
CONFIG_SECTION_CBD1 = 'cbdefense1'
CONFIG_SECTION_CBD2 = 'cbdefense2'
CONFIG_SECTION_LOGS = 'connector_log'
CONFIG_LABEL_VENDOR = 'vendor'
CONFIG_LABEL_PRODUCT = 'product'
CONFIG_LABEL_DEV_VER = 'dev_version'
CONFIG_LABEL_LOGFILE = 'log_file'
CONFIG_LABEL_LOGLEVEL = 'log_level'
CONFIG_LABEL_OVERWRITE = 'log_overwrite'
CONFIG_LABEL_SERVERURL = 'server_url'
CONFIG_LABEL_APIKEY = 'api_key'
CONFIG_LABEL_CNNCTRID = 'connector_id'
CONFIG_LABEL_CNNCTRNAME = 'connector_name'
#
LOG_LEVEL_DEBUG = 'debug'
LOG_LEVEL_INFO = 'info'
LOG_LEVEL_WARN = 'warn'
LOG_LEVEL_ERROR = 'error'
LOG_LEVEL_CRITICAL = 'critical'
#
LOG_STDOUT = 'STDOUT'
LOG_OPENMODE = 'a+'
LOG_OVERWRITE = 'w+'
#
DEFAULT_VENDOR = 'CBJ'
DEFAULT_PRODUCT = 'PSC_Syslog_Connector_oss'
DEFAULT_DEV_VER = '1.0'

##############################################################################
# Classes
class PSCAPI:
	path_notification = '/integrationServices/v3/notification'

	def __init__(self, server, api_key, con_id):
		self.server = server
		self.api_token = api_key + '/' + con_id

	def getNotification(self):
		url = urljoin(self.server, self.path_notification)
		return self._get(url)

	def _get(self, url):
		req = urllib.request.Request(url)
		req.add_header('X-Auth-Token', self.api_token)    # IMDL: multiple headder

		try:
			with urllib.request.urlopen(req) as res:
				body = res.read()
			return 'success', body.decode('utf-8')
		except urllib.error.HTTPError as err:
			return 'HTTPError', str(err.code)
		except urllib.error.URLError as err:
			return 'URLError', str(err.reason)


class PSCJsonAlert:
	def __init__(self, json_txt, connector_name):
		self.connector_name = connector_name
		self.output_str_list = []
		_json_txt = json_txt.replace('\n','') #Response body has '\n'. Getting error if it is not removed.
		json_dict = json.loads(_json_txt)
		self._mkOutList(json_dict)


	def _mkOutList(self, json_dict):
		for per_alert_dict in json_dict['notifications']: #If there is no alert, this foreach finishs without loop. 
			if 'threatInfo' in per_alert_dict:
				output_str = self._mkPerAltStr(per_alert_dict)
				self.output_str_list.append(output_str)
			if 'policyAction' in per_alert_dict:
				output_str = self._mkPerAltStr(per_alert_dict)
				self.output_str_list.append(output_str)


	def _mkPerAltStr(self, per_alert_dict):
		_output = OrderedDict()
		#fixed strings might change in a future release.
		_output['source'] = self.connector_name
		_output['version']= 'CEF:0'
		_output['vendor'] = vendor
		_output['product'] = product
		_output['dev_version'] = dev_version
		_output['signature'] = 'Active_Threat' # "Signature" is always "Active_Threat".
		if 'threatInfo' in per_alert_dict:
			_output['name'] = per_alert_dict['threatInfo']['summary']
			_output['severity'] = per_alert_dict['threatInfo']['score']
			_output['extention'] = self._mkAltExtension(per_alert_dict)
		if 'policyAction' in per_alert_dict:
			_output['name'] = per_alert_dict['eventDescription'].strip()
			_output['severity'] = '1'
			_output['extention'] = self._mkAltPolicyAction(per_alert_dict)

		_output_str = ''
		for v in _output.values():
			_output_str += str(v)
			_output_str += '|'

		return _output_str[:-1]

	def _mkAltExtension(self, per_alert_dict):
		_extension = OrderedDict()
		eventtime = per_alert_dict['threatInfo']['time'] # Should I use 'eventTime' instead of 'time'?
		date_str = datetime.fromtimestamp(int(eventtime) / 1000)
		_extension['rt'] = '"' + date_str.strftime('%b %d %Y %H:%M:%S') + '"'  # Format = Dec 06 2018 22:04:53
		dev_name = per_alert_dict['deviceInfo']['deviceName']
		if '\\' in dev_name:
			(domain_name, device) = dev_name.split('\\')
			_extension['sntdom'] = domain_name
			_extension['dvchost'] = device
		else:
			_extension['dvchost'] = dev_name
		user_name = per_alert_dict['deviceInfo']['email']
		if '\\' in user_name:
			(domain_name, user) = user_name.split('\\')
			_extension['duser'] = user
		else:
			_extension['duser'] = user_name
		_extension['dvc'] = per_alert_dict['deviceInfo']['internalIpAddress'] 
		_extension['cs3Label'] = '"Link"'
		_extension['cs3'] = '"' + per_alert_dict['url'] + '"'
		_extension['cs4Label'] = '"Threat_ID"'
		_extension['cs4'] = '"' + per_alert_dict['threatInfo']['incidentId'] + '"'
		_extension['act'] = 'Alert'

		_extension_str = ''
		for k, v in _extension.items():
			_extension_str += k + '=' + str(v) + ' '

		return _extension_str[:-1]

	def _mkAltPolicyAction(self, per_alert_dict):
		_extension = OrderedDict()
		eventtime = per_alert_dict['eventTime'] # Should I use 'eventTime' instead of 'time'?
		date_str = datetime.fromtimestamp(int(eventtime) / 1000)
		_extension['rt'] = '"' + date_str.strftime('%b %d %Y %H:%M:%S') + '"'  # Format = Dec 06 2018 22:04:53
		dev_name = per_alert_dict['deviceInfo']['deviceName']
		if '\\' in dev_name:
			(domain_name, device) = dev_name.split('\\')
			_extension['sntdom'] = domain_name
			_extension['dvchost'] = device
		else:
			_extension['dvchost'] = dev_name
		user_name = per_alert_dict['deviceInfo']['email']
		if '\\' in user_name:
			(domain_name, user) = user_name.split('\\')
			_extension['duser'] = user
		else:
			_extension['duser'] = user_name
		_extension['dvc'] = per_alert_dict['deviceInfo']['internalIpAddress'] 
		_extension['cs3Label'] = '"Link"'
		_extension['cs3'] = '"' + per_alert_dict['url'] + '"'
		_extension['act'] = per_alert_dict['policyAction']['action']
		_extension['hash'] = per_alert_dict['policyAction']['sha256Hash']
		_extension['deviceprocessname'] = per_alert_dict['policyAction']['applicationName']

		_extension_str = ''
		for k, v in _extension.items():
			_extension_str += k + '=' + str(v) + ' '

		return _extension_str[:-1]

	def getOutputList(self):
		return self.output_str_list


class SendSyslog:
	def __init__(self, syslog_server_port, facility):
		syslog_server, syslog_port = syslog_server_port.split(':')
		self.my_syslog = logging.getLogger('MySyslog')
		self.my_syslog.setLevel(logging.DEBUG)
		handler = logging.handlers.SysLogHandler(address = (syslog_server,int(syslog_port)), facility = facility)
		formatter = logging.Formatter('%(message)s') 
		handler.setFormatter(formatter)
		self.my_syslog.addHandler(handler)

	def send(self, priority, msg):
		#alert, emerg, notice are not supported in python logging module.
		if priority == LOG_LEVEL_DEBUG:
			self.my_syslog.debug(msg)
		elif priority == LOG_LEVEL_INFO:
			self.my_syslog.info(msg)
		elif priority == LOG_LEVEL_WARN:
			self.my_syslog.warn(msg)
		elif priority == LOG_LEVEL_ERROR:
			self.my_syslog.error(msg)
		elif priority == LOG_LEVEL_CRITICAL:
			self.my_syslog.critical(msg)
		

class LocalLogging:
	_log_disable_flag = False
	_log_format = '%(asctime)s : %(levelname)s : %(message)s'
	_handler = None

	def __init__(self, log_file, level = LOG_LEVEL_INFO, mode = LOG_OPENMODE):
		self.llogger = logging.getLogger('LocalLogging')
		self.open(log_file, level = level, mode = mode)

	def open(self, log_file, level = LOG_LEVEL_INFO, mode = LOG_OPENMODE):
		self._setLoggingLevel(level)
		if not log_file:
			self._log_disable_flag = True
			return
		elif log_file == LOG_STDOUT:
			self._log_disable_flag = False
			self._handler = StreamHandler()
		else:
			self._log_disable_flag = False
			self._handler = logging.FileHandler(log_file, mode, 'utf-8')

		handler_format = logging.Formatter(self._log_format)
		self._handler.setFormatter(handler_format)
		self.llogger.addHandler(self._handler)

	def reopen(self, log_file, level = LOG_LEVEL_INFO, mode = LOG_OPENMODE):
		if self.llogger.hasHandlers():
			self.llogger.removeHandler(self._handler)
		self.open(log_file, level = level, mode = mode)

	def _setLoggingLevel(self, level):
		if level == LOG_LEVEL_DEBUG:
			self.llogger.setLevel(logging.DEBUG)	
		elif level == LOG_LEVEL_INFO:
			self.llogger.setLevel(logging.INFO)	
		elif level == LOG_LEVEL_WARN:
			self.llogger.setLevel(logging.WARN)	
		elif level == LOG_LEVEL_ERROR:
			self.llogger.setLevel(logging.ERROR)	
		elif level == LOG_LEVEL_CRITICAL:
			self.llogger.setLevel(logging.CRITICAL)	
		else:
			self.llogger.setLevel(logging.INFO)	


	def write(self, level, msg):
		if self._log_disable_flag == True:
			return
		if level == LOG_LEVEL_DEBUG:
				self.llogger.debug(msg)
		elif level == LOG_LEVEL_INFO:
				self.llogger.info(msg)
		elif level == LOG_LEVEL_WARN:
				self.llogger.warn(msg)
		elif level == LOG_LEVEL_ERROR:
				self.llogger.error(msg)
		elif level == LOG_LEVEL_CRITICAL:
				self.llogger.critical(msg)
		else:
				self.llogger.info(msg)


##############################################################################
# main()

def read_config(config_file):
	if not os.path.exists(config_file):
		ll.write(LOG_LEVEL_ERROR, "Cannot locate config file: " + config_file)
		sys.exit(-1)
	for encoding in ['UTF-8-SIG', 'UTF-8', 'CP932', 'Shift-JIS', 'EUC-JP']:
		try:
			config.read(config_file, encoding)
			return
		except configparser.NoSectionError:
			ll.write(LOG_LEVEL_ERROR, "Config format error: " + config_file)
			sys.exit(-1)
		except UnicodeDecodeError:
			pass
		except:
			pass
	ll.write(LOG_LEVEL_ERROR, "Config parse error: " + config_file)
	sys.exit(-1)

parser = argparse.ArgumentParser()
parser.add_argument('--config-file', '-c', help="Absolute path to configuration file")
parser.add_argument('--log-file', '-l', help="Log file location")
parser.add_argument('--log-level', '-L', help="Log output level")
parser.add_argument('--log-overwrite', '-W', action='store_true', help="Log overwrite")
args = parser.parse_args()

# Temporary setup logging output
if args.log_overwrite:
	log_overwrite = LOG_OVERWRITE
else:
	log_overwrite = LOG_OPENMODE
if args.log_file and args.log_level:
	ll = LocalLogging(args.log_file, level = args.log_level)
elif args.log_file:
	ll = LocalLogging(args.log_file)
elif args.log_level:
	ll = LocalLogging(LOG_STDOUT, level = args.log_level)
else:
	ll = LocalLogging(LOG_STDOUT)

# Handle config file parsing
config = configparser.ConfigParser()
if args.config_file:
	read_config(args.config_file)
else:
	path = os.path.dirname(os.path.abspath(sys.argv[0])) + os.sep + CONFIG_FILENAME
	if os.path.exists(path):
		read_config(path)
	else:
		read_config(CONFIG_FILENAME)

# Setup logging based on config paramters
if args.log_overwrite:
	True
elif config.has_option(CONFIG_SECTION_LOGS, CONFIG_LABEL_OVERWRITE):
	if config.get(CONFIG_SECTION_LOGS, CONFIG_LABEL_OVERWRITE).lower() == 'true':
		log_overwrite = LOG_OVERWRITE
if args.log_file and args.log_level:
	# Already setup
	True
elif args.log_file:
	if config.has_option(CONFIG_SECTION_LOGS, CONFIG_LABEL_LOGLEVEL):
		ll.reopen(args.log_file, level = config.get(CONFIG_SECTION_LOGS, CONFIG_LABEL_LOGLEVEL), mode = log_overwrite)
	else:
		ll.reopen(args.log_file, mode = log_overwrite)
else:
	if config.has_option(CONFIG_SECTION_LOGS, CONFIG_LABEL_LOGFILE):
		path = config.get(CONFIG_SECTION_LOGS, CONFIG_LABEL_LOGFILE)
		if path and path != LOG_STDOUT and not pathlib.Path(path).is_absolute():
			path = os.path.dirname(os.path.abspath(sys.argv[0])) + os.sep + path
	else:
		path = None
	if args.log_level:
		ll.reopen(path, level = args.log_level, mode = log_overwrite)
	elif config.has_option(CONFIG_SECTION_LOGS, CONFIG_LABEL_LOGLEVEL):
		ll.reopen(path, level = config.get(CONFIG_SECTION_LOGS, CONFIG_LABEL_LOGLEVEL), mode = log_overwrite)
	else:
		ll.reopen(path, mode = log_overwrite)

# Allow vendor/product setting to be overwritten.
if config.has_option(CONFIG_SECTION_GENERAL, CONFIG_LABEL_VENDOR):
	vendor = config.get(CONFIG_SECTION_GENERAL, CONFIG_LABEL_VENDOR)
	ll.write(LOG_LEVEL_DEBUG, 'Using Vendor:' + vendor)
else:
	vendor = DEFAULT_VENDOR
if config.has_option(CONFIG_SECTION_GENERAL, CONFIG_LABEL_PRODUCT):
	product = config.get(CONFIG_SECTION_GENERAL, CONFIG_LABEL_PRODUCT)
	ll.write(LOG_LEVEL_DEBUG, 'Using Product:' + product)
else:
	dev_version = DEFAULT_PRODUCT
if config.has_option(CONFIG_SECTION_GENERAL, CONFIG_LABEL_DEV_VER):
	dev_version = config.get(CONFIG_SECTION_GENERAL, CONFIG_LABEL_DEV_VER)
	ll.write(LOG_LEVEL_DEBUG, 'Using Dev_version:' + dev_version)
else:
	dev_version = DEFAULT_DEV_VER

# Start processing alerts
ll.write(LOG_LEVEL_INFO,'Start')

# Get Alert from PSC
ll.write(LOG_LEVEL_DEBUG, 'Getting json started.')
papi = PSCAPI(config.get(CONFIG_SECTION_CBD1, CONFIG_LABEL_SERVERURL), config.get(CONFIG_SECTION_CBD1, CONFIG_LABEL_APIKEY), config.get(CONFIG_SECTION_CBD1, CONFIG_LABEL_CNNCTRID))
http_stat, resp_body = papi.getNotification()
del papi
if http_stat != 'success':
	ll.write(LOG_LEVEL_DEBUG, http_stat + ':' + resp_body)
	sys.exit(1)
	
ll.write(LOG_LEVEL_DEBUG, resp_body)
ll.write(LOG_LEVEL_DEBUG, 'Getting json finished.')

# Parse response body
pja = PSCJsonAlert(resp_body, config.get(CONFIG_SECTION_CBD1, CONFIG_LABEL_CNNCTRNAME))
output_list = pja.getOutputList() #Get each output str in list format.

alt_cnt = len(output_list)
ll.write(LOG_LEVEL_INFO, 'Alert count:' + str(alt_cnt))

if not alt_cnt:
	ll.write(LOG_LEVEL_INFO, 'Finished.')
	sys.exit(0)

#Send syslog
ll.write(LOG_LEVEL_DEBUG, 'Sending syslog started.')
ss = SendSyslog(config.get(CONFIG_SECTION_GENERAL, 'udp_out'), config.get(CONFIG_SECTION_GENERAL, 'facility'))

for msg in output_list:
	ss.send(config.get(CONFIG_SECTION_GENERAL, 'priority'), msg)
	ll.write(LOG_LEVEL_DEBUG, 'Send: ' + msg)

ll.write(LOG_LEVEL_INFO, 'Finished.')
sys.exit(0)
