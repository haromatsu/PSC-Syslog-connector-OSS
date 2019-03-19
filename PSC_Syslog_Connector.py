import urllib.request
import json 
import configparser
import logging
from logging import handlers, StreamHandler
from collections import OrderedDict
from urllib.parse import urljoin
from datetime import datetime
from sys import exit



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
			output_str = self._mkPerAltStr(per_alert_dict)
			self.output_str_list.append(output_str)


	def _mkPerAltStr(self, per_alert_dict):
		_output = OrderedDict()
		#fixed strings might change in a future release.
		_output['source'] = self.connector_name
		_output['version']= 'CEF:0'
		_output['vendor'] = vendor
		_output['product'] = product
		_output['dev_version'] = '1.0'
		_output['signature'] = 'Active_Threat' # "Signature" is always "Active_Threat".
		_output['name'] = per_alert_dict['threatInfo']['summary']
		_output['severity'] = per_alert_dict['threatInfo']['score']
		_output['extention'] = self._mkAltExtension(per_alert_dict)

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
		_extension['dvchost'] = per_alert_dict['deviceInfo']['deviceName'] 
		_extension['duser'] = per_alert_dict['deviceInfo']['email'] 
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

	def getOutputList(self):
		return self.output_str_list


class SendSyslog:
	def __init__(self, syslog_server_port, facility):
		syslog_server, syslog_port = syslog_server_port.split(':')
		self.my_syslog = logging.getLogger('MySyslog')
		self.my_syslog.setLevel(logging.DEBUG) #IMCL.
		handler = logging.handlers.SysLogHandler(address = (syslog_server,int(syslog_port)), facility=facility) #IMCL facility
		formatter = logging.Formatter('%(message)s') 
		handler.setFormatter(formatter)
		self.my_syslog.addHandler(handler)

	def send(self, priority, msg):
		#alert, emerg, notice are not supported in python logging module.
		if priority == 'debug':
				self.my_syslog.debug(msg)
		elif priority == 'info':
				self.my_syslog.info(msg)
		elif priority == 'warn':
				self.my_syslog.warn(msg)
		elif priority == 'error':
				self.my_syslog.error(msg)
		elif priority == 'critical':
				self.my_syslog.critical(msg)
		

class LocalLogging:
	_log_disable_flag = False
	_log_format = '%(asctime)s : %(levelname)s : %(message)s'

	def __init__(self, log_file, level):
		self.llogger = logging.getLogger('LocalLogging')
#		self.llogger.setLevel(logging.INFO)	
		self._setLoggingLevel(level)

		if not log_file:
			self._log_disable_flag = True
			return
		elif log_file == 'STDOUT':
			file_handler = StreamHandler()
		else:
#			file_handler = logging.FileHandler(filename=log_file)
			file_handler = logging.FileHandler(log_file, 'a', 'utf-8')


		file_handler.setLevel(logging.DEBUG)
		handler_format = logging.Formatter(self._log_format)
		file_handler.setFormatter(handler_format)
		self.llogger.addHandler(file_handler)


	def _setLoggingLevel(self, level):
		if level == 'debug':
				self.llogger.setLevel(logging.DEBUG)	
		elif level == 'info':
				self.llogger.setLevel(logging.INFO)	
		elif level == 'warn':
				self.llogger.setLevel(logging.WARN)	
		elif level == 'error':
				self.llogger.setLevel(logging.ERROR)	
		elif level == 'critical':
				self.llogger.setLevel(logging.CRITICAL)	


	def write(self, level, msg):
		if self._log_disable_flag == True:
			return

		if level == 'debug':
				self.llogger.debug(msg)
		elif level == 'info':
				self.llogger.info(msg)
		elif level == 'warn':
				self.llogger.warn(msg)
		elif level == 'error':
				self.llogger.error(msg)
		elif level == 'critical':
				self.llogger.critical(msg)



##############################################################################
# main()
config = configparser.ConfigParser()
config.read('config.ini', 'UTF-8')

# Allow vendor/product setting to be overwritten.
if config.has_option('general', 'vendor'):
	vendor = config.get('general', 'vendor')
else:
	vendor = 'CBJ'
if config.has_option('general', 'product'):
	product = config.get('general', 'product')
else:
	product = 'PSC_Syslog_Connector_oss'

ll = LocalLogging(config.get('connector_log', 'log_file'), config.get('connector_log', 'log_level'))

ll.write('info','Start')

# Get Alert from PSC
ll.write('debug', 'Getting json started.')
papi = PSCAPI(config.get('cbdefense1', 'server_url'), config.get('cbdefense1', 'api_key'), config.get('cbdefense1', 'connector_id'))
http_stat, resp_body = papi.getNotification()
del papi
if http_stat != 'success':
	ll.write('debug', http_stat + ':' + resp_body)
	exit()
	
ll.write('debug', resp_body)
ll.write('debug', 'Getting json finished.')

# Parse response body
pja = PSCJsonAlert(resp_body, config.get('cbdefense1', 'connector_name'))
output_list = pja.getOutputList() #Get each output str in list format.

alt_cnt = len(output_list)
ll.write('info', 'Alert count:' + str(alt_cnt))

if not alt_cnt:
	ll.write('info', 'Finished.')
	exit()

#Send syslog
ll.write('debug', 'Sending syslog started.')
ss = SendSyslog(config.get('general', 'udp_out'), config.get('general', 'facility'))

for msg in output_list:
	ss.send(config.get('general', 'priority'), msg)

ll.write('info', 'Finished.')


