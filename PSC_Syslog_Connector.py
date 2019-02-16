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
		url = urljoin(server, self.path_notification)
		return self._get(url)

	def _get(self, url):
		req = urllib.request.Request(url)
		req.add_header('X-Auth-Token', self.api_token)    # IMDL: multiple headder

		try:
			with urllib.request.urlopen(req) as res:
				body = res.read()
			return body.decode('utf-8')

		except urllib.error.HTTPError as err:
			exit(str(err.code)) #IMDL Debug log
		except urllib.error.URLError as err:
			exit(str(err.reason)) #IMDL Debug log


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
		_output['vendor'] = 'Carbon Black Japan'
		_output['product'] = 'PSC_Alart_Syslog_Connector_oss'
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
		self.my_syslog.setLevel(logging.DEBUG)
		handler = logging.handlers.SysLogHandler(address = (syslog_server,int(syslog_port)), facility=facility) #IMCL facility
		formatter = logging.Formatter('%(message)s') 
		handler.setFormatter(formatter)
		self.my_syslog.addHandler(handler)

	def send(self, msg, priority):
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
	def __init__(self, filename, level): #IMDL Write log to a file.
		self.llogger = logging.getLogger('LocalLogging')
		self.llogger.setLevel(logging.DEBUG)
		stream_handler = StreamHandler()
		stream_handler.setLevel(logging.DEBUG)
		handler_format = logging.Formatter('%(asctime)s : %(levelname)s : %(message)s')
		stream_handler.setFormatter(handler_format)
		self.llogger.addHandler(stream_handler)

	def write(self, msg):
		self.llogger.info(msg)



##############################################################################
# main()
ll = LocalLogging(1,2)
ll.write('Start')
config = configparser.ConfigParser()
config.read('config.ini', 'UTF-8')
server = config.get('cbdefense1', 'server_url')
api_key = config.get('cbdefense1', 'api_key')
con_id = config.get('cbdefense1', 'connector_id')


# Get Alert from PSC
ll.write('Getting json started.')
papi = PSCAPI(server, api_key, con_id)
resp_body = papi.getNotification()
del papi
ll.write('Getting json finished.')


# Parse response body
connector_name = config.get('cbdefense1', 'connector_name')
pja = PSCJsonAlert(resp_body, connector_name)
output_list = pja.getOutputList() #Get each output str in list format.

alt_cnt = len(output_list)
ll.write('Alert count:' + str(alt_cnt))

if not alt_cnt:
	ll.write('Finished.')
	exit()

#Send syslog
ll.write('Sending syslog started.')
syslog_server_port = config.get('general', 'udp_out')
syslog_facility = config.get('general', 'facility')
syslog_priority = config.get('general', 'priority')
ss = SendSyslog(syslog_server_port, syslog_facility)

for msg in output_list:
	ss.send(msg, syslog_priority)

ll.write('Finished.')


