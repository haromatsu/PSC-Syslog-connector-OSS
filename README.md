# PSC-Syslog-Connector-OSS
Syslog connector for Carbon Black PSC

## Description
This application gets Alerts from Carbon Black PSC and send them to your syslog server.  
This application only supports CBD Alerts. ThreatHunter is not supported yet.

## Support
This application is not official Carbon Black product. Carbon Black doesn't offer any support for this application. Please use it at your own risk.

## Difference between .py and .exe
They have the same feature. *.exe* was build by pyinstaller with the following command.  
```
pyinstaller PSC_Syslog_Connector.py --onefile
```

## System Requirements
* Python 3.6.3+  

## Usage
1. Save *PSC_Syslog_Connector.py* and *config.ini* in the same directory.  
2. Modify *config.ini*.  
3. Run *PSC_Syslog_Connector.py*.  

