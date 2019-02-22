# PSC-Syslog-Connector-OSS
Syslog connector for Carbon Black PSC

## Description
This application gets Alerts from Carbon Black PSC and send them to your syslog server.  
This application only supports CBD Alerts. ThreatHunter is not supported yet.

## Support
This application is not official Carbon Black product. Carbon Black doesn't offer any support for this application. Please use it at your own risk.

## Difference between .py and .exe
*.exe* was build by pyinstaller with the following command. 
```
pyinstaller PSC_Syslog_Connector.py --onefile
```
Both of them have the same feature.

## System Requirements
* Python 3.6.3+ (When you choose .py version)

## Usage
1. Save *PSC_Syslog_Connector.py or .exe* and *config.ini* in the same directory.  
2. Modify *config.ini*.  
3. Run *PSC_Syslog_Connector.py or .exe*.  

