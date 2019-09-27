# PSC-Syslog-Connector-OSS
Syslog connector for Carbon Black PSC

## Description
This application gets Alerts from Carbon Black PSC and send them to your syslog server.  
This application supports CB Defense or CB ThreatHunter Alerts.

## Support
This application is not official Carbon Black product. Carbon Black doesn't offer any support for this application.
Cybernet Systems has modified the source code for easier usage, based on source code provided by Carbon Black.
Cybernet Systems does not offer any support for this application.
Please use it at your own risk.

## How To Setup
### System Requirements
* Windows x86-64 environment
	- Windows 7/Windows 10/Windows Server 2019

### Installation
* Using the installer: *PSC_Syslog_Connector_Installer.exe*
1. Download installer *PSC_Syslog_Connector_Installer.exe*
1. Run installer and specify folder for installtion.
1. Confirm following files are available specified folder.
	- *PSC_Syslog_Connector_Installer.exe*
	- *config.ini*
	- *schtasks_setup.bat*

* Using the executable: *PSC_Syslog_Connector.exe*
1. Download following files into same folder:
	- *PSC_Syslog_Connector_Installer.exe*
	- *config.ini*
	- *schtasks_setup.bat*

* Using the python script: *PSC_Syslog_Connector.py*
1. Download following files into same folder:
	- *PSC_Syslog_Connector_Installer.py*
	- *config.ini*
1. Setup Python environment.
	- Python      3.6.3+
	- cbapi       1.4.1+ (Installed with 'pip install cbapi')

### Configuration
1. Setup PSC Console to send alerts through connector:
	- Setup API keys for *SIEM* on [Settings]>[API Keys] Page
	- Setup nortification on [Settings]>[Notifications] Page and select connector created above.
1. Modify *config.ini*.
	- Setup *connector_id* and *api_key* based on PSC Console connector setting.
	- Setup *server_url* for backend server of PSC Console you use.
	- Setup *udp_out* for your syslog server.
1. Run *PSC_Syslog_Connector.py* or *PSC_Syslog_Connector.exe* to confirm correct setup.
1. Setup Task Scheduler to run periodically.
	- Can use *schtasks_setup.bat* with administrator privilege when using *PSC_Syslog_Connector.exe* 


## Building
### Build Requirements
* Python      3.6.3+
* PyInstaller 3.4+
* cbapi       1.4.1+ (Installed with 'pip install cbapi')

### Build Instructions
*PSC_Syslog_Connector.exe* was build by pyinstaller with the following command. 
```
pyinstaller PSC_Syslog_Connector.py --onefile --windowed --icon=CB.ico --version-file=PSC_Syslog_Connector_version.txt
```

When using [Cygwin](https://www.cygwin.com/), following command will produce executable in *build* folder.
```
make -f Makefile.cygwin
```

