■概要
PSC-Syslog-Connector-OSSモジュールは、Carbon Black PSC (Predictive Security Cloud)用の
Windows版 Syslogコネクタです。
PSC環境で稼働するソリューションが発信する通知を、Syslog経由で外部システムに通知を行います。
CB Defense検知アラートおよび CB ThreatHunterの Watchlist検知アラートに対応しています。


■サポートについて
本アプリケーションは Carbon Blackがオープンソースとして提供しているアプリケーションに対して、
サイバネットシステムで利便性向上などの改変を行ったアプリケーションです。
Carbon Blackおよびサイバネットシステムでは、本アプリケーションへのサポートは提供しておりません。

This application is not official Carbon Black product. Carbon Black doesn't offer any support for this application.
Cybernet Systems has modified the source code for easier usage, based on source code provided by Carbon Black.
Cybernet Systems does not offer any support for this application.
Please use it at your own risk.

■設定方法
□システム要件
- Windows x86-64 environment
   (Windows 7/Windows 10/Windows Server 2016)

□インストール方法
1. インストールモジュール「PSC_Syslog_Connector_Installer.exe」を実行します。
2. アプリケーションのインストール用フォルダを指定します。
3. インストール用フォルダに以下のファイルが配置されていることを確認します。
　- PSC_Syslog_Connector_Installer.exe
  - config.ini
  - schtasks_setup.bat
  - README.txt    (本ファイル)

□設定方法
1. CB Defenseや CB ThreatHunterの PSCコンソールにてコネクタおよび通知設定を行います。
　- [設定]>[コネクタ]画面にて「SIEM」用コネクタを作成
　- [設定]>[通知]画面にて、作成したコネクタを利用する通知を作成

2. config.iniファイルに設定を行います。
　- PSCコンソールのコネクタ設定従い、connector_id項および api_key項を設定
　- PSCコンソールに合わせてバックエンドサーバ用 server_url項を設定
　- 通知先 Syslogサーバに合わせて udp_out項を設定

3. PSC_Syslog_Connector.exeを実行し、設定通りに動作することを確認します。

4. 管理者権限で schtasks_setup.batを実行し、タスクスケジューラに自動実行を登録します。
　- タスクスケジューラに「PSC Syslog Connector」を登録

