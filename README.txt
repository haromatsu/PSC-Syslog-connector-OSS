■概要
PSC-Syslog-Connector-OSSモジュールは、Carbon Black社の PSC連携用の Windows版 
Syslogコネクタです。
PSC環境の稼働ソリューションからの通知を、Syslog経由で外部システムに連携します。
CB Defense検知アラート、CB ThreatHunterの Watchlist検知アラートに対応しています。


■サポートについて
本アプリケーションは、Carbon Black社がオープンソースとして提供しているアプリ
ケーションに対して、サイバネットシステムで利便性向上などの改変を行ったアプリ
ケーションです。
Carbon Black社およびサイバネットシステムでは、本アプリケーションへのサポートは
提供しておりません。

This application is not official Carbon Black product.
Carbon Black doesn't offer any support for this application.
Cybernet Systems has modified the source code for easier usage, based on source 
code provided by Carbon Black.
Cybernet Systems does not offer any support for this application.
Please use it at your own risk.


■設定方法
□システム要件
- Windows x86-64 environment
   (Windows 7/Windows 10/Windows Server 2016)

□インストール方法
1. アプリケーションのインストール用フォルダを作成します。
2．インストールモジュール「PSC_Syslog_Connector_Installer.exe」を実行します。
3．インストール確認画面にて【はい(Y)】を押下します。
4. 上記 1.で作成した、インストール用フォルダを指定します。
5. インストール完了を示すウィンドウで【OK】を押下します。
6. インストール用フォルダに以下のファイルが配置されていることを確認します。
　- PSC_Syslog_Connector_Installer.exe
  - config.ini
  - schtasks_setup.bat
  - README.txt    (本ファイル)
7. インストール用フォルダの README.txtを参照して設定を完了してください。

□設定方法
1. CB Defenseや CB ThreatHunterの PSCコンソールにて、コネクタ設定および
　通知設定を行います。
　(1) [設定]>[コネクタ]画面にて「SIEM」用コネクタを作成
　(2) [設定]>[通知]画面にて、作成したコネクタを利用する通知を作成

2. インストール用フォルダの config.ini設定ファイルに設定を行います。
　(1) 通知先 Syslogサーバに合わせて udp_out項を設定
　(2) PSCコンソールのコネクタ設定従って connector_id項および api_key項を設定
　(3) PSCコンソールに合わせてバックエンドサーバ用 server_url項を設定

3. PSC_Syslog_Connector.exeを実行し、設定通りに動作することを確認します。
　(1) 実行フォルダに PSC_Syslog.logログファイルの生成を確認
　(2) PSC_Syslog.logログファイルに以下の行が出力されることを確認
　　・INFO : Start
　　・INFO : Finished.

4. 管理者権限で schtasks_setup.batを実行し、タスクスケジューラに自動実行を
　登録します。
　(1) タスクスケジューラへの「PSC Syslog Connector」登録状態を確認
　(2) 10分程度経過後、タスクスケジューラで実行結果の「正しく終了」を確認


■トラブル対応
(1) 状況：PSC_Syslog.logログファイルに以下のエラーが記録された場合
　ERROR : URLError:[Errno 11001] getaddrinfo failed

・対応：以下の手順で問題が解消されるか確認ください。
　(a) config.ini設定ファイルの server_url項の指定 URLを再確認ください。
　　※テクさぽFAQ：SIEM/syslog連携と REST API連携用サーバの URLについて
　　　https://secure.okbiz.okwave.jp/cybernet/faq/show/3422

(2) 状況：PSC_Syslog.logログファイルに以下のエラーが記録された場合
　ERROR : URLError:[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed 

・対応：以下の手順で問題が解消されるか確認ください。
　(a) Webブラウザ(Internet Explorer, Chome, Fireforxなど)を開きます。
　(b) config.ini設定ファイルの server_url項で指定した URLに、Webブラウザで
　　　アクセスします。
　　※Webブラウザのアクセスで 404エラーとなっても問題ございません。
　(c) 再度 PSC_Syslog_Connector.exeを実行し、上記 SSLエラーが解消することを
　　　確認します。

(3) 状況：PSC_Syslog.logログファイルに以下のエラーが記録された場合
　ERROR : HTTPError:401

・対応：以下の手順で問題が解消されるか確認ください。
　(a) config.ini設定ファイルの connector_id項および api_key項の設定内容を
　　　再確認ください。

(4) 状況：PSC_Syslog.logログファイルに以下のエラーが記録された場合
　ERROR : Syslog setup error: <エラー内容>

・対応：以下の手順で問題が解消されるか確認ください。
　(a) config.ini設定ファイルの udp_out項の設定内容を再確認ください。

