���T�v
PSC-Syslog-Connector-OSS���W���[���́ACarbon Black�Ђ� PSC�A�g�p�� Windows�� 
Syslog�R�l�N�^�ł��B
PSC���̉ғ��\�����[�V��������̒ʒm���ASyslog�o�R�ŊO���V�X�e���ɘA�g���܂��B
CB Defense���m�A���[�g�ACB ThreatHunter�� Watchlist���m�A���[�g�ɑΉ����Ă��܂��B


���T�|�[�g�ɂ���
�{�A�v���P�[�V�����́ACarbon Black�Ђ��I�[�v���\�[�X�Ƃ��Ē񋟂��Ă���A�v��
�P�[�V�����ɑ΂��āA�T�C�o�l�b�g�V�X�e���ŗ��֐�����Ȃǂ̉��ς��s�����A�v��
�P�[�V�����ł��B
Carbon Black�Ђ���уT�C�o�l�b�g�V�X�e���ł́A�{�A�v���P�[�V�����ւ̃T�|�[�g��
�񋟂��Ă���܂���B

This application is not official Carbon Black product.
Carbon Black doesn't offer any support for this application.
Cybernet Systems has modified the source code for easier usage, based on source 
code provided by Carbon Black.
Cybernet Systems does not offer any support for this application.
Please use it at your own risk.


���ݒ���@
���V�X�e���v��
- Windows x86-64 environment
   (Windows 7/Windows 10/Windows Server 2016)

���C���X�g�[�����@
1. �A�v���P�[�V�����̃C���X�g�[���p�t�H���_���쐬���܂��B
2�D�C���X�g�[�����W���[���uPSC_Syslog_Connector_Installer.exe�v�����s���܂��B
3�D�C���X�g�[���m�F��ʂɂāy�͂�(Y)�z���������܂��B
4. ��L 1.�ō쐬�����A�C���X�g�[���p�t�H���_���w�肵�܂��B
5. �C���X�g�[�������������E�B���h�E�ŁyOK�z���������܂��B
6. �C���X�g�[���p�t�H���_�Ɉȉ��̃t�@�C�����z�u����Ă��邱�Ƃ��m�F���܂��B
�@- PSC_Syslog_Connector_Installer.exe
  - config.ini
  - schtasks_setup.bat
  - README.txt    (�{�t�@�C��)
7. �C���X�g�[���p�t�H���_�� README.txt���Q�Ƃ��Đݒ���������Ă��������B

���ݒ���@
1. CB Defense�� CB ThreatHunter�� PSC�R���\�[���ɂāA�R�l�N�^�ݒ肨���
�@�ʒm�ݒ���s���܂��B
�@(1) [�ݒ�]>[�R�l�N�^]��ʂɂāuSIEM�v�p�R�l�N�^���쐬
�@(2) [�ݒ�]>[�ʒm]��ʂɂāA�쐬�����R�l�N�^�𗘗p����ʒm���쐬

2. �C���X�g�[���p�t�H���_�� config.ini�ݒ�t�@�C���ɐݒ���s���܂��B
�@(1) �ʒm�� Syslog�T�[�o�ɍ��킹�� udp_out����ݒ�
�@(2) PSC�R���\�[���̃R�l�N�^�ݒ�]���� connector_id������� api_key����ݒ�
�@(3) PSC�R���\�[���ɍ��킹�ăo�b�N�G���h�T�[�o�p server_url����ݒ�

3. PSC_Syslog_Connector.exe�����s���A�ݒ�ʂ�ɓ��삷�邱�Ƃ��m�F���܂��B
�@(1) ���s�t�H���_�� PSC_Syslog.log���O�t�@�C���̐������m�F
�@(2) PSC_Syslog.log���O�t�@�C���Ɉȉ��̍s���o�͂���邱�Ƃ��m�F
�@�@�EINFO : Start
�@�@�EINFO : Finished.

4. �Ǘ��Ҍ����� schtasks_setup.bat�����s���A�^�X�N�X�P�W���[���Ɏ������s��
�@�o�^���܂��B
�@(1) �^�X�N�X�P�W���[���ւ́uPSC Syslog Connector�v�o�^��Ԃ��m�F
�@(2) 10�����x�o�ߌ�A�^�X�N�X�P�W���[���Ŏ��s���ʂ́u�������I���v���m�F


���g���u���Ή�
(1) �󋵁FPSC_Syslog.log���O�t�@�C���Ɉȉ��̃G���[���L�^���ꂽ�ꍇ
�@ERROR : URLError:[Errno 11001] getaddrinfo failed

�E�Ή��F�ȉ��̎菇�Ŗ�肪��������邩�m�F���������B
�@(a) config.ini�ݒ�t�@�C���� server_url���̎w�� URL���Ċm�F���������B
�@�@���e�N����FAQ�FSIEM/syslog�A�g�� REST API�A�g�p�T�[�o�� URL�ɂ���
�@�@�@https://secure.okbiz.okwave.jp/cybernet/faq/show/3422

(2) �󋵁FPSC_Syslog.log���O�t�@�C���Ɉȉ��̃G���[���L�^���ꂽ�ꍇ
�@ERROR : URLError:[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed 

�E�Ή��F�ȉ��̎菇�Ŗ�肪��������邩�m�F���������B
�@(a) Web�u���E�U(Internet Explorer, Chome, Fireforx�Ȃ�)���J���܂��B
�@(b) config.ini�ݒ�t�@�C���� server_url���Ŏw�肵�� URL�ɁAWeb�u���E�U��
�@�@�@�A�N�Z�X���܂��B
�@�@��Web�u���E�U�̃A�N�Z�X�� 404�G���[�ƂȂ��Ă���育�����܂���B
�@(c) �ēx PSC_Syslog_Connector.exe�����s���A��L SSL�G���[���������邱�Ƃ�
�@�@�@�m�F���܂��B

(3) �󋵁FPSC_Syslog.log���O�t�@�C���Ɉȉ��̃G���[���L�^���ꂽ�ꍇ
�@ERROR : HTTPError:401

�E�Ή��F�ȉ��̎菇�Ŗ�肪��������邩�m�F���������B
�@(a) config.ini�ݒ�t�@�C���� connector_id������� api_key���̐ݒ���e��
�@�@�@�Ċm�F���������B

(4) �󋵁FPSC_Syslog.log���O�t�@�C���Ɉȉ��̃G���[���L�^���ꂽ�ꍇ
�@ERROR : Syslog setup error: <�G���[���e>

�E�Ή��F�ȉ��̎菇�Ŗ�肪��������邩�m�F���������B
�@(a) config.ini�ݒ�t�@�C���� udp_out���̐ݒ���e���Ċm�F���������B

