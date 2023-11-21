# this file is for automating nmap output 
import utils

def nmap_xml_output(dest = "scanme.nmap.org", args = "-oX -"):
    # this runs the command "nmap -oX - scanme.nmap.org"
    command = 'sudo nmap ' + args + ' ' + str(dest)
    print("running command: " + command)
    result = utils.runThisCommand(command)
    print("NMAP scan finished")
    return result
# for testing the above
# nmap_xml_output("scanme.nmap.org")



_nmap_sample_ouput = '''sudo nmap -p- -sV -O -A -T5 -sC -Pn 192.168.119.129
Starting Nmap 7.80 ( https://nmap.org ) at 2023-11-09 19:34 EST
Nmap scan report for 192.168.119.129
Host is up (0.0013s latency).
Not shown: 65505 closed ports
PORT      STATE SERVICE     VERSION
21/tcp    open  ftp         vsftpd 2.3.4
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to 192.168.119.1
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      vsFTPd 2.3.4 - secure, fast, stable
|_End of status
22/tcp    open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
| ssh-hostkey:
|   1024 60:0f:cf:e1:c0:5f:6a:74:d6:90:24:fa:c4:d5:6c:cd (DSA)
|_  2048 56:56:24:0f:21:1d:de:a7:2b:ae:61:b1:24:3d:e8:f3 (RSA)
23/tcp    open  telnet      Linux telnetd
25/tcp    open  smtp        Postfix smtpd
|_smtp-commands: metasploitable.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN,
|_ssl-date: 2023-11-10T00:37:23+00:00; +2s from scanner time.
| sslv2:
|   SSLv2 supported
|   ciphers:
|     SSL2_RC4_128_WITH_MD5
|     SSL2_RC2_128_CBC_WITH_MD5
|     SSL2_DES_64_CBC_WITH_MD5
|     SSL2_RC2_128_CBC_EXPORT40_WITH_MD5
|     SSL2_DES_192_EDE3_CBC_WITH_MD5
|_    SSL2_RC4_128_EXPORT40_WITH_MD5
53/tcp    open  domain      ISC BIND 9.4.2
| dns-nsid:
|_  bind.version: 9.4.2
80/tcp    open  http        Apache httpd 2.2.8 ((Ubuntu) DAV/2)
|_http-server-header: Apache/2.2.8 (Ubuntu) DAV/2
|_http-title: Metasploitable2 - Linux
111/tcp   open  rpcbind     2 (RPC #100000)
139/tcp   open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp   open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
512/tcp   open  exec        netkit-rsh rexecd
513/tcp   open  login?
514/tcp   open  tcpwrapped
1099/tcp  open  java-rmi    GNU Classpath grmiregistry
1524/tcp  open  bindshell   Metasploitable root shell
2049/tcp  open  nfs         2-4 (RPC #100003)
2121/tcp  open  ftp         ProFTPD 1.3.1
3306/tcp  open  mysql       MySQL 5.0.51a-3ubuntu5
| mysql-info:
|   Protocol: 10
|   Version: 5.0.51a-3ubuntu5
|   Thread ID: 12
|   Capabilities flags: 43564
|   Some Capabilities: Support41Auth, LongColumnFlag, Speaks41ProtocolNew, SwitchToSSLAfterHandshake, SupportsTransactions, ConnectWithDatabase, SupportsCompression
|   Status: Autocommit
|_  Salt: Rtq\Y*c4y(V[E'4nQ(r*
3632/tcp  open  distccd     distccd v1 ((GNU) 4.2.4 (Ubuntu 4.2.4-1ubuntu4))
5432/tcp  open  postgresql  PostgreSQL DB 8.3.0 - 8.3.7
|_ssl-date: 2023-11-10T00:37:31+00:00; +2s from scanner time.
5900/tcp  open  vnc         VNC (protocol 3.3)
| vnc-info:
|   Protocol version: 3.3
|   Security types:
|_    VNC Authentication (2)
6000/tcp  open  X11         (access denied)
6667/tcp  open  irc         UnrealIRCd (Admin email admin@Metasploitable.LAN)
6697/tcp  open  irc         UnrealIRCd
8009/tcp  open  ajp13       Apache Jserv (Protocol v1.3)
|_ajp-methods: Failed to get a valid response for the OPTION request
8180/tcp  open  http        Apache Tomcat/Coyote JSP engine 1.1
|_http-favicon: Apache Tomcat
|_http-server-header: Apache-Coyote/1.1
|_http-title: Apache Tomcat/5.5
8787/tcp  open  drb         Ruby DRb RMI (Ruby 1.8; path /usr/lib/ruby/1.8/drb)
32988/tcp open  mountd      1-3 (RPC #100005)
35522/tcp open  status      1 (RPC #100024)
56340/tcp open  java-rmi    GNU Classpath grmiregistry
58588/tcp open  nlockmgr    1-4 (RPC #100021)
Device type: general purpose|WAP|switch|media device|VoIP phone
Running (JUST GUESSING): Linux 2.6.X|2.4.X (97%), Linksys embedded (94%), Extreme Networks ExtremeXOS 15.X|12.X (93%), Brocade Fabric OS 4.X (93%), LifeSize embedded (93%), ShoreTel embedded (93%), D-Link embedded (93%)
OS CPE: cpe:/o:linux:linux_kernel:2.6 cpe:/h:linksys:wrv54g cpe:/o:extremenetworks:extremexos:15.3 cpe:/o:extremenetworks:extremexos:12.5.1 cpe:/o:linux:linux_kernel:2.4 cpe:/o:brocade:fabric_os:4.4.0 cpe:/h:shoretel:8800 cpe:/h:dlink:dwl-900ap
Aggressive OS guesses: Linux 2.6.9 - 2.6.33 (97%), Linux 2.6.22 (embedded, ARM) (96%), Linux 2.6.22 - 2.6.23 (96%), Linksys WRV54G WAP (94%), Linux 2.6.19 - 2.6.36 (94%), Linux 2.6.31 (94%), Linux 2.6.9 - 2.6.24 (94%), Linux 2.6.9 - 2.6.30 (94%), Linux 2.6.13 - 2.6.32 (94%), Extreme Networks ExtremeXOS 12.5.1 or 15.3 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Hosts:  metasploitable.localdomain, irc.Metasploitable.LAN; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 1s, deviation: 0s, median: 1s
|_ms-sql-info: ERROR: Script execution failed (use -d to debug)
|_nbstat: NetBIOS name: METASPLOITABLE, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
|_smb-os-discovery: ERROR: Script execution failed (use -d to debug)
|_smb-security-mode: ERROR: Script execution failed (use -d to debug)
|_smb2-time: Protocol negotiation failed (SMB2)

TRACEROUTE (using port 995/tcp)
HOP RTT     ADDRESS
1   0.57 ms LAPTOP-PO56QG8G.mshome.net (172.23.208.1)
2   2.30 ms 192.168.119.129

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 241.32 seconds'''.splitlines()

###