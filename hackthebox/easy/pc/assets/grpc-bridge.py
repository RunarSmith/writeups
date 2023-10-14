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
