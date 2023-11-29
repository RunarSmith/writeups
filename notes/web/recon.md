
# Web reconnaissance

## gobuster

Use dirbuster to enumerate folders ans files on remote web server :

```bash
gobuster dir -w `fzf-wordlists` -u http://${TARGET}:${Port}/
```

### Some big dictionnaries

- /usr/share/seclists/Discovery/Web-Content/common.txt
- /usr/share/seclists/Discovery/Web-Content/big.txt
- /usr/share/seclists/Discovery/Web-Content/directory-list-1.0.txt
- /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt

### add possible extenstions

```bash
gobuster dir -w `fzf-wordlists` -u http://${TARGET}:${Port}/ -x json,html,php,txt,xml,md
```

### speed up

go buster use 10 threads by default. use 30 instead :

```bash
gobuster dir -w `fzf-wordlists` -u http://${TARGET}:${Port}/ -t 30
```
