


## Scan open ports

```bash
nmap -sT -Pn ${TARGET} -p - --open
```

## scan for services behind somr ports

```bash
nmap -sT -sV -sC -A -Pn ${TARGET} -p 80,135,445,50000
```

## use nmap to scan for vulnerabilities

```bash
nmap -sT -sV -sC -Pn ${TARGET} -p 80,135,445,50000 --script vuln
```
