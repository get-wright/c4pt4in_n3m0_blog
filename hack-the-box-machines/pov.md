---
description: 'IP: 10.10.11.251'
cover: ../.gitbook/assets/Pov.png
coverY: 338.72222222222223
layout:
  cover:
    visible: true
    size: hero
  title:
    visible: true
  description:
    visible: true
  tableOfContents:
    visible: true
  outline:
    visible: true
  pagination:
    visible: true
---

# 🟨 POV

1. Recon

nmap reveals that only port 80 is open. That is kinda strange for a typical machine seen on HTB. Most of the boxes tend to open port 22 (or commonly refer as SSH) as a way to remote access as user or root. The usual approach would be to grab the creds through some nefarious ways then log in SSH creds.  &#x20;

```

map -sV -sC -v -T4 10.10.11.251

PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: pov.htb
|_http-server-header: Microsoft-IIS/10.0
|_http-favicon: Unknown favicon MD5: E9B5E66DEBD9405ED864CAC17E2A888E
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

```

Using ffuf to search for subdomains that respond different with code 200/300

```
ffuf -c -u http://pov.htb -H "Host: FUZZ.pov.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -ac -mc all


        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://pov.htb
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
 :: Header           : Host: FUZZ.pov.htb
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
________________________________________________

dev                     [Status: 302, Size: 152, Words: 9, Lines: 2, Duration: 476ms]
:: Progress: [19966/19966] :: Job [1/1] :: 153 req/sec :: Duration: [0:02:13] :: Errors: 0 ::

```

Only 1 subdomain returns 302 - dev. Let add it into /etc/hosts&#x20;



