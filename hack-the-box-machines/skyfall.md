---
description: 'IP: 10.10.11.254 - Platform: Linux- Difficulty: Insane'
cover: ../.gitbook/assets/Skyfall.png
coverY: 320.49066666666664
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

# 🟥 SKYFALL

## RECON

### Nmap

```
nmap -sV -sC -v -T4 -p- 10.10.11.254

Initiating Connect Scan at 00:46
Scanning 10.10.11.254 [65535 ports]
Discovered open port 22/tcp on 10.10.11.254
Discovered open port 80/tcp on 10.10.11.254

Host is up (0.045s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 6570f71247073a888e27e9cb445d10fb (ECDSA)
|_  256 74483307b7889d320e3bec16aab4c8fe (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-favicon: Unknown favicon MD5: FED84E16B6CCFE88EE7FFAAE5DFEFD34
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-title: Skyfall - Introducing Sky Storage!
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### FFUF

```
ffuf -c -u http://skyfall.htb -H "Host: FUZZ.skyfall.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -ac -mc all

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://skyfall.htb
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
 :: Header           : Host: FUZZ.skyfall.htb
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
________________________________________________

demo                    [Status: 302, Size: 218, Words: 21, Lines: 4, Duration: 61ms]
#www                    [Status: 400, Size: 166, Words: 6, Lines: 8, Duration: 41ms]
#mail                   [Status: 400, Size: 166, Words: 6, Lines: 8, Duration: 44ms]
```

**`ffuf`** ends up discovered a demo subdomain. Let add it into `/etc/hosts` file and access it.

## GAINING FOOTHOLD

<figure><img src="../.gitbook/assets/423036588_396942352883327_2020450717708441511_n.png" alt=""><figcaption><p>Image taken from skyfall.htb</p></figcaption></figure>

No valuable points of exploitation were discovered using automation tools such as the Nikto vulnerability scanner. However, while searching for other directories, we come across skyfall.htb/assets and receive only a 403 code in response. Let's shift our focus to the other subdomain since we haven't had any luck breaking into it yet.&#x20;

<figure><img src="../.gitbook/assets/423062765_1862329410890858_5174765670734243236_n.png" alt="" width="375"><figcaption><p>Login portal of demo.skyfall.htb</p></figcaption></figure>

Well, there is no need to use any tools to get around authentication since we are presented with the default credentials. Let hop in and look around to see if you can find anything helpful.

<figure><img src="../.gitbook/assets/423105531_923516372471819_1990932098032323772_n.png" alt=""><figcaption><p>Dashboard</p></figcaption></figure>

<figure><img src="../.gitbook/assets/423422279_920682549270738_2236155709537720576_n.png" alt=""><figcaption><p>Bingo! File Upload </p></figcaption></figure>

Upon closer inspection, it appears that uploading a normal malicious payload does not give us any shell. We learn something about this system from the dashboard. It supposed to be a MinIO Object Storage System.

{% hint style="info" %}
**MinIO** is a high-performance object store that works with S3. It is designed to handle massive workloads in databases, data lakes, and AI/ML. It is software-defined and runs on any cloud or on-premises infrastructure. Oh, and **MinIO** is also open-sourced!
{% endhint %}



## PRIVILEGE ESCALATION <a href="#privilege-escalation" id="privilege-escalation"></a>

