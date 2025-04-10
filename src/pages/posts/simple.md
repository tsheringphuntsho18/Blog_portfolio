---
title: "THM Simple CTF Walkthrough"
date: "2025-04-08"

layout: ../../layouts/PostLayout.astro
description: "Detail walkthrough on tryhackme machine simple ctf."

img_path : "/images/simplectf/theme.png"
img_alt: "theme picture"
---

# Try Hack Me Room: Simple CTF
![CTF](/images/simplectf/simplctf.png)

When I paste the ip address on the browser, it showed like this;
![CTF](/images/simplectf/webpage.png)

It looks like a default Ubuntu installation. Now lets scan the machine
![CTF](/images/simplectf/nmapscan.png)

### How many services are running under port 1000?
<b>ANS:</b> 2

### What is running on the higher port?
<b>ANS:</b> ssh

### What's the CVE you're using against the application? 
To know this answer, let’s find out the hidden files using ffuf.
![CTF](/images/simplectf/simpleffuf.png)

We found that there is a hidden directory /simple let's check it out.
![CTF](/images/simplectf/simple.png)

Here we can see this is a default page for something called “CMS Made Simple” and if we look in the bottom corner we can see it is version 2.2.8. Let’s search in exploit DB for CMS Made Simple 2.2.8 exploit.
![CTF](/images/simplectf/simplecve.png)

We are going to use this cve.<br>
<b>ANS:</b> CVE-2019-9053

### To what kind of vulnerability is the application vulnerable?
It is vulnerable to SQL injection<br>
<b>ANS:</b> SQLi

### What's the password?
To get the password, I started the exploit using the python script given in the CVE. First I copy pasted that python script and save as exploit.py.
![CTF](/images/simplectf/simpleexploit.png)

Next I ran this python file in the terminal. Command to run the python file is<br> 
python3 exploit.py -u http://10.10.137.253/simple/ 

![CTF](/images/simplectf/simplecrack.png)

I cracked that password and got as the password secret

<b>ANS:</b> secret

### Where can you login with the details obtained?
<b>ANS:</b> ssh

### What's the user flag?
Using username and password, now lets login into ssh
<b>ANS:</b>G00d j0b, keep up!

### Is there any other user in the home directory? What's its name? 
<b>ANS:</b> sunbath

### What can you leverage to spawn a privileged shell?
<b>ANS:</b> vim

### What's the root flag?
<b>ANS:</b> W3ll d0n3. You made it!

## Conclusion
I have written the basic walkthrough of simplectf from try hack me room.