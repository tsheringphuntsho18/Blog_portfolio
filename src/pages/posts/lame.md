---
title: "HTB Lame Walkthrough"
date: "2025-04-17"

layout: ../../layouts/PostLayout.astro
description: "Detail walkthrough on hackthebox machine lame."

img_path : "/images/lame/theme.png"
img_alt: "web image"
---

## Title: Lame

## About Lame

Lame is an easy Linux machine, requiring only one exploit to obtain root access. It was the first machine published on Hack The Box and was often the first machine for new users prior to its retirement. 

## 1. The Process

### Enumeration

First I always run the nmap command on that machine's IP address.

![image.png](/images/lame/nmap.png)

On the remote host, there are 4 TCP ports open. And 2.3.4 version of vsftpd is running on the machine. Since there isn’t HTTP port open, I will not check for website. But nmap has revealed that vsFTPd 2.3.4, OpenSSH, and Samba are running on the target server.

### FTP

Whenever there is FTP port open, my instinct says to login as anonymous. let’s also try here.

![image.png](/images/lame/ftp.png)

Using an anonymous username and a random password, I did login to FTP server but nothing was interesting. There is a famous backdoor in VSFTPd version 2.3.4, and a Metasploit module to exploit it. 

![image.png](/images/lame/msfconsole.png)

Start msfconsole and search for vsftpd version 2.3.4

![image.png](/images/lame/vsftpd.png)

Use the vsftpd_234_backdoor module and set rhost, and then run it.

![image.png](/images/lame/run.png)

Although the exploit was completed, there is no shell. let’s skip the FTP port and try different port.

### SMB

 Let’s enumerate the SMB service using smbmap.

![image.png](/images/lame/smbver.png)

Samba 3.0.20 is running on the target. I will once again search for this version module in msfconsole.

![samba.png](/images/lame/samba.png)

Use that module and check for the available options to set up.

![image.png](/images/lame/set.png)

I need to set rhost and lhost. When I kept the host as default, it didn’t work, so I changed it to my lhost. Then it worked. Now I got the root shell. The user flag can be found at /home/makis/user.txt, and the root flag can be found at /root/root.txt.

![image.png](/images/lame/userflag.png)

## 2. Learning

- I have learned that if the “Host seems down” message pops up, I need to use the -Pn flag. Tells Nmap not to ping the host before scanning. Useful when the host blocks ping requests (ICMP echo) or when you already know the host is up. Without  -Pn, Nmap might skip hosts it thinks are offline.
- SMBMap allows users to enumerate samba share drives across an entire domain

## 3. Reference list

[Lame.pdf](attachment:72a80f02-12bf-44e7-b512-d7bcfd93fedd:Lame.pdf)

[HackTheBox (HTB) — Lame](https://medium.com/@sshekhar01/hackthebox-htb-lame-94cba9bf304f)