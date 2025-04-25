---
title: "HTB Legacy Walkthrough"
date: "2025-04-21"

layout: ../../layouts/PostLayout.astro
description: "Detail walkthrough on hackthebox machine legacy."

img_path : "/images/legacy/theme.png"
img_alt: "web image"
---

## Title: Legacy

## About Legacy

Legacy is a fairly straightforward beginner-level machine which 
demonstrates the potential security risks of SMB on Windows. Only one 
publicly available exploit is required to obtain administrator access.

---

## 1. The Process

### Enumeration

First let’s run the nmap

![image.png](/images/legacy/image1.png)

There are 3 TCP ports open. It also reveals that smb is running and the OS is Windows XP.

I asked AI(chatgpt) for the CVE ID that is vulnerable for SMB.

![image.png](/images/legacy/image2.png)

CVE ID “CVE-2008-4250”  is a SMB vulnerability that allows RCE.

This can be exploit using metasploit module. 

### Exploitation

Start a msfconsole and search for the smb cve-2008-4250 module.

![image.png](/images/legacy/image3.png)

Enter use 0 to use that module.

![image.png](/images/legacy/image4.png)

Run show options to see what setting do we have to set.

![image.png](/images/legacy/image5.png)

So we need to set rhosts and lhost. Set the rhosts as the remote machine’s ip and set lhost as your attacking machine’s ip.

![image.png](/images/legacy/image6.png)

After everything is set, run the command “exploit”

![image.png](/images/legacy/image7.png)

Boom…we got the system shell. now let’s search user flag and root flag.

![image.png](/images/legacy/image8.png)

The user flag can be obtained from C:\Documents and Settings\john\Desktop\user.txt and the
root flag from C:\Documents and Settings\Administrator\Desktop\root.txt

### user flag

![image.png](/images/legacy/image9.png)

### root flag

![image.png](/images/legacy/image10.png)

## 2. Learning

- I have learned how to find the vulnerability services and identify the CVE ID.
- I have also learned to exploit the SMB.

## 3. Reference List

[legacy.pdf](/images/legacy/Legacy.pdf)
