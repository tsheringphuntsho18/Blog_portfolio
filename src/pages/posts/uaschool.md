---
title: "THM U.A. High School Walkthrough"
date: "2025-04-09"

layout: ../../layouts/PostLayout.astro
description: "Detail walkthrough on tryhackme machine u.a. high school."

img_path : "/images/U.AhighSchool/theme.png"
img_alt: "theme picture"
---

"<span style="color:yellow">*Remember, hacking is more than just a crime. It's a survival trait.*</span>"

![cover](/images/U.AhighSchool/cover.png)

### Room Information
 - Room Name: U.A. High School
 - Difficulty Level: Easy
 - Room type: Challenges(CTF)

![cover](/images/U.AhighSchool/machine.png)

### Reconnaissance
let’s run nmap and check what ports are open
![cover](/images/U.AhighSchool/nmap.png)
I discovered 2 open ports: 22 and 80,. Since port 80 is open, let’s check the website.

![cover](/images/U.AhighSchool/website.png)
It is just a normal high school website. 

So let’s check for any other hidden directories using dirsearch.
![cover](/images/U.AhighSchool/dirsearch.png)
![cover](/images/U.AhighSchool/hiddendir.png)
I found that there is a hidden directory (/assets). Let’s check /assets.
![cover](/images/U.AhighSchool/blank.png)

The directory is simply a blank page. Let’s proceed further by finding the subdirectory.
![cover](/images/U.AhighSchool/subdir.png)
![cover](/images/U.AhighSchool/hiddensubdir.png)
I found the index.php subdirectory. So there is the possibility of command injection.
![cover](/images/U.AhighSchool/cmd.png)
Let’s begin the command injection
![cover](/images/U.AhighSchool/ls.png)
Oh, I got the base64. Let's crack it using cyberchef.
![cover](/images/U.AhighSchool/base64.png)
I already knew there were subdirectories like images, index.php, or styles.css. So this confirms that we can perform command injection. 
Let’s Try with the cat passwd
![cover](/images/U.AhighSchool/catpasswd.png)

Again base64, let’s crack it using cyberchef.
![cover](/images/U.AhighSchool/user.png)
deku:x:1000:1000:deku:/home/deku:/bin/bash
From the last line, I got the user(deku). 


### Now Let’s get to the User.
![cover](/images/U.AhighSchool/hydra.png)

To log in using ssh, I try to brute force Deku’s password using the hydra command and I try to file that contains passwords. I could not found in the first file and rockyou.txt took lots of time to complete. So let’s do using the reverse shell.

Let's get a reverse connection using Netcat
Start netcat listener 
![cover](/images/U.AhighSchool/nc.png)

Go to https://www.revshells.com/ and generate the reverse shell as below.
![cover](/images/U.AhighSchool/reverseshell.png)

Click on copy and then paste it into the URL after cmd= 
![cover](/images/U.AhighSchool/paste.png)
![cover](/images/U.AhighSchool/connection.png)

Wow, I received the connection.
![cover](/images/U.AhighSchool/image.png)
Run command: python3 -c 'import pty;pty.spawn("/bin/bash")' to use /bin/bash

Inside the images directory, there are 2 images.

Let’s Transfer these files from the Victim’s machine to the attacker’s system using Netcat.
![cover](/images/U.AhighSchool/sender.png)
We send files like this. And in another terminal, we receive like this;
![cover](/images/U.AhighSchool/receiver.png)

Let’s check if I received it or not
![cover](/images/U.AhighSchool/isthere.png)

upon further inspection found that the file uses the extension .jpg but is in data format. So we are going to Change the incorrect jpg file headers. 

Opening the file using Hexedit.
Command: hexedit oneforall.jpg
![cover](/images/U.AhighSchool/header.png)
Change the initial header to FF D8 FF E0  00 10 4A 46  49 46 00 01  01 00 00 01. This is the correct signature for the jpeg file. Save the file.
![cover](/images/U.AhighSchool/show.png)
Now it is showing the correct extension for the image and I can also view the image.
![cover](/images/U.AhighSchool/pic.png)


Now using this file we can use stegnography to check file contents
Using steghide to extract the files inside the file
![cover](/images/U.AhighSchool/steghide.png)

Oh, we need to enter the passphrase, earlier I found the hidden file and it contains the base64 code.
![cover](/images/U.AhighSchool/hiddencontent.png)
![cover](/images/U.AhighSchool/pass.png)
So the passphrase is AllmightForEver!!!
![cover](/images/U.AhighSchool/password.png)
wow, finally I got the password for Deku.

Using the password that I got, I can easily log in to Duke using ssh. 
![cover](/images/U.AhighSchool/ssh.png)

There is a user.txt file. I got the user flag. 

### Privilege Escalation
The next task is to get the root.txt flag. It isn’t as easy as I thought. I can’t get into root just with the command sudo su.
![cover](/images/U.AhighSchool/su.png)

I need to check for sudo privileges.
Command: sudo -l
![cover](/images/U.AhighSchool/-l.png)

User deku can run (ALL) /opt/NewComponent/feedback.sh. Let’s do what user deku is allowed to do. 
![cover](/images/U.AhighSchool/feedback.png)
Deku can give feedback. Let’s try to give malicious feedback.
The malicious feedback is ‘Deku ALL=NOPASSWD: ALL >> /etc/sudoers’
![cover](/images/U.AhighSchool/root.png)
It works and now I got the root access.
![cover](/images/U.AhighSchool/rootflag.png)
Finally, I also got the root.txt

### Flag Captured
- user.txt flag: THM{W3lC0m3_D3kU_1A_0n3f0rAll??}

- root.txt flag:  THM{Y0U_4r3_7h3_NUm83r_1_H3r0}
