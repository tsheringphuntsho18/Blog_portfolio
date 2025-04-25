---
title: "HTB Netmon Walkthrough"
date: "2025-04-19"

layout: ../../layouts/PostLayout.astro
description: "Detail walkthrough on hackthebox machine netmon."

img_path : "/images/netmon/theme.png"
img_alt: "web image"
---

## Title: Netmon

## About Netmon

Netmon is an easy difficulty Windows box with simple enumeration and exploitation. PRTG is running, and an FTP server with anonymous access allows reading of PRTG Network Monitor configuration files. The version of PRTG is vulnerable to RCE which can be exploited to gain a SYSTEM shell. 

## 1. The Process

### Enumeration

The first step is to run nmap on the machine's IP address.

![image.png](/images/netmon/nmap1.png)

I have run a basic nmap, i.e, only with the -sV flag. By doing this, I get the services and the version. I got a better way of doing nmap with lots of details given to us.

```bash
nmap -sC -sV 10.10.10.152 
```

![image.png](/images/netmon/nmap2.png)

By adding -sC flag I get more details about that machine.

There are 5 ports open, and the FTP port allows anonymous login. So let’s try FTP login.

![image.png](/images/netmon/ftp3.png)

With an anonymous username and random password, I could login into the FTP server.

![image.png](/images/netmon/userflag4.png)

The user flag is located on the Public user's desktop. To download the user.txt file we need to use 

 Next, let’s check the website since the HTTP port 80 is open.

![image.png](/images/netmon/website5.png)

The PRTG Network Monitor application is running on port 80. So I googled for the default credentials for the PRTG network monitoring application.

![image.png](/images/netmon/defalut6.png)

I found that prtgadmin is the default login name and password. Let’s try to log in with those default credentials.

![image.png](/images/netmon/loginfail7.png)

oops…didn't work. The best way is to search for prtg network configuration file using FTP. 

![image.png](/images/netmon/file8.png)

It is shown that we can find PRTG data folder located in “**C:\ProgramData\Paessler\PRTG Network Monitor**". 

![image.png](/images/netmon/programdata9.png)

PRTG Configuration.dat and PRTG Configuration.old are the same file. So I downloaded PRTG Configuration.dat and inspected it, but nothing was found. Next, I downloaded PRTG Configuration.old.bak the file and inspected it, and found the DB credential

![image.png](/images/netmon/db9b.png)

With these credentials, let’s login to the website.

![loginfail7.png](/images/netmon/loginfail7.png)

However, the credentials refuse to work. Maybe the password was changed from the old
configuration. The box was released in 2019 and that users are forced to rotate their passwords from time to time. Let’s follow the pattern and try "PrTg@dmin2019" as the password.

![image.png](/images/netmon/page10.png)

Wow…that worked, and now I have access to the website as an administrator. 

### Privilege escalation

My main aim is to get a root shell in window, it is the system shell.. By studying the website, I found that the website is using the older version.

![image.png](/images/netmon/version11.png)

On googling, I found one github [repo](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/exploit/windows/http/prtg_authenticated_rce.md) about the vulnerabilities yields a CVE for versions < 18.1.39 (CVE-2018-9276).

![image.png](/images/netmon/vul12.png)

According to this article,  RCE can be achieved while triggering notifications. Let’s try exploiting it.

Click on Setup > Account Settings > Notifications.

![image.png](/images/netmon/noti13.png)

Click on “Add new notification” which is the plus icon.

Leave the default fields as they are and scroll down to the "Execute Program" section. We can
add a user to the Administrators group using this command:

```bash
abc.txt | net user htb abc123! /add ; net localgroup administrators htb
/add
```

![image.png](/images/netmon/execution14.png)

In the program file select “Demo exe notification-outfile.ps1” and in parameter add the above command. Then click on save.

Now to trigger that notification, click on the edit icon of your notification name (if the basic setting is kept as same, then the notification name should be “notification”) and then click on the bell icon.

![editicon15.png](/images/netmon/editicon15.pngg)

Then we will get the output as follow;

![notioutput16.png](/images/netmon/notioutput16.png)

Now use psexec to login as the created admin user.

```bash
python3 psexec.py htb:'abc123!'@10.10.10.152
```

First we need to download the [psexec.py](https://github.com/fortra/impacket/blob/master/examples/psexec.py) file. There is one bug in this code that is in line 644. We need to change `logger.init(options.ts, options.debug)` to `logger.init()`

![execution17.png](/images/netmon/execution17.png)

Finally, we got the system shell. The commands in Windows are a bit different from Linux. To list a directory, it is `dir`, and to read a text file, the command is `type`.

![image.png](/images/netmon/rootflag.png)

The root flag is in the \Users\Administrator\Desktop directory.

## 2. Learning

- I have learn that nmap -sC -sV IP gives the detailed info about the list of open ports, names, and versions of services on those ports, script outputs from the default script set, giving deeper insight
- I have learned that some applications have default credentials. The PRTG network monitor application has the default credential **prtgadmin** for both the login name and password.
- If the directory name has a space between its name, I have to specify it within quotation marks.
- PsExec is a command-line tool that allows system administrators to execute processes on remote Windows systems. It essentially enables remote command execution, allowing users to run programs, scripts, and commands on other computers over the network.
- In Windows Shell, the command is dir to list a directory.
- In Windows Shell, the command is type to read a text file.

## 3. Reference list

[https://www.youtube.com/watch?v=ZxvgniJXbOo](https://www.youtube.com/watch?v=ZxvgniJXbOo)

[Netmon.pdf](/images/netmon/Netmon.pdf)
