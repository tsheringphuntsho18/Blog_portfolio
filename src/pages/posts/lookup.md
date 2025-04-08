---
title: "THM Lookup Walkthrough"
date: "2025-04-09"

layout: ../../layouts/PostLayout.astro
description: "Detail walkthrough on tryhackme machine lookup."

img_path : "/images/lookup/theme.png"
img_alt: "theme picture"
---

"<span style="color:yellow">*There is no right and wrong. There's only fun and boring.*</span>"

![cover](/images/lookup/cover.png)

### Room Information
- Room Name: Lookup
- Difficulty Level: Easy
- Room type: Challenges(CTF)

![cover](/images/lookup/machine.png)

### Reconnaissance
![cover](/images/lookup/info.png)

Let’s run nmap and check what ports are open.

![cover](/images/lookup/nmap.png)

We have discovered 2 open ports: 22(ssh) and 80(http). Since port 80 is open let’s check the website.

![cover](/images/lookup/lookup.png)

We can see that the website redirects us to “lookup.thm”, so let’s add that to our hosts file.

![cover](/images/lookup/nano.png)

Let’s refresh the website.

![cover](/images/lookup/website.png)

It shows the login form. 

![cover](/images/lookup/wrong.png)

We don’t have user credentials so we can write a small python script that would help us enumerate valid usernames:

![cover](/images/lookup/script.png)

![cover](/images/lookup/user.png)

When I ran that python script I got two usernames;
- admin
- jose

Now let’s brute force the password using hydra.<br>
Command: hydra -l jose -P /path/to/rockyou.txt lookup.thm http-post-form "/login.php:username=^USER^&password=^PASS^:Wrong" -V

![cover](/images/lookup/password.png)

When we login we have been re-directed to “files.lookup.thm”. 

![cover](/images/lookup/file.png)

Let’s add that to our host file.( sudo nano /etc/hosts)

![cover](/images/lookup/add.png)

When refreshed, We landed in something called “elFinder”. This looks like a file manager.

![cover](/images/lookup/filesite.png)

Start metaexploit and search for elfinder. 

![cover](/images/lookup/elfinder.png)

Use exploit/unix/webapp/elfinder_php_connector_exiftran_cmd_injection

![cover](/images/lookup/run.png)

Drop shell and use netcat.

![cover](/images/lookup/shell.png)

![cover](/images/lookup/netcat.png)

Once we receive the connection.<br>
Run this command: python3 -c 'import pty;pty.spawn("/bin/bash")'

### Now Let’s get to the User. 

We do have user think. 

![cover](/images/lookup/think.png)

![cover](/images/lookup/perme.png)

We need to login as a user think to get user.txt flag.

Let’s search for SUID binaries:
Command: find / -perm /4000 2>/dev/null

![cover](/images/lookup/suid.png)

The /usr/sbin/pwm binary draws my attention because it's not there by default on Linux hosts.

Let’s try to trick the program into executing a different “ID” command, one that would result in the “think” username being extracted from the output.<br>
We can add /tmp to our path:

![cover](/images/lookup/way.png)

And now create /tmp/id. When we try running pwm we get the password list for user think. 

![cover](/images/lookup/list.png)

Now let’s save those lists and brute force the password using hydra.

Command: hydra -l think -P /home/tshering/THM/password.txt 10.10.211.78 ssh

![cover](/images/lookup/brute.png)

Username: think 
Password: josemario.AKA(think)

With those credentials let’s login to ssh.

![cover](/images/lookup/ssh.png)

Finally, boom…..we got the user flag. 

### Privilege Escalation
Now let’s try to get into a root.

![cover](/images/lookup/-l.png)

think can run /usr/bin/look. Let’s search in gtfobin 

![cover](/images/lookup/gtfo.png)

Let’s run it.

![cover](/images/lookup/id_rsa.png)

We got the id_rsa for the root, now save it, and let’s use it to login to root.

![cover](/images/lookup/root.png)

Now I have root access. 

![cover](/images/lookup/rootflag.png)

Finally, I got the root.txt


### Flag Captured
user.txt flag: 38375fb4dd8baa2b2039ac03d92b820e<br>
root.txt flag:  5a285a9f257e45c68bb6c9f9f57d18e8
