---
title: "HTB Jerry Walkthrough"
date: "2025-04-20"

layout: ../../layouts/PostLayout.astro
description: "Detail walkthrough on hackthebox machine jerry."

img_path : "/images/jerry/theme.png"
img_alt: "web image"
---

## Title: Jerry

## About Jerry

Jerry is an easy-difficulty Windows machine that showcases how to exploit Apache Tomcat, leading to an `NT Authority\\SYSTEM` shell, thus fully compromising the target. 

## 1. The Process

### Enumeration

let’s begin with the nmap scan.

![image.png](/images/jerry/image1.png)

Only TCP port 8080 is open on the remote host and Apache Tomcat web server is running on the remote host. let’s check its website. We should also specify the port.

![image.png](/images/jerry/image2.png)

Website shows us the default Tomcat’s landing page. When we click on manager app, a login form is pop up. 

![image3.png](/images/jerry/image3.png)

let’s search for the default tomcat credentials. On the [github](https://github.com/netbiosX/Default-Credentials/blob/master/Apache-Tomcat-Default-Passwords.mdown) it is given the following credentials.

![image.png](/images/jerry/image4.png)

There are many credentials, so the correct way is by using metasploit module. 

Start a msfconsole and search for the “tomcat manager login” module.

![image.png](/images/jerry/image5.png)

Use that module and set rhosts and run. By doing this it will try every possible combination and give us the valid credentials.

![image.png](/images/jerry/image6.png)

We got the credentials that is “tomcat:s3cret”. let’s login to the manager app.

![image.png](/images/jerry/image7.png)

The credentials is valid so we successfully logged in into the manager app. 

**`.war` (Web Application Archive)** is the **only file type that** can be uploaded and deployed on the server using the Tomcat Web Application Manager.

Using this knowledge, we can exploit Tomcat with Metasploit by creating a custom malicious
WAR file and deploying a new application. So in msfconsole search for exploit tomcat manager upload.

![image.png](/images/jerry/image8.png)

Use tomcat_mgr_upload. We need to set the following;

- HttpPassword  :   s3cret   (User password that we used to login to manager app)
- HttpUsername :   tomcat  (username that we used to login to manager app)
- RHOSTS  : 10.10.10.95 (remote hosts ip address)
- RPORT : 8080 (remote port)
- LHOSTS : (your local hosts ip address)
- LPORT : port we want to receive a connection on

![image9.png](/images/jerry/image9.png)

Run show options command to finalized the setting. If everything is set then run the exploit command.

![image.png](/images/jerry/image10.png)

Boom…we got the meterpreter session. Let’s find the user flag and root flag.

![image.png](/images/jerry/image11.png)

Both the user flag and root flag is located in the directoery  \Users\Administrator\Desktop\flags

## 2. Learning

- If the host blocking our ping probes, then we should  try -Pn in the nmap command.
- Tomcat is an open-source web server and servlet. The Apache Software Foundation has developed it. It is used widely for hosting Java-based applications on the web. It is built on Java technologies and implements the Java Servlet and JavaServer Pages (JSP) specifications.
- The Manager app in Tomcat is a  web application that allows administrators to manage web applications deployed within the Tomcat server, such as deploying, undeploying, and reloading them.
- Web Application Archive file type is a web application archive, containing a collection of JAR files, JavaServer Pages, Java Servlets, Java classes, XML files, and more.
- I learn that we can use metasploit to upload and deploy into the  tomcat web application manager.
- We get meterperter session, after we have successfully exploit a host.

## 3. Reference List

[Jerry.pdf](/images/jerry/Jerry.pdf)