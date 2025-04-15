---
title: "Pentest Notes on Linux"
date: "2025-04-16"

layout: ../../layouts/PostLayout.astro
description: "Linux is like a fridge full of ingredients — if you know how to cook, you can make a gourmet meal.If not, you'll just stare at it and order pizza (mac, window)."

img_path : "/images/linux/theme.png"
img_alt: "theme picture"
---

## Linux Structure

- Linux is an operating system used for personal computers, servers, and even mobile devices.
- However, Linux stands as a fundamental pillar in cybersecurity, renowned for its robustness, flexibility, and open-source nature.
- Linux is an operating system, just like Windows, macOS, iOS, or Android.
- An operating system (OS) is software that manages a computer's hardware resources, facilitating communication between software applications and hardware components.
- Linux comes in many different distributions, often called "distros", which are versions of Linux tailored to various needs and preferences.

### History

The history of Linux begins with its precursors in the 1970s and 80s:

- 1970: Ken Thompson and Dennis Ritchie of AT&T released the Unix operating system
- 1977: Berkeley Software Distribution (BSD) emerged but faced legal limitations due to AT&T's Unix code
- 1983: Richard Stallman launched the GNU project to create a free Unix-like OS and developed the GNU General Public License (GPL)

The Linux kernel itself began in 1991 as a personal project by Finnish student Linus Torvalds, who aimed to create a free operating system kernel. Since then, Linux has evolved from a small collection of C files with restrictive licensing to the current version containing over 23 million lines of source code, licensed under GNU GPL v2.

Today, Linux is available in over 600 distributions (including Ubuntu, Debian, Fedora, and Red Hat) and is known for its:

- Enhanced security compared to other operating systems
- Stability and high performance
- Open-source nature allowing modification and distribution
- Wide implementation across servers, desktops, embedded systems, and more

The Android operating system is based on the Linux kernel, making Linux the most widely installed operating system globally. While Linux may have a steeper learning curve for beginners and fewer hardware drivers than Windows, its security, flexibility, and performance have made it foundational to modern computing infrastructure.

### Philosophy

The Linux philosophy centers on simplicity, modularity, and openness. Linux follows five core principles:

| Principle | Description |
| --- | --- |
| Everything is a file | All configuration files for the various services running on the Linux operating system are stored in one or more text files. |
| Small, single-purpose programs | Linux offers many different tools that we will work with, which can be combined to work together. |
| Ability to chain programs together to perform complex tasks | The integration and combination of different tools enable us to carry out many large and complex tasks, such as processing or filtering specific data results. |
| Avoid captive user interfaces | Linux is designed to work mainly with the shell (or terminal), which gives the user greater control over the operating system. |
| Configuration data stored in a text file | An example of such a file is the `/etc/passwd` file, which stores all users registered on the system. |

### Components

| Component | Description |
| --- | --- |
| **Bootloader** | A piece of code that runs to guide the booting process to start the operating system. Parrot Linux uses the GRUB Bootloader. |
| **OS Kernel** | The kernel is the main component of an operating system. It manages the resources for system's I/O devices at the hardware level. |
| **Daemons** | Background services are called "daemons" in Linux. Their purpose is to ensure that key functions such as scheduling, printing, and multimedia are working correctly. These small programs load after we boot or log into the computer. |
| **OS Shell** | The operating system shell or the command language interpreter (also known as the command line) is the interface between the OS and the user. This interface allows the user to tell the OS what to do. The most commonly used shells are Bash, Tcsh/Csh, Ksh, Zsh, and Fish. |
| **Graphics Server** | This provides a graphical sub-system (server) called "X" or "X-server" that allows graphical programs to run locally or remotely on the X-windowing system. |
| **Window Manager** | Also known as a graphical user interface (GUI). There are many options, including GNOME, KDE, MATE, Unity, and Cinnamon. A desktop environment usually has several applications, including file and web browsers. These allow the user to access and manage the essential and frequently accessed features and services of an operating system. |
| **Utilities** | Applications or utilities are programs that perform particular functions for the user or another program. |

### Linux Architecture

The Linux operating system can be broken down into layers:

| Layer | Description |
| --- | --- |
| **Hardware** | Peripheral devices such as the system's RAM, hard drive, CPU, and others. |
| **Kernel** | The core of the Linux operating system whose function is to virtualize and control common computer hardware resources like CPU, allocated memory, accessed data, and others. The kernel gives each process its own virtual resources and prevents/mitigates conflicts between different processes. |
| **Shell** | A command-line interface (CLI), also known as a shell, that a user can enter commands into to execute the kernel's functions. |
| **System Utility** | Makes available to the user all of the operating system's functionality. |

### File System Hierarchy

Linux is structured with the following standard top-level directories:

| Path | Description |
| --- | --- |
| **/** | The top-level directory is the root filesystem and contains all of the files required to boot the operating system before other filesystems are mounted, as well as the files required to boot the other filesystems. After boot, all of the other filesystems are mounted at standard mount points as subdirectories of the root. |
| **/bin** | Contains essential command binaries. |
| **/boot** | Consists of the static bootloader, kernel executable, and files required to boot the Linux OS. |
| **/dev** | Contains device files to facilitate access to every hardware device attached to the system. |
| **/etc** | Local system configuration files. Configuration files for installed applications may be saved here as well. |
| **/home** | Each user on the system has a subdirectory here for storage. |
| **/lib** | Shared library files that are required for system boot. |
| **/media** | External removable media devices such as USB drives are mounted here. |
| **/mnt** | Temporary mount point for regular filesystems. |
| **/opt** | Optional files such as third-party tools can be saved here. |
| **/root** | The home directory for the root user. |
| **/sbin** | This directory contains executables used for system administration (binary system files). |
| **/tmp** | The operating system and many programs use this directory to store temporary files. This directory is generally cleared upon system boot and may be deleted at other times without any warning. |
| **/usr** | Contains executables, libraries, man files, etc. |
| **/var** | This directory contains variable data files such as log files, email in-boxes, web application related files, cron files, and more. |

## Linux Distributions

Linux distributions are operating systems built on the Linux kernel, each tailored for specific purposes like desktops, servers, mobile, or cybersecurity. Though they share core components and structure, each distro offers unique tools, packages, and user experiences.

Popular distros include **Ubuntu, Fedora, CentOS, Debian, Red Hat**, and **Kali Linux**. Desktop users often prefer **Ubuntu** and **Fedora** for their ease of use, while **Kali Linux** is widely used in cybersecurity for its pre-installed security tools.

**Debian**, known for its **stability, security, and long-term support**, is used in desktops, servers, and embedded systems. While it may be complex for beginners, it offers great control and customization, making it ideal for advanced users and cybersecurity professionals.

Linux distros are used across many fields—servers, embedded systems, cloud computing, and cybersecurity—because they are **open-source, secure, reliable, and customizable**.

## Shell

A Linux terminal, also called a shell or command line, provides a text-based input/output (I/O) interface between users and the kernel for a computer system.

![image](/images/linux/terminal.png)

We can think of a shell as a text-based GUI in which we enter commands to perform actions like navigating to other directories, working with files, and obtaining information from the system but with
way more capabilities.

### Terminal Emulators

Terminal emulation is software that emulates the function of a terminal. A terminal serves as an interface to the shell interpreter. The terminal serves as your gateway to communicate with and control the core operations managed by the shell. Terminal emulators and multiplexers are beneficial extensions for the terminal. They provide us with different methods and functions to work
with the terminal, such as splitting the terminal into one window, working in multiple directories, creating different workspaces, and much more.

### Shell

The most commonly used shell in Linux is the Bourne-Again Shell (BASH), and is part of the GNU project. Everything we do through the GUI we can do with the shell. The shell gives us many more possibilities to interact with programs and processes to get information faster. Besides, many processes can be easily automated with smaller or larger scripts that make manual work much easier. Besides Bash, there also exist other shells like Tcsh/Csh, Ksh, Zsh, Fish shell and others.

## Prompt Description

The Bash prompt is a simple line of text that appears when the system is ready for a command. By default, it displays your **username**, **computer name (hostname)**, and **current directory**. The **cursor** appears right after the prompt, waiting for you to enter a command.

The format can look something like this:

```
<username>@<hostname><current working directory>$
```

![image](/images/linux/terminal.png)

The home directory for a user is marked with a tilde <~> and is the default folder when we log in.

The dollar sign, in this case, stands for a user. As soon as we log in as root, the character changes to a hash <#> and looks like this:

```
root@htb[/htb]#
```

## Manual Page

In the man pages, we will find the detailed manuals with detailed explanations. The `ls` command in Linux and Unix systems is used to list the files and directories within the current folder or any specified directory, allowing you to see what's inside and manage files more effectively.

To discover which options a tool or command offers, there are several ways to get help. One such method is using the man command, which displays the manual pages for commands and provides detailed information about their usage.

Let us have a look at an example and get help for the ls command:

```
tshering@linux-os:~$ man ls
```

![image](/images/linux/man.png)

After looking at some examples, we can also quickly look at the optional parameters without browsing through the complete documentation. We have several ways to do that.

![image](/images/linux/help.png)
