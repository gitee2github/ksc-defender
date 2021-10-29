![](https://gitee.com/openeuler/G11N/raw/master/learning-materials/open-source-basics/images/ksc-defender.png)
----------
## Introduction to KSC-Defender

KSC-Defender is a terminal tool for OS security hardening. It adopts a joint framework of multiple security mechanisms to provide systematic protection for data files, access mechanisms, network control, and system hardening, and supports the linkage of security ecosystem applications such as system-level vulnerability scanning, intrusion detection, and antivirus software. KSC-Defender can be used on openEuler 21.09 and LTS or later versions. Currently, it supports the account security, firewall, and antivirus modules.

Open source enthusiasts are welcome to join us to build a pluggable, scalable, and easy-to-use system security tool framework.

## Installing KSC-Defender

### Preparations: Installing ClamAV

The antivirus module of KSC-Defender depends on the API library of the ClamAV open source antivirus software package. You need to download and install ClamAV first.

#### 1. Download the ClamAV software package.

Download the latest version of ClamAV from [http://www.clamav.net/download.html](http://www.clamav.net/download.html), for example, **clamav-0.103.2.tar.gz**.

#### 2. Install the dependency packages.

```
 yum install openssl-devel -y
 yum install libcurl-devel -y
```
#### 3. Build and install ClamAV.

```
tar xf clamav-0.103.2.tar.gz
cd clamav-0.103.2
./configure --disable-clamav
make install

cat /etc/ld.so.conf
echo "/usr/local/lib64" >> /etc/ld.so.conf
ldconfig
```
### Method 1 (for common users): Install the default KSC-Defender provided by openEuler.

```
yum install ksc-defender
```
### Method 2 (for developers): Use the source code in this repository for installation.

#### 1. Install the dependent system software package.

```
yum install cmake gcc-c++ libpwquality-devel libxml2-devel sqlite-devel
```
#### 2. Build the source code.

```
mkdir build
cmake ../src
make clean
make
```
The generated executable program is ksc-defender in the build directory.

#### 3. Perform the installation.

```
make install
```

## Quick Start Guide

Check the function modules in the security center. The following is a command example:

```
ksc-defender --help
```
### 1. Account Security

Account security covers account locking and password strength.

Check the account locking function. The following is a command example:

```
ksc-defender --account --help
```
View the account locking and password setting information. The following is a command example:

```
ksc-defender --account --status
```

#### 1.1 Account Locking

You can set the account locking policy, the maximum number of login failures, and the time threshold to ensure account security. After consecutive login failures, a user is locked and cannot log in to the system for a period of time (time threshold).

Enable login locking. The following is a command example:

```
ksc-defender --account --lock on  
```
Set the maximum number of login failures to 3. The following is a command example:

```
ksc-defender --account --lock_deny 3 
```
Set the login locking duration to 1 minute. The following is a command example:

```
ksc-defender --account --lock_time 1  
```
#### 1.2 Password Security

You can view the password of an account and set the security level.

Enable password setting. The following is a command example:

```
ksc-defender --account --pwd on  
```
Set the current password security level to the preset level: recommended level (default) or a customized level (custom). The following is a command example:

```
ksc-defender --account --pwd_set default 
```
View the detailed information about the current password. The following is a command example:

```
ksc-defender --account --pwd_get
```
A submenu is displayed when you customize the password complexity settings (custom). The following is a command example:

```
ksc-defender --account  --pwd_set custom 
```
- Submenu

| Parameter   | Description                                                  |
| ----------- | ------------------------------------------------------------ |
| --ls        | Views the customized submenu that is currently set.          |
| --minlen    | Sets the minimum password length.                            |
| --minclass  | Sets the minimum number of character types that a password must contain. |
| --usercheck | Sets user name and password checks.                          |
| --dictcheck | Sets the password dictionary check.                          |
| --limitdays | Sets the password validity period. (If **limitday** is set to **0**, the password is permanently valid.) |
| --warnday   | Sets the number of days in advance users are notified that their passwords are about to expire. (If **limitday** is set to **0**, and the **warnday** item is hidden.) |
| --exit      | Exits the customized menu and does not save the settings.    |
| --apply     | Exits the customized menu and applies the settings.          |
| --help      | Displays the customized setting submenu.                     |

### 2. Cyber Security

You can set basic functions of the Kirin firewall, including the public, work, and custom modes.

Check the current Kylin firewall function module. The following is a command example:

```
ksc-defender --firewall --help
```
Enable the Kirin firewall. The following is a command example:

```
ksc-defender --firewall --enable
```
Disable the Kirin firewall. The following is a command example:

```
ksc-defender --firewall --disable
```
Check the Kylin firewall status. The following is a command example:

```
ksc-defender --firewall --status
```

Set the firewall security policy to the public network. The following is a command example:

```
ksc-defender --firewall --policy public
```
Set the firewall security policy to a customized network. A submenu is displayed. The following is a command example:

```
ksc-defender --firewall --policy custom
```

- Submenu

| Parameter            | Description                                               |
| -------------------- | --------------------------------------------------------- |
| --ls                 | Views the customized submenu that is currently set.       |
| --del[index/all]     | Deletes a policy.                                         |
| --add[portocol&port] | Adds a rule based on the protocol and port number.        |
| --exit               | Exits the customized menu and does not save the settings. |
| --apply              | Exits the customized menu and applies the settings.       |
| --help               | Displays the customized setting submenu.                  |

### 3. Antivirus

You can run the following commands to perform antivirus-related operations.

Check the virus scanning function. The following is a command example:

```
ksc-defender --antivirus  --help
```

Update the antivirus signature database (download and update the database before the first virus scanning). The following is a command example:

```
ksc-defender --antivirus --update
```
Scan for viruses in a specified file/directory or in the default location. The following is a command example:

```
ksc-defender --antivirus  --scan [file/dir]
```
View virus scanning logs. The following is a command example:

```
ksc-defender --antivirus  --status
```
Enter the virus processing submenu. The following is a command example:

```
ksc-defender --antivirus  --deal
```
-Submenu

| Parameter           | Description                                         |
| ------------------- | --------------------------------------------------- |
| --ls  [index]       | Views the customized submenu that is currently set. |
| --del[index/all/db] | Deletes viruses.                                    |
| --iso[index/all]    | Isolates viruses.                                   |
| --res[index/all]    | Restores viruses.                                   |
| --exit              | Exits the customized menu.                          |
| --help              | Displays the customized setting submenu.            |

## Contributions

We welcome new contributors to join the project and are very pleased to provide guidance and help. Before you commit your code, sign the [CLA](https://openeuler.org/en/cla.html) first.

### Conferences
The regular meeting of the SIG team is held every two weeks from 10:00 a.m. to 12:00 a.m. on Friday.

## Contact Information

If you have any questions or discussions, please contact us using emails.

Function requirements: <zhangzixue@kylinos.cn>

R&D issues: <liu_yi@kylinos.cn>

Code problem: <zhengtingting@kylinos.cn>

----------