<img src="ksc-defender.png" width="50%" height="50%"/>

----------

##  ksc-defender介绍

ksc-defender是一款操作系统安全加固的终端工具应用。采用多安全机制联合框架，提供对数据文件、访问机制、联网控制、系统加固等多方面的系统保护，并支持系统级漏洞扫描、入侵检测和杀毒软件等安全生态应用的联动。
支持操作系统：openEuler 21.09 创新版/LTS及以上版本，目前支持账户安全、防火墙和病毒防护几个模块。

欢迎开源爱好者加入进来，共同打造一款可插拔、可扩展、更易用的系统安全工具框架。

一、安装ksc-defender
----------

### 前期准备：安装ClamAV

ksc-defender的病毒防护模块当前是依赖于ClamAV开源反病毒软件包的API库实现的，需要首先下载安装ClamAV。

#### 1、下载ClamAV版本

从ClamAV的官方下载地址：http://www.clamav.net/download.html  下载最新版，例如当前版本clamav-0.103.2.tar.gz。

#### 2、安装依赖包

```bash
 yum install openssl-devel -y
 yum install libcurl-devel -y
```
#### 3、编译安装Clamav

```bash
tar xf clamav-0.103.2.tar.gz
cd clamav-0.103.2
./configure --disable-clamav
make install

cat /etc/ld.so.conf
echo "/usr/local/lib64" >> /etc/ld.so.conf
ldconfig
```
### 方法一（适用于普通用户）：安装openEuler默认自带的ksc-defender

```bash
yum install ksc-defender
```
### 方法二（适用于开发者）：从本仓库源码安装

#### 1、安装依赖系统软件包

```bash
yum install cmake gcc-c++ libpwquality-devel libxml2-devel sqlite-devel
```
#### 2、编译源码

```bash
mkdir build
cmake ../src
make clean
make
```
生成的可执行程序在build目录下的ksc-defender。

#### 3、安装

```bash
make install
```

二、快速使用指南
----------

查看安全中心功能模块，运行示例

```bash
ksc-defender --help
```
### 1、账户安全

账户安全包括账户锁定和密码强度两个部分。

查看账户锁定功能，运行示例：

```bash
ksc-defender --account --help
```
查看账户锁定和密码设置信息，运行示例：

```bash
ksc-defender --account --status
```

#### 1.1、账户锁定

通过以下命令可以设置账户锁定策略，保护账户安全。提供账户登录失败次数和时间阈值的选择。用户连续登录失败后将被锁定，一段时间（时间阈值）内无法登录。

启用登录锁定，运行示例：

```bash
ksc-defender --account --lock on  
```
设置登录失败次数阈值为3 次，运行示例：

```bash
ksc-defender --account --lock_deny 3 
```
设置登录锁定的时间为1分钟，运行示例：

```bash
ksc-defender --account --lock_time 1  
```
#### 1.2、密码安全


通过以下命令提供账户密码查看与安全级别设置功能。

启用密码设置，运行示例：

```bash
ksc-defender --account --pwd on  
```
可设置当前密码安全的级别为预设级别 - 推荐（default）自定义（custom），运行示例：

```bash
ksc-defender --account --pwd_set default 
```
查看当前密码设置详细信息，运行示例：

```bash
ksc-defender --account --pwd_get
```
自定义密码复杂度设置（custom）会弹出二级菜单项，运行示例：

```bash
ksc-defender --account  --pwd_set custom 
```
- SUBMENU

| 参数                  | 描述                                                         |
| ----------------  | ------------------------------------------------------------ |
| --ls                    | 查看当前设置的自定义子菜单项                                          |
| --minlen       | 设置密码最小长度                               |
| --minclass      | 设置密码至少包含字符种类                                   |
| --usercheck        | 设置密码用户名检查                                |
| --dictcheck      | 设置密码最字典检查                                |
| --limitdays | 设置密码有效时间 （limitday为0，表示永久）                              |
| --warnday  | 设置密码过期前提醒天数  （limitday为0，warnday项隐藏）                               |
| --exit  | 退出自定义菜单不保存                                |
| --apply  | 退出自定义菜单并应用                                |
| --help  | 弹出自定义设置子菜单项                                |

### 2、网络安全

通过以下命令可以对麒麟防火墙的基本功能进行设置，包括public、work和custom三种模式。

查看当前麒麟防火墙功能模块，运行示例：

```bash
ksc-defender --firewall --help
```
开启麒麟防火墙，运行示例：

```bash
ksc-defender --firewall --enable
```
关闭麒麟防火墙，运行示例：

```bash
ksc-defender --firewall --disable
```
查看当前麒麟防火墙状态，运行示例：

```bash
ksc-defender --firewall --status
```

设置防火墙安全策略为公共网络，运行示例：

```bash
ksc-defender --firewall --policy public
```
设置防火墙安全策略为自定义网络，会弹出二级菜单，运行示例：

```bash
ksc-defender --firewall --policy custom
```

- SUBMENU

| 参数                  | 描述                                                         |
| ----------------  | ------------------------------------------------------------ |
| --ls                    | 查看当前设置的自定义子菜单项                                          |
| --del[index/all]      | 删除策略                               |
| --add[portocol&port]      | 通过协议和端口添加规则                                   |
| --exit  | 退出自定义菜单不保存                                |
| --apply  | 退出自定义菜单并应用                                |
| --help  | 弹出自定义设置子菜单项                                |

### 3、病毒防护

通过以下命令可以对执行防病毒的相关操作。

查看病毒扫描功能，运行示例：

```bash
ksc-defender --antivirus  --help
```

更新病毒特征库（首次进行病毒扫描之前必须要先下载更新病毒库），运行示例：

```bash
ksc-defender --antivirus --update
```
对指定文件/目录或默认位置进行病毒扫描，运行示例：

```bash
ksc-defender --antivirus  --scan [file/dir]
```
查看病毒扫描日志，运行示例：

```bash
ksc-defender --antivirus  --status
```
进入病毒处理子菜单，运行示例：

```bash
ksc-defender --antivirus  --deal
```
- SUBMENU

| 参数                  | 描述                                                         |
| ----------------  | ------------------------------------------------------------ |
| --ls  [index]                  | 查看当前设置的自定义子菜单项                                          |
| --del[index/all/db]       | 删除病毒                               |
| --iso[index/all]      | 隔离病毒                                   |
| --res[index/all]  | 恢复病毒                                |
| --exit  | 退出自定义菜单                              |
| --help  | 显示自定义设置子菜单项                                |

三、如何贡献
----------
我们非常欢迎新贡献者加入到项目中来，也非常高兴能为新加入贡献者提供指导和帮助。在您贡献代码前，需要先签署[CLA](https://openeuler.org/en/cla.html)。

### 会议
每双周周五上午10:00-12:00召开SIG组例会。


四、联系方式
----------

如果您有任何疑问或讨论，请通过邮件和我们进行联系。

功能需求：<zhangzixue@kylinos.cn>

研发问题：<liu_yi@kylinos.cn> 

代码问题：<zhengtingting@kylinos.cn> 












----------
