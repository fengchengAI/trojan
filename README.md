# trojan

[![Build Status](https://dev.azure.com/GreaterFire/Trojan-GFW/_apis/build/status/trojan-gfw.trojan?branchName=master)](https://dev.azure.com/GreaterFire/Trojan-GFW/_build/latest?definitionId=5&branchName=master)

An unidentifiable mechanism that helps you bypass GFW.

Trojan features multiple protocols over `TLS` to avoid both active/passive detections and ISP `QoS` limitations.

Trojan is not a fixed program or protocol. It's an idea, an idea that imitating the most common service, to an extent that it behaves identically, could help you get across the Great FireWall permanently, without being identified ever. We are the GreatER Fire; we ship Trojan Horses.

## Documentations

An online documentation can be found [here](https://trojan-gfw.github.io/trojan/).  
Installation guide on various platforms can be found in the [wiki](https://github.com/trojan-gfw/trojan/wiki/Binary-&-Package-Distributions).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Dependencies

- [CMake](https://cmake.org/) >= 3.7.2
- [Boost](http://www.boost.org/) >= 1.66.0
- [OpenSSL](https://www.openssl.org/) >= 1.1.0
- [libmysqlclient](https://dev.mysql.com/downloads/connector/c/)





## 图解

参考[Trojan原理简单分析](https://renyili.org/post/trojan_principle_analysis/)

![wHdTZn.png](https://s1.ax1x.com/2020/09/21/wHdTZn.png)







![wHwkRO.png](https://s1.ax1x.com/2020/09/21/wHwkRO.png)



## 代码改动

在本项目中主要做的工作就是简化了项目，使得项目可以以最简单的方式运行client和service服务。由于目前大多数网页并不支持UDP协议，所以删去了所有有关UDP的代码，并为了简化验证阶段，删去了mysql服务。本项目核心为session，即client和service。实际上forward，client，service都很相似。且由于本人并不熟悉nat，并没有该需求，所以不做解释。实际上forward是类似于client的，且比client简单，理解好client就可以更好理解service和forward。

config中，主要将写log改为ofsream，并加入了`ENABLE_LOG`以开启log功能，

service主要是配置ssl，这里本人并不熟悉，不做解释

main中本人加入了路径转化的代码

本人在client和service中的in_async_write中，删掉了将读取数据包装成智能指针的代码，因为发现在实际中，data并不会失效，所以不需要包装

且将in_async_write和out_async_write声明为char，这样在out_recv阶段，就不需要强制转换

删去啦`first_packet_recv`的判断，因为该判断一直为真

最主要的是在destroy时，将socket的关闭改为异步延迟关闭



使用前，需要修改CMakeList.txt中的

```shell
set(DEFAULT_CONFIG /usr/local/etc/trojan/buy.json CACHE STRING "Default config path")
```



## 源码解读

| Client 状态 | <span style="display:inline-block;width:550px">备注</span>   |
| ----------- | ------------------------------------------------------------ |
| HANDSHAKE   | 这里是http的握手阶段，读取本地浏览器内容，并判断data的合法性。这个data是三个字符，其ASCII数对应为510,判断正确后，将50发送给浏览器，状态进入REQUEST |
|REQUEST|读取本地浏览器请求，继续判断合法性(data[0]=5,data[2]=0,从第四位开始为http地址即data.substr(3))。如果判断成功，则用密码构成异构trojan头信息，并加上读取到的真实data请求，即data.substr(3)，这个data.substr(3)是包含地址端口的。 此时这个trojan数据存在out_write_buf中给本地浏览器发送5001000000,并转入CONNECT阶段。|
|CONNECT|读取本地浏览器数据，将读取的数据加在out_write_buf上，然后解析远程服务器(自己申请的域名)，并链接握手async_resolve,async_connect,async_handshake,然后状态进入FORWARD|
|FORWARD|读取远程服务器数据，并发送给本地浏览器，一直重复。（上面的操作，应该只是一些头信息，或者握手，下面是真正的请求）。将CONNECT阶段的out_write_buf发送给远程服务器，并读取远程服务器，然后发送给本地浏览器。重复。这里是在ssl保护下的传输|

| SERVICE状态 | <span style="display:inline-block;width:550px">备注</span>   |
| ----------- | ------------------------------------------------------------ |
| HANDSHAKE   | 先进行CLIENT握手，然后读取client数据，判断data数据是否包含trojan头信息，并判断密码的合法性，然后解析。如果为真，则表示是trojan请求，将troajn中的真实请求地址(去掉trojan头信息作为解析地址，即真实请求地址)赋值给out_write_buf; 如果为假，则表示这是一个正常的请求，直接将读取到的数据data赋值给out_write_buf（不用去除trojan头）。进入FORWARD |
| FORWARD     | 将解析的地址(eg: www.google.com:443)的数据发送给client，然后将从client读取的数据，即(out_write_buf),发送给真实请求地址(eg: www.google.com:443) |



## trojan



这里的密码是经过加密的，CRLF是空格回车，Trojan Request是REQUEST阶段读取到的真实请求，Payload是CONNECT阶段读取到的

```
+-----------------------+---------+----------------+---------+----------+
| hex(SHA224(password)) |  CRLF   | Trojan Request |  CRLF   | Payload  |
+-----------------------+---------+----------------+---------+----------+
|          56           | X'0D0A' |    Variable    | X'0D0A' | Variable |
+-----------------------+---------+----------------+---------+----------+
```