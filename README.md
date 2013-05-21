##tcpxm 基于pylibcap的抓包工具
### 原理
* python开发，调用pylibcap进行抓包
* 3个线程：一个负责抓包并分析内容，一个负责写日志，一个用来清除过期数据

使用tcpdump抓取的数据还需要2次分析，tcpxm可以很方便的抓取和分析tcp请求，打印成需求的日志形式。

我们用它来抓取和分析米聊用户登陆时间，当然可以用它来抓取微信或网站访问等时间，计算用户建立TCP链接时间，第一次发包时间等等

打印的日志类似如下格式：
`2012-09-13 21:25:25 tcpxm.py [line:229] [INFO]  221.179.36.189:3103->xxx.xxx.xxx.xx:2424 [usr:54298295] [login(t6-t0+rtt):2760]  [t1:0] [rtt:217] [t3:137] [t4:0] [t5:118] [t6:2069] [t7:193]`

Login Time = t6（发送<success\>的时间） - t0(收到SYN的时间)  + rtt(估算出的收到SYN包和发送ACK包的路径时间)

具体每个t代表的时间含义如下，日志中的t3 = T3 – T2,  t4 = T4 – T3, rrt(t2) = T2 – T1 ,……

![图片](http://noops.me/wp-content/uploads/2013/05/tcpxm.png)

### 安装
```
git clone git://github.com/xiaomi-sa/tcpxm.git

#安装pylibcap
cd tcpxm/lib/pylibpcap-0.6.4 && python setup.py
```

### 启动
`./tcpxm.py -i eth0 -f "port 80 and not host ip1 and not host ip2“`
具体filter参考pcap `man 7 pcap-filter`

### 注意
* 修改tcpxm.py中`DEBUG = True`，开始调试模式
* 启动tcpxm `./tcpxm.py -i eth0 -f "port 80“` ，并启动一个简单的web server(twisted自带web server)，访问http页面。

抓包本地http 80的 tcp访问

## 联系
siyu#xiaomi.com
