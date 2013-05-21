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
cd tcpxm/lib/pylibpcap-0.6.4 && sudo python setup.py install
```

### 启动
`sudo ./tcpxm.py -i eth0 -f "port 80 and not host ip1 and not host ip2“`
具体filter参考pcap `man 7 pcap-filter`

## 测试
因为还没有做成可配置，所以代码里面是抓取米聊login时间，匹配到`<success/>`后完成一次tcp请求的记录。

测试时，可以修改成DEBUG模式，它匹配到`Content-Type`，完成一次记录

### 步骤
1. 修改tcpxm.py中`DEBUG = True`
1. 启动一个简单的twisted web, `sudo twistd web --path=/home/work/tcpxm/ -p 80`, 在浏览器中使用ip访问本机80端口，默认会展现tcpxm/index.html
1. 启动tcpxm `sudo ./tcpxm.py -i eth0 -f "port 80“` ，访问http页面，查看log/日志记录

抓包本地http 80的 tcp访问

## 联系
siyu#xiaomi.com
