#!/bin/bash
num=`sudo cat ../conf/tcpxm.pid`
sudo kill -9 $num

