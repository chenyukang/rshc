#!/usr/bin/expect -f
spawn ssh kang@192.168.3.4
expect "Password:"
send "xx\r"
expect "%"
send "ps -ef |grep nginx\r"
expect "%"
send "exit\r"

