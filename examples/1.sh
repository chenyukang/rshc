spawn ssh yukang@127.0.0.1
expect "Password:"
send "xx\r"
expect "%"
send "ps -ef |grep nginx\r"
expect "%"
send "exit\r"

