ifconfig enp7s0 up
ifconfig enp7s0 10.31.2.254/24
arp -s 10.31.2.1 01:01:01:01:01:01
arp -s 10.31.2.2 01:01:01:01:01:02
arp -s 10.31.2.3 01:01:01:01:01:03
arp -a -n
