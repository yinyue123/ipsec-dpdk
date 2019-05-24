echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 192.168.11.0/24 -o enp2s0 -j MASQUERADE
