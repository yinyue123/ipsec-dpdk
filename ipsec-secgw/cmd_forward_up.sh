# Turn on IP forwarding
sysctl -w net.ipv4.ip_forward=1
service firewalld start
sleep 10
iptables -t nat -F
iptables -t nat -X

# turn on NAT over eth0 and VPN
iptables -t nat -A POSTROUTING -s 10.31.2.0/24 -o enp7s0 -j MASQUERADE
iptables -A FORWARD -i enp2s0 -o enp7s0 -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -i enp7s0 -o enp2s0 -j ACCEPT

# turn on MSS fix
# MSS = MTU - TCP header - IP header
iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1300

iptables -t nat -nL
