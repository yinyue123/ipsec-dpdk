
ifconfig vEth0 192.168.100.1/24
sleep 1
ifconfig vEth0 up
ifconfig vEth0 mtu 1450
ifconfig vEth0 hw ether 00:11:22:33:44:55
ifconfig vEth0
ping -c 10 192.168.100.2
