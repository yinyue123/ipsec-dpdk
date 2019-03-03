ps -aux | grep 'ipsec-secgw' | awk '{print $2}' | xargs kill -9
