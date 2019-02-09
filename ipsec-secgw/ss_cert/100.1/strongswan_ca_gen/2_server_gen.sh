IP=192.168.100.1
ipsec pki --gen --outform pem > server.key.pem
ipsec pki --pub --in server.key.pem --outform pem > server.pub.pem
ipsec pki --issue --lifetime 1200 --cacert ca.cert.pem --cakey ca.key.pem --in server.pub.pem --dn "C=CN, O=TZ, CN=Test Server" --san="$IP" --flag serverAuth --flag ikeIntermediate --outform pem > server.cert.pem

