ipsec pki --gen --outform pem > ca.key.pem
ipsec pki --self --in ca.key.pem --dn "C=CN, O=TZ, CN=Test CA" --ca --lifetime 3650 --outform pem > ca.cert.pem

