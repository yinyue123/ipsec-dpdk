ipsec pki --gen --outform pem > client.key.pem
ipsec pki --pub --in client.key.pem --outform pem > client.pub.pem
ipsec pki --issue --lifetime 1200 --cacert ca.cert.pem --cakey ca.key.pem --in client.pub.pem --dn "C=CN, O=TZ, CN=Test client" --outform pem > client.cert.pem
# 生成 p12 证书可以设置密码，请注意：OS X 无法导入密码为空的 p12 证书
openssl pkcs12 -export -inkey client.key.pem -in client.cert.pem -name "Test Client Cert" -certfile ca.cert.pem -caname "Test CA" -out client.cert.p12

