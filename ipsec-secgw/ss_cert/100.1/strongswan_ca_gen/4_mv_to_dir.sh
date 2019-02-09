mkdir cacerts certs private rest
mv ca.key.pem server.key.pem client.key.pem private
mv server.cert.pem client.cert.pem certs
mv ca.cert.pem cacerts
mv client.cert.p12 client.pub.pem server.pub.pem rest
