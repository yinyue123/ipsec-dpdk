#./build/app/ipsec-secgw --master-lcore 0 -l 0,1 -n 1 --socket-mem=512,0 --file-prefix=qat -w 03:00.0 -w 06:00.0 -w 07:00.0 -w 08:00.0 -- -p 0xf -P -u 0x03 --config="(0,0,0),(1,0,1),(2,0,0),(3,0,1)" -f ipsec_secgw_rules.cfg
#./build/app/ipsec-secgw --master-lcore 0 -l 0,1 -n 1 --socket-mem=384,0 --vdev "cryptodev_null_pmd" -w 03:00.0 -w 06:00.0 -w 07:00.0 -w 08:00.0 -- -k 0x2 -p 0xf -P -u 0x03 --config="(0,0,0),(1,0,0),(2,0,0),(3,0,0)" -f ipsec_secgw_rules.cfg
#./build/app/ipsec-secgw --master-lcore 0 -l 0,1 -n 1 --socket-mem=384,0 --vdev "cryptodev_null_pmd" -w 03:00.0 -w 06:00.0 -w 07:00.0 -w 08:00.0 -- -k 0x1 -p 0xf -P -u 0x01 --config="(0,0,0),(1,0,0),(2,0,0),(3,0,0)" -f ipsec_secgw_rules.cfg
#./build/app/ipsec-secgw --master-lcore 0 -l 0,1 -n 1 --socket-mem=384,0 --vdev "cryptodev_null_pmd" -w 03:00.0 -w 06:00.0 -- -k 0x1 -p 0x3 -P -u 0x01 --config="(0,0,0),(1,0,0)" -f ipsec-test.cfg
#./build/app/ipsec-secgw --master-lcore 0 -l 0,1 -n 1 --socket-mem=512,0 --vdev "crypto_aesni_mb" -w 03:00.0 -w 06:00.0 -- -k 0x1 -p 0x3 -P -u 0x01 --config="(0,0,0),(1,0,0)" -f ipsec-test.cfg
#./build/app/ipsec-secgw --master-lcore 0 -l 0,1 -n 1 --socket-mem=512,0 --vdev "crypto_aesni_mb_pmd" -w 03:00.0 -w 06:00.0 -- -k 0x1 -p 0x3 -P -u 0x01 --config="(0,0,0),(1,0,0)" -f ipsec-test.cfg
#./build/app/ipsec-secgw --master-lcore 0 -l 0,1 -n 1 --socket-mem=512,0 --vdev "crypto_openssl" -w 03:00.0 -w 06:00.0 -- -k 0x1 -p 0x3 -P -u 0x01 --config="(0,0,0),(1,0,0)" -f ipsec-test.cfg
#./build/app/ipsec-secgw --master-lcore 0 -l 0,1 -n 1 --socket-mem=512,0 --vdev "cryptodev_openssl_pmd" -w 03:00.0 -w 06:00.0 -- -k 0x1 -p 0x3 -P -u 0x01 --config="(0,0,0),(1,0,0)" -f ipsec-test.cfg
#./build/app/ipsec-secgw --master-lcore 0 -l 0,1 -n 1 --socket-mem=512,0 --vdev "crypto_aesni_mb,socket_id=0,max_nb_sessions=128" -w 03:00.0 -w 06:00.0 -- -k 0x1 -p 0x3 -P -u 0x01 --config="(0,0,0),(1,0,0)" -f ipsec-test.cfg
#./build/app/ipsec-secgw --master-lcore 0 -l 0,1 -n 1 --socket-mem=512,0 --vdev "crypto_null" -w 03:00.0 -w 06:00.0 -- -k 0x1 -p 0x3 -P -u 0x01 --config="(0,0,0),(1,0,0)" -f ipsec-test.cfg
#./build/app/ipsec-secgw --master-lcore 0 -l 0,1 -n 1 --socket-mem=512,0 --vdev "crypto_openssl" -w 03:00.0 -w 06:00.0 -- -k 0x1 -p 0x3 -P -u 0x01 --config="(0,0,0),(1,0,0)" -f ipsec-test.cfg
./build/app/ipsec-secgw --master-lcore 0 -l 0,1 -n 1 --socket-mem=512,0 --vdev "crypto_openssl" -w 03:00.0 -w 06:00.0 -- -k 0x1 -p 0x3 -P -u 0x01 --config="(0,0,0),(1,0,1)" -f ipsec-test.cfg
