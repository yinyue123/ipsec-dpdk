cd /root/pktgen-dpdk-pktgen-3.1.2
#./pktgen --master-lcore 1 -c 0x3 -n 1 -w 01:00.0 -w 02:00.0 --socket-mem=128,0 -- file-prefix=dpdk_pktgen -- -P -T -m '[0:1].0,[0:1].1'
./pktgen --master-lcore 1 -c 0x3 -n 1 -w 03:00.0 -w 04:00.0 --socket-mem=128,0 -- file-prefix=dpdk_pktgen -- -P -T -m '[0:1].0,[0:1].1'
