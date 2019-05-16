rmmod rte_kni
insmod $RTE_SDK/x86_64-native-linuxapp-gcc/kmod/rte_kni.ko

modprobe uio
insmod $RTE_SDK/x86_64-native-linuxapp-gcc/kmod/igb_uio.ko

echo 384 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages

#mkdir -p /mnt/huge
mount -t hugetlbfs nodev /mnt/huge

grep '/mnt/huge' /proc/mounts

ip link set enp3s0 down
ip link set enp6s0 down
#ip link set enp7s0 down
#ip link set enp8s0 down

#$RTE_SDK/usertools/dpdk-devbind.py -b igb_uio 03:00.0 06:00.0 07:00.0 08:00.0
$RTE_SDK/usertools/dpdk-devbind.py -b igb_uio 03:00.0 06:00.0
