//
// Created by 殷悦 on 26/01/2019.
//

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>

#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_kni.h>
#include <rte_ip.h>

#include "kni.h"

#define RTE_LOGTYPE_IPSEC RTE_LOGTYPE_USER1

/* Max size of a single packet */
#define MAX_PACKET_SZ           2048

/* Number of mbufs in mempool that is created */
#define NB_MBUF                 8192

/* How many packets to attempt to read from NIC in one go */
#define PKT_BURST_SZ            32

/* How many objects (mbufs) to keep in per-lcore mempool cache */
#define MEMPOOL_CACHE_SZ        256

/* Total octets in ethernet header */
#define KNI_ENET_HEADER_SIZE    14

/* Total octets in the FCS */
#define KNI_ENET_FCS_SIZE       4

struct kni_port_params {
	uint16_t port_id;/* Port ID */
	struct rte_kni *kni; /* KNI context pointers */
} __rte_cache_aligned;

static struct kni_port_params *kni_port_params_array[RTE_MAX_ETHPORTS];

static uint32_t ports_mask = 0;

/* Mempool for mbufs */
static struct rte_mempool **pktmbuf_pool = NULL;

static struct rte_eth_conf *port_conf = NULL;

static int kni_change_mtu(uint8_t port_id, unsigned new_mtu);

static int kni_config_network_interface(uint8_t port_id, uint8_t if_up);

static void
kni_burst_free_mbufs(struct rte_mbuf **pkts, unsigned num) {
	unsigned i;

	if (pkts == NULL)
		return;

	for (i = 0; i < num; i++) {
		rte_pktmbuf_free(pkts[i]);
		pkts[i] = NULL;
	}
}

int
check_kni_data(struct rte_mbuf *pkt) {
	struct ipv4_hdr *ip_hdr;
	ip_hdr = rte_pktmbuf_mtod_offset(pkt,
	struct ipv4_hdr *, sizeof(struct ether_hdr));
	if (ip_hdr->next_proto_id == IPPROTO_ESP) {
		//printf("return 0");
		return 0;
	}
	//printf("return 1");
	return 1;
}

void
send_to_kni(uint8_t port_id, struct rte_mbuf **pkts, uint32_t nb_rx) {
	unsigned num;
	//printf("send_to_kni\n");
	num = rte_kni_tx_burst(kni_port_params_array[port_id]->kni, pkts, nb_rx);
	rte_kni_handle_request(kni_port_params_array[port_id]->kni);
	if (unlikely(num < nb_rx)) {
		/* Free mbufs not tx to kni interface */
		kni_burst_free_mbufs(&pkts[num], nb_rx - num);
	}
}

void
forward_from_kni_to_eth(uint16_t tx_queue_id, uint8_t port_id) {
	uint16_t nb_tx, num;
	struct rte_mbuf *pkts_burst[PKT_BURST_SZ];
	num = rte_kni_rx_burst(kni_port_params_array[port_id]->kni, pkts_burst, PKT_BURST_SZ);
	if (likely(num)) {
		//printf("forward_from_kni_to_eth\n");
		nb_tx = rte_eth_tx_burst(port_id, tx_queue_id, pkts_burst, num);
		if (unlikely(nb_tx < num))
			kni_burst_free_mbufs(&pkts_burst[nb_tx], num - nb_tx);
	}
}

static void
print_config(void) {
	uint32_t i;
	struct kni_port_params **p = kni_port_params_array;

	for (i = 0; i < RTE_MAX_ETHPORTS; i++) {
		if (!p[i])
			continue;
		RTE_LOG(DEBUG, IPSEC, "Kni Port ID: %d\n", p[i]->port_id);
	}
}

/* Initialize KNI subsystem */
static void
init_kni(void) {
	unsigned int num_of_kni_ports = 0, i;

	/* Calculate the maximum number of KNI interfaces that will be used */
	for (i = 0; i < RTE_MAX_ETHPORTS; i++) {
		if (kni_port_params_array[i])
			num_of_kni_ports++;
	}
	printf("%d--------------------\n", num_of_kni_ports);
	/* Invoke rte KNI init to preallocate the ports */
	rte_kni_init(num_of_kni_ports);
}

//不用改，在kni_alloc中
/* Callback for request of changing MTU */
static int
kni_change_mtu(uint8_t port_id, unsigned new_mtu) {
	int ret;
	struct rte_eth_conf conf;

	if (port_id >= rte_eth_dev_count()) {
		RTE_LOG(ERR, IPSEC, "Invalid port id %d\n", port_id);
		return -EINVAL;
	}

	RTE_LOG(INFO, IPSEC, "Change MTU of port %d to %u\n", port_id, new_mtu);

	/* Stop specific port */
	rte_eth_dev_stop(port_id);

	memcpy(&conf, port_conf, sizeof(conf));
	/* Set new MTU */
	if (new_mtu > ETHER_MAX_LEN)
		conf.rxmode.jumbo_frame = 1;
	else
		conf.rxmode.jumbo_frame = 0;

	/* mtu + length of header + length of FCS = max pkt length */
	conf.rxmode.max_rx_pkt_len = new_mtu + KNI_ENET_HEADER_SIZE +
								 KNI_ENET_FCS_SIZE;
	ret = rte_eth_dev_configure(port_id, 1, 1, &conf);
	if (ret < 0) {
		RTE_LOG(ERR, IPSEC, "Fail to reconfigure port %d\n", port_id);
		return ret;
	}

	/* Restart specific port */
	ret = rte_eth_dev_start(port_id);
	if (ret < 0) {
		RTE_LOG(ERR, IPSEC, "Fail to restart port %d\n", port_id);
		return ret;
	}

	return 0;
}

//不用改，在kni_alloc中
/* Callback for request of configuring network interface up/down */
static int
kni_config_network_interface(uint8_t port_id, uint8_t if_up) {
	int ret = 0;

	if (port_id >= rte_eth_dev_count() || port_id >= RTE_MAX_ETHPORTS) {
		RTE_LOG(ERR, IPSEC, "Invalid port id %d\n", port_id);
		return -EINVAL;
	}

	RTE_LOG(INFO, IPSEC, "Configure network interface of %d %s\n",
			port_id, if_up ? "up" : "down");

	if (if_up != 0) { /* Configure network interface up */
		rte_eth_dev_stop(port_id);
		ret = rte_eth_dev_start(port_id);
	} else /* Configure network interface down */
		rte_eth_dev_stop(port_id);

	if (ret < 0)
		RTE_LOG(ERR, IPSEC, "Failed to start port %d\n", port_id);

	return ret;
}


static int
kni_alloc(uint8_t port_id) {
	struct rte_kni *kni;
	struct rte_kni_conf conf;
	struct kni_port_params **params = kni_port_params_array;

	if (port_id >= RTE_MAX_ETHPORTS || !params[port_id])
		return -1;

	/* Clear conf at first */
	memset(&conf, 0, sizeof(conf));

	snprintf(conf.name, RTE_KNI_NAMESIZE, "vEth%u", port_id);
	conf.group_id = (uint16_t) port_id;
	conf.mbuf_size = MAX_PACKET_SZ;
	printf("conf.name:%s\n", conf.name);

	struct rte_kni_ops ops;
	struct rte_eth_dev_info dev_info;

	memset(&dev_info, 0, sizeof(dev_info));
	rte_eth_dev_info_get(port_id, &dev_info);
	conf.addr = dev_info.pci_dev->addr;
	conf.id = dev_info.pci_dev->id;

	memset(&ops, 0, sizeof(ops));
	ops.port_id = port_id;
	ops.change_mtu = kni_change_mtu;
	ops.config_network_if = kni_config_network_interface;

	kni = rte_kni_alloc(pktmbuf_pool[port_id], &conf, &ops);
	if (!kni)
		rte_exit(EXIT_FAILURE, "Fail to create kni for "
				"port: %d\n", port_id);
	params[port_id]->kni = kni;

	return 0;
}

static int
kni_free_kni(uint8_t port_id) {
	struct kni_port_params **p = kni_port_params_array;

	if (port_id >= RTE_MAX_ETHPORTS || !p[port_id])
		return -1;

	if (rte_kni_release(p[port_id]->kni))
		printf("Fail to release kni\n");
	p[port_id]->kni = NULL;

	rte_eth_dev_stop(port_id);

	return 0;
}

///* Create the mbuf pool */
//static void
//pool_create() {
//    pktmbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", NB_MBUF,
//                                           MEMPOOL_CACHE_SZ, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
//    if (pktmbuf_pool == NULL)
//        rte_exit(EXIT_FAILURE, "Could not initialise mbuf pool\n");
//}
//
//static void
//pool_free() {
//    if (pktmbuf_pool)
//        rte_mempool_free(pktmbuf_pool);
//}

static void
init_kni_param(uint8_t port_id) {
	memset(&kni_port_params_array, 0, sizeof(kni_port_params_array));
	kni_port_params_array[port_id] =
			rte_zmalloc("KNI_port_params", sizeof(struct kni_port_params), RTE_CACHE_LINE_SIZE);
	kni_port_params_array[port_id]->port_id = port_id;
}

void
kni_main(struct rte_mempool **mbuf_pool, struct rte_eth_conf *portconf, uint32_t kni_port_mask) {
	printf("-----------kni-----------\n");

	uint8_t nb_sys_ports, port;
	pktmbuf_pool = mbuf_pool;
	ports_mask = kni_port_mask;
	port_conf = portconf;
//    pool_create();
	/* Get number of ports found in scan */
	nb_sys_ports = rte_eth_dev_count();
	if (nb_sys_ports == 0)
		rte_exit(EXIT_FAILURE, "No supported Ethernet device found\n");

	for (port = 0; port < nb_sys_ports; port++) {
		/* Skip ports that are not enabled */
		if (!(ports_mask & (1 << port)))
			continue;
		init_kni_param(port);
	}

	init_kni();
	/* Initialize KNI subsystem */

	printf("nb_sys_ports:%d\n", nb_sys_ports);
	printf("ports_mask:%d\n", ports_mask);
	/* Initialise each port */
	for (port = 0; port < nb_sys_ports; port++) {
		printf("init_kni_param:%d\n", port);
		if (port >= RTE_MAX_ETHPORTS)
			rte_exit(EXIT_FAILURE, "Can not use more than "
					"%d ports for kni\n", RTE_MAX_ETHPORTS);

		kni_alloc(port);
	}
	print_config();
	printf("-----------kni-----------\n");
}

void
kni_free(void) {
	uint8_t nb_sys_ports, port;

	/* Get number of ports found in scan */
	nb_sys_ports = rte_eth_dev_count();
	if (nb_sys_ports == 0)
		rte_exit(EXIT_FAILURE, "No supported Ethernet device found\n");

	/* Release resources */
	for (port = 0; port < nb_sys_ports; port++) {
		if (!(ports_mask & (1 << port)))
			continue;
		kni_free_kni(port);
	}
#ifdef RTE_LIBRTE_XEN_DOM0
	rte_kni_close();
#endif
	//pool_free();

}