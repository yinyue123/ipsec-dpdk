//
// Created by 殷悦 on 26/01/2019.
//

#ifndef __KNI_H__
#define __KNI_H__

#include <netinet/ip.h>
#include <rte_ethdev.h>

/* port/source ethernet addr and destination ethernet addr */
struct ethaddr_info {
	uint64_t src, dst;
};

#if RTE_BYTE_ORDER != RTE_LITTLE_ENDIAN
#define __BYTES_TO_UINT64(a, b, c, d, e, f, g, h) \
	(((uint64_t)((a) & 0xff) << 56) | \
	((uint64_t)((b) & 0xff) << 48) | \
	((uint64_t)((c) & 0xff) << 40) | \
	((uint64_t)((d) & 0xff) << 32) | \
	((uint64_t)((e) & 0xff) << 24) | \
	((uint64_t)((f) & 0xff) << 16) | \
	((uint64_t)((g) & 0xff) << 8)  | \
	((uint64_t)(h) & 0xff))
#else
#define __BYTES_TO_UINT64(a, b, c, d, e, f, g, h) \
    (((uint64_t)((h) & 0xff) << 56) | \
    ((uint64_t)((g) & 0xff) << 48) | \
    ((uint64_t)((f) & 0xff) << 40) | \
    ((uint64_t)((e) & 0xff) << 32) | \
    ((uint64_t)((d) & 0xff) << 24) | \
    ((uint64_t)((c) & 0xff) << 16) | \
    ((uint64_t)((b) & 0xff) << 8) | \
    ((uint64_t)(a) & 0xff))
#endif

#define ETHADDR_TO_UINT64(addr) __BYTES_TO_UINT64( \
        addr.addr_bytes[0], addr.addr_bytes[1], \
        addr.addr_bytes[2], addr.addr_bytes[3], \
        addr.addr_bytes[4], addr.addr_bytes[5], \
        0, 0)

#define ETHADDR(a, b, c, d, e, f) (__BYTES_TO_UINT64(a, b, c, d, e, f, 0, 0))

//int
//check_kni_data(struct rte_mbuf *pkt);

void
send_to_kni(uint8_t port_id, struct rte_mbuf **pkts, uint32_t nb_rx);

void
forward_from_kni_to_eth(uint16_t tx_queue_id, uint8_t port_id);

void
kni_main(struct rte_mempool **mbuf_pool, struct rte_eth_conf *portconf, uint32_t kni_port_mask);

void
kni_free(void);

void
get_mac_by_ip(struct ether_hdr *eth, struct ethaddr_info def, struct ip *ip);

#endif /* __KNI_H__ */
