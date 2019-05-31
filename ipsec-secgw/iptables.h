//
// Created by 殷悦 on 16/05/2019.
//

#ifndef BYSJ_IPTABLES_H
#define BYSJ_IPTABLES_H

#include <netinet/ip.h>

#include <rte_ether.h>
//#include "../lib/rte_ether.h"

#include "uthash.h"

//arp
struct arp_table {
	uint32_t ip;
	struct ether_addr mac;
//	unsigned char mac[ETHER_ADDR_LEN];
	UT_hash_handle hh;
};


//nat
struct tuple {
	uint32_t src_ip;
	uint32_t dst_ip;
	uint16_t src_port;
	uint16_t dst_port;
	uint8_t proto;
};

struct nat_table {
	struct tuple dnat;
	struct tuple snat;
	UT_hash_handle shh;
	UT_hash_handle dhh;
};

struct gateway_ctx {
	uint32_t lan_ip;
	uint32_t lan_netmask;
	uint32_t wan_ip;
	uint32_t wan_netmask;
	uint32_t wan_gateway;
	struct ether_addr wan_ha;
	struct ether_addr wan_gateway_ha;
	struct arp_table *arp_tab;
	struct nat_table *snat_tab;
	struct nat_table *dnat_tab;
};
//


//nat
void print_tuple(struct tuple *packet);

int check_dnat(struct gateway_ctx *ctx, struct tuple *packet);

int check_snat(struct gateway_ctx *ctx, struct tuple *packet);

int check_forward(struct gateway_ctx *ctx, struct tuple *packet);

//arp
//void printHex(unsigned char *ptr, int len);

void print_ip_mac(uint32_t ip, struct ether_addr *ha);

struct ether_addr *find_tab(struct gateway_ctx *ctx, uint32_t ip);

void add_tab(struct gateway_ctx *ctx, uint32_t ip, struct ether_addr *mac);

//void prepare_arp(struct gateway_ctx *ctx, unsigned char *pkt, uint32_t target_ip);
void prepare_arp(struct gateway_ctx *ctx, unsigned char *pkt, uint32_t arp_op, struct arp_table *target);

//void parse_arp(struct gateway_ctx *ctx, unsigned char *pkt, struct arp_table *result);
int parse_arp(struct gateway_ctx *ctx, unsigned char *pkt, struct arp_table *result);

//iptables
//int bypass_before_tunnel(struct rte_mbuf *pkt);

int bypass_before_tunnel_protect(struct rte_mbuf *pkt);

int bypass_before_tunnel_unprotect(struct rte_mbuf *pkt);

void bypass_after_tunnel(struct rte_mbuf *pkt);

struct rte_mbuf *send_arp_gw(struct rte_mempool *mbuf_pool);

void prepend_ether(struct ether_hdr *eth, uint32_t *dst_ip);

void iptables_init(void);

#endif //BYSJ_IPTABLES_H


