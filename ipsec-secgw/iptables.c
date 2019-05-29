//
// Created by 殷悦 on 16/05/2019.
//

#include <stdint.h>
#include <arpa/inet.h>

#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_tcp.h>
#include <rte_arp.h>
#include <rte_ether.h>
#include <rte_ethdev.h>

#include "uthash.h"
#include "iptables.h"

//#include "../lib/rte_ether.h"
//#include "../lib/rte_ip.h"
//#include "../lib/rte_udp.h"
//#include "../lib/rte_tcp.h"

struct gateway_ctx *gw_ctx;

static int
parse_pkt(struct ipv4_hdr *ip_hdr, struct udp_hdr **udp_hdr, struct tcp_hdr **tcp_hdr, struct tuple *pkt_tuple) {
	memset(pkt_tuple, 0, sizeof(struct tuple));
	pkt_tuple->dst_ip = ip_hdr->dst_addr;
	pkt_tuple->src_ip = ip_hdr->src_addr;
	pkt_tuple->proto = ip_hdr->next_proto_id;
	if (pkt_tuple->proto == IPPROTO_TCP) { //proto is tcp,
		*tcp_hdr = (struct tcp_hdr *) ((unsigned char *) ip_hdr +
									   sizeof(struct ipv4_hdr));
		pkt_tuple->src_port = (*tcp_hdr)->src_port;
		pkt_tuple->dst_port = (*tcp_hdr)->dst_port;
		return 1;
	} else if (pkt_tuple->proto == IPPROTO_UDP) { //proto is udp
		*udp_hdr = (struct udp_hdr *) ((unsigned char *) ip_hdr +
									   sizeof(struct ipv4_hdr));
		pkt_tuple->src_port = (*udp_hdr)->src_port;
		pkt_tuple->dst_port = (*udp_hdr)->dst_port;
		return 1;
	} else { // proto is icmp etc, send to kni
		return 0;
	}
}

//int bypass_before_tunnel(struct rte_mbuf *pkt) {
//	//return:
//	//0:go on
//	//1:send to kni
//	struct ether_hdr *eth;
//	struct ipv4_hdr *ip_hdr;
//	struct udp_hdr *udp_hdr;
//	struct tcp_hdr *tcp_hdr;
//	struct arp_table arp_pkt;
//	struct tuple pkt_tuple;
//
//	eth = rte_pktmbuf_mtod(pkt,
//	struct ether_hdr *);
//
//	if (eth->ether_type == rte_cpu_to_be_16(ETHER_TYPE_ARP)) { //proto is arp
//		parse_arp(ctx, pkt, &arp_pkt);
//		if (arp_pkt.ip == gw_ctx->wan_gateway) { //from wan gateway
//			printf("before:ARP from wan gateway\n");
//			print_ip_mac(arp_pkt.ip, &(arp_pkt.mac));
//			memcpy(gw_ctx->wan_gateway_ha.addr_bytes, arp_pkt.mac.addr_bytes, ETHER_ADDR_LEN);
//			return 0;
//		} else { // from other host, send to kni
//			printf("before:ARP from other host\n");
//			printf("before:IN\n");
//			print_ip_mac(arp_pkt.ip, &(arp_pkt.mac));
//			return 1;
//		}
//	}
//
//	if (eth->ether_type == rte_cpu_to_be_16(ETHER_TYPE_IPv4)) { // proto is ip
//		ip_hdr = rte_pktmbuf_mtod_offset(pkt,
//		struct ipv4_hdr *,sizeof(struct ether_hdr));
//		if (ip_hdr->next_proto_id == IPPROTO_ESP) {//proto is esp, decrype
//			printf("before:ESP\n");
//			// decrype
//			return 0;
//		}
//
//		if (!parse_pkt(pkt, ip_hdr, udp_hdr, tcp_hdr, &pkt_tuple)) { // proto is icmp etc, send to kni
//			printf("before:ICMP etc.\n");
//			print_tuple(&pkt_tuple);
//			return 1;
//		}
//		print_tuple(&pkt_tuple);
//		if (check_dnat(gw_ctx, &pkt_tuple)) { // dnat data
//			printf("before:DNAT\n");
//			print_tuple(&pkt_tuple);
//			ip_hdr->dst_addr = pkt_tuple.dst_ip;
//			if (pkt_tuple.proto == IPPROTO_TCP)
//				tcp_hdr->dst_port = pkt_tuple.dst_port;
//			else if (pkt_tuple.proto == IPPROTO_UDP)
//				udp_hdr->dst_port = pkt_tuple.dst_port;
//			return 0;
//		} else { // data dnat to kni,send to kni
//			printf("before:IN\n");
//			return 1;
//		}
//	}
//	return 0;
//}

static void parse_ike_ip_mac(struct rte_mbuf *pkt) {
	struct ether_hdr *eth;
	struct ipv4_hdr *ip4_hdr;

	eth = rte_pktmbuf_mtod(pkt,
	struct ether_hdr *);
	ip4_hdr = rte_pktmbuf_mtod_offset(pkt,
	struct ipv4_hdr *, sizeof(struct ether_hdr));

	printf("parse_ike_ip_mac add_tab\n");
	add_tab(gw_ctx, ip4_hdr->src_addr, &(eth->s_addr));
}

int bypass_before_tunnel_protect(struct rte_mbuf *pkt) {
	//return:
	//0:go on
	//1:send to kni
	struct ether_hdr *eth;
	struct ipv4_hdr *ip_hdr;
	struct udp_hdr *udp_hdr;
	int dport;

	eth = rte_pktmbuf_mtod(pkt,
	struct ether_hdr *);

	if (eth->ether_type == rte_cpu_to_be_16(ETHER_TYPE_IPv4)) { // proto is ip
		ip_hdr = rte_pktmbuf_mtod_offset(pkt,
		struct ipv4_hdr *,sizeof(struct ether_hdr));
		if (ip_hdr->next_proto_id == IPPROTO_ESP) { //proto is esp, decrype
			printf("before:ESP\n");
			// decrype
			return 0;
		} else if (ip_hdr->next_proto_id == IPPROTO_UDP) { //ike etc.
			udp_hdr = (struct udp_hdr *) ((unsigned char *) ip_hdr +
										  sizeof(struct ipv4_hdr));
			dport = rte_be_to_cpu_16(udp_hdr->dst_port);
			if (dport == 500) {
				parse_ike_ip_mac(pkt);
			}
		}
		return 1;
	} else if (eth->ether_type == rte_cpu_to_be_16(ETHER_TYPE_IPv6)) {
		return 0;
	}
	return 1;
}

static void
prepare_arp_reply(struct gateway_ctx *ctx, unsigned char *pkt, struct arp_table *target) {
	prepare_arp(ctx, pkt, ARP_OP_REPLY, target);
}

//return arp reply
int
bypass_before_tunnel_unprotect(struct rte_mbuf *pkt) {
	struct ether_hdr *eth;
	struct ipv4_hdr *ip_hdr;
	struct udp_hdr *udp_hdr = NULL;
	struct tcp_hdr *tcp_hdr = NULL;
	struct arp_table arp_pkt;
	struct tuple pkt_tuple;
	int arp_request;

	eth = rte_pktmbuf_mtod(pkt,
	struct ether_hdr *);

	if (eth->ether_type == rte_cpu_to_be_16(ETHER_TYPE_ARP)) { //proto is arp
		arp_request = parse_arp(gw_ctx, rte_pktmbuf_mtod(pkt, void * ), &arp_pkt);
		if (arp_request) {
			prepare_arp_reply(gw_ctx, rte_pktmbuf_mtod(pkt, void * ), &arp_pkt);
			return 1;
		} else if (arp_pkt.ip == gw_ctx->wan_gateway) { //from wan gateway
			printf("before:ARP from wan gateway\n");
			print_ip_mac(arp_pkt.ip, &(arp_pkt.mac));
			memcpy(gw_ctx->wan_gateway_ha.addr_bytes, arp_pkt.mac.addr_bytes, ETHER_ADDR_LEN);
			return 0;
		}
	}

	if (eth->ether_type == rte_cpu_to_be_16(ETHER_TYPE_IPv4)) { // proto is ip
		ip_hdr = rte_pktmbuf_mtod_offset(pkt,
		struct ipv4_hdr *,sizeof(struct ether_hdr));

		if (!parse_pkt(ip_hdr, &udp_hdr, &tcp_hdr, &pkt_tuple)) { // proto is icmp etc, send to kni
			printf("before:ICMP etc.\n");
			print_tuple(&pkt_tuple);
			return 0;
		}
		print_tuple(&pkt_tuple);
		if (check_dnat(gw_ctx, &pkt_tuple)) { // dnat data
			printf("before:DNAT\n");
			print_tuple(&pkt_tuple);
			ip_hdr->dst_addr = pkt_tuple.dst_ip;
			ip_hdr->hdr_checksum = 0;
			ip_hdr->hdr_checksum = rte_ipv4_cksum(ip_hdr)+0x1;
			if (pkt_tuple.proto == IPPROTO_TCP) {
				tcp_hdr->dst_port = pkt_tuple.dst_port;
				tcp_hdr->cksum = 0;
				tcp_hdr->cksum = rte_ipv4_udptcp_cksum(ip_hdr, (unsigned char *) ip_hdr + sizeof(struct ipv4_hdr));
			} else if (pkt_tuple.proto == IPPROTO_UDP) {
				udp_hdr->dst_port = pkt_tuple.dst_port;
				udp_hdr->dgram_cksum = 0;
				udp_hdr->dgram_cksum = rte_ipv4_udptcp_cksum(ip_hdr,
															 (unsigned char *) ip_hdr + sizeof(struct ipv4_hdr));
			}
			return 0;
		} else { // data dnat to kni,send to kni
			printf("before:IN\n");
			return 0;
		}
	}
	return 0;
}

//static uint16_t get_ip_checksum(char *ip_hdr) {
//	int i;
//	char *ptr_data = ip_hdr;
//	uint32_t tmp = 0;
//	uint32_t sum = 0;
//	for (i = 0; i < 20; i += 2) {
//		tmp += (uint8_t) ptr_data[i] << 8;
//		tmp += (uint8_t) ptr_data[i + 1];
//		sum += tmp;
//		tmp = 0;
//	}
//	uint16_t lWord = sum & 0x0000FFFF;
//	uint16_t hWord = sum >> 16;
//	uint16_t checksum = lWord + hWord;
//	checksum = ~checksum;
//	return checksum;
//}

void bypass_after_tunnel(struct rte_mbuf *pkt) {
	struct ipv4_hdr *ip_hdr;
	struct udp_hdr *udp_hdr = NULL;
	struct tcp_hdr *tcp_hdr = NULL;
	struct tuple pkt_tuple;
//	uint16_t ip_cksum;

	printf("bypass_after_tunnel\n");

	ip_hdr = rte_pktmbuf_mtod(pkt,
	struct ipv4_hdr *);

//	printf("2 offset:%d\n",offsetof(
//	struct ipv4_hdr, dst_addr));

	if (!parse_pkt(ip_hdr, &udp_hdr, &tcp_hdr, &pkt_tuple)) { // proto is icmp etc, send to kni
		printf("after:ICMP,ESP,etc.\n");
		return;
	}

	print_tuple(&pkt_tuple);

	if (check_snat(gw_ctx, &pkt_tuple)) {
		printf("after:SNAT\n");
		print_tuple(&pkt_tuple);
		ip_hdr->src_addr = pkt_tuple.src_ip;
//		memset(&(ip_hdr->hdr_checksum), 0, sizeof(uint16_t));
//		printf("get_ip_checksum:0x%04x\n", get_ip_checksum((char *) ip_hdr));
//		printf("rte_ipv4_cksum :0x%04x\n", rte_ipv4_cksum(ip_hdr));
//		ip_cksum = rte_ipv4_cksum(ip_hdr);
//		ip_hdr->hdr_checksum = 0;
//		ip_hdr->hdr_checksum = rte_ipv4_cksum(ip_hdr);
//		printf("ip_hdr->hdr_checksum:%x\n", ip_hdr->hdr_checksum);
		if (pkt_tuple.proto == IPPROTO_TCP) {
			tcp_hdr->src_port = pkt_tuple.src_port;
			tcp_hdr->cksum = 0;
			tcp_hdr->cksum = rte_ipv4_udptcp_cksum(ip_hdr, (unsigned char *) ip_hdr + sizeof(struct ipv4_hdr));
		} else if (pkt_tuple.proto == IPPROTO_UDP) {
			udp_hdr->src_port = pkt_tuple.src_port;
			udp_hdr->dgram_cksum = 0;
			udp_hdr->dgram_cksum = rte_ipv4_udptcp_cksum(ip_hdr, (unsigned char *) ip_hdr + sizeof(struct ipv4_hdr));
		}
	} else if (check_forward(gw_ctx, &pkt_tuple)) {
		printf("after:FORWARD\n");
		print_tuple(&pkt_tuple);
	}
}

static struct rte_mbuf *
prepare_arp_request(struct rte_mempool *mbuf_pool, uint32_t target_ip) {
	struct rte_mbuf *m;
	struct arp_table target;
	m = rte_pktmbuf_alloc(mbuf_pool);
	if (m == NULL) {
		return m;
	}
	target.ip = target_ip;
	memset(target.mac.addr_bytes, 0x00, ETHER_ADDR_LEN);
	prepare_arp(gw_ctx, rte_pktmbuf_mtod(m, void * ), ARP_OP_REQUEST, &target);
	return m;
}

struct rte_mbuf *send_arp_gw(struct rte_mempool *mbuf_pool) {
#define LEFT_TIME 50000
	static int wait_timp = LEFT_TIME;//100us * LEFT_TIME (0.1ms * LEFT_TIME)
	struct ether_addr empty = {.addr_bytes = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}};
	if (likely(memcmp(gw_ctx->wan_gateway_ha.addr_bytes, empty.addr_bytes, sizeof(struct ether_addr)))) {
		return NULL;
	}
	if (likely(wait_timp--)) {
		return NULL;
	}
	wait_timp = LEFT_TIME;
	return prepare_arp_request(mbuf_pool, gw_ctx->wan_gateway);
//	send_arp(mbuf_pool, port, queueid, 0, NULL);
}

void prepend_ether(struct ether_hdr *eth, uint32_t *dst_ip) {
	struct ether_addr *res;
	printf("prepend_ether\n");
	res = find_tab(gw_ctx, *dst_ip);
	if (res) {
		memcpy(eth->s_addr.addr_bytes, gw_ctx->wan_ha.addr_bytes, ETHER_ADDR_LEN);
		memcpy(eth->d_addr.addr_bytes, res->addr_bytes, ETHER_ADDR_LEN);
	} else {
		memcpy(eth->s_addr.addr_bytes, gw_ctx->wan_ha.addr_bytes, ETHER_ADDR_LEN);
		memcpy(eth->d_addr.addr_bytes, gw_ctx->wan_gateway_ha.addr_bytes, ETHER_ADDR_LEN);
	}
}

void iptables_init(void) {
	struct gateway_ctx temp = {
			.wan_ip = inet_addr("192.168.11.123"),
			.wan_netmask = inet_addr("255.255.255.0"),
			.wan_gateway = inet_addr("192.168.11.2"),
			.wan_ha.addr_bytes = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
			.lan_ip = inet_addr("10.31.2.0"),
			.lan_netmask = inet_addr("255.255.255.0")
	};
	gw_ctx = (struct gateway_ctx *) malloc(sizeof(struct gateway_ctx));
	if (gw_ctx == NULL) {
		printf("malloc error\n");
	}
//	memset(gw_ctx, 0, sizeof(struct gateway_ctx));
	memcpy(gw_ctx, &temp, sizeof(struct gateway_ctx));
}

//void send_arp(struct rte_mempool *mbuf_pool, uint8_t port, uint16_t queueid) {
//#define LEFT_TIME 50000
//	static int wait_timp = LEFT_TIME;//100us * LEFT_TIME (0.1ms * LEFT_TIME)
//	struct rte_mbuf *m;
//	int32_t ret;
//	struct ether_addr empty = {
//			.addr_bytes = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
//	};
//	if (likely(memcmp(gw_ctx->wan_gateway_ha.addr_bytes, empty.addr_bytes, sizeof(struct ether_addr)))) {
//		return;
//	}
//	if (likely(wait_timp--)) {
//		return;
//	}
//	wait_timp = LEFT_TIME;
//	m = rte_pktmbuf_alloc(mbuf_pool);
//	if (m == NULL) {
//		return;
//	}
//	printf("send arp to gateway\n");
//	prepare_arp(gw_ctx, rte_pktmbuf_mtod(m, void * ), gw_ctx->wan_gateway);
//	m->nb_segs = 1;
//	m->next = NULL;
//	m->pkt_len = sizeof(struct ether_hdr) + sizeof(struct arp_hdr);
//	m->data_len = sizeof(struct ether_hdr) + sizeof(struct arp_hdr);
//	ret = rte_eth_tx_burst(port, queueid, &m, 1);
//	if (unlikely(ret < 1)) {
//		rte_pktmbuf_free(m);
//	}
//}
