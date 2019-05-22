////
//// Created by 殷悦 on 03/03/2019.
////
//
//#include <stdio.h>
//#include <stdlib.h>
//#include <netinet/in.h>
//#include <arpa/inet.h>
//
//#include <rte_ip.h>
//#include <rte_mbuf.h>
//#include <rte_ether.h>
//
//#include "kni.h"
//#include "xfrm.h"
//
//struct arp_table {
//	uint64_t mac;
//	uint32_t ip;
//};
//
//#define IP_MASK (256)
//#define IP2IDX(ip) (ip >> 24 & (IP_MASK - 1))
//
//
//struct arp_table table[IP_MASK] = {
//		{
//				.ip = 0,
//				.mac = 0
//		}
//};
//
//
//static void
//add_ip_mac(uint32_t ip, uint64_t mac) {
//	struct in_addr ip_addr;
//	if (table[IP2IDX(ip)].mac != mac) {
//		printf("---------------   ADD IP   ---------------\n");
//		printf("ip_mac_table update:\n");
//		printf("idx:%d\n", IP2IDX(ip));
//		ip_addr.s_addr = table[IP2IDX(ip)].ip;
//		printf("origin\tip:%s\tmac:%lx\n",
//			   inet_ntoa(ip_addr),
//			   table[IP2IDX(ip)].mac
//		);
//		table[IP2IDX(ip)].ip = ip;
//		table[IP2IDX(ip)].mac = mac;
//		ip_addr.s_addr = ip;
//		printf("new\tip:%s\tmac:%lx\n",
//			   inet_ntoa(ip_addr),
//			   mac
//		);
//		printf("------------------------------------------\n");
//	}
//}
//
//static void
//classify_addr(uint32_t saddr, uint64_t smac, uint32_t daddr, uint64_t dmac) {
//	//add others ip and address
//	add_ip_mac(saddr, smac);
//
//	//add my ip and address
//	add_ip_mac(daddr, dmac);
//	xfrm_add_addr(daddr);
//}
//
//void
//parse_pkt_arp(struct rte_mbuf *pkt) {
//	struct ether_hdr *eth;
//	struct ipv4_hdr *ip4_hdr;
//	struct in_addr src_addr, dst_addr;
//	uint64_t src, dst;
////	struct ether_addr ethaddr;
//	char s_addr[ETHER_ADDR_FMT_SIZE], d_addr[ETHER_ADDR_FMT_SIZE];
//
//	eth = rte_pktmbuf_mtod(pkt,
//	struct ether_hdr *);
//	ip4_hdr = rte_pktmbuf_mtod_offset(pkt,
//	struct ipv4_hdr *, sizeof(struct ether_hdr));
//
//	src = ETHADDR_TO_UINT64(eth->s_addr);
//	dst = ETHADDR_TO_UINT64(eth->d_addr);
//
//	ether_format_addr(s_addr, ETHER_ADDR_FMT_SIZE, &eth->s_addr);
//	ether_format_addr(d_addr, ETHER_ADDR_FMT_SIZE, &eth->d_addr);
//
//	printf("arp:\n");
//	printf("s_addr:%s\td_addr:%s\n", s_addr, d_addr);
//
//	src_addr.s_addr = ip4_hdr->src_addr;
//	dst_addr.s_addr = ip4_hdr->dst_addr;
//
//	printf("src_addr:%s\t", inet_ntoa(src_addr));
//	printf("dst_addr:%s\n", inet_ntoa(dst_addr));
//
//	classify_addr(ip4_hdr->src_addr, src, ip4_hdr->dst_addr, dst);
//}
//
//void
//get_mac_by_ip(struct ether_hdr *eth, struct ethaddr_info def, struct ip *ip) {
//	char s_addr[ETHER_ADDR_FMT_SIZE], d_addr[ETHER_ADDR_FMT_SIZE];
//	struct in_addr temp;
//	temp.s_addr=table[IP2IDX(ip->ip_src.s_addr)].ip;
//	printf("IP2IDX(ip->ip_src.s_addr):%d\n", IP2IDX(ip->ip_src.s_addr));
//	printf("table[IP2IDX(ip->ip_src.s_addr)].ip:%s\n", inet_ntoa(temp));
//
//	//deal src mac address
//	if (table[IP2IDX(ip->ip_src.s_addr)].ip == ip->ip_src.s_addr)
//		memcpy(&eth->s_addr, &table[IP2IDX(ip->ip_src.s_addr)], sizeof(struct ether_addr));
//	else
//		memcpy(&eth->s_addr, &def.src, sizeof(struct ether_addr));
//
//	ether_format_addr(s_addr, ETHER_ADDR_FMT_SIZE, &eth->s_addr);
//	printf("kni send\tsrc ip:%s\tmac:%s\n", inet_ntoa(ip->ip_src), s_addr);
//
//	temp.s_addr=table[IP2IDX(ip->ip_dst.s_addr)].ip;
//	printf("IP2IDX(ip->ip_dst.s_addr):%d\n", IP2IDX(ip->ip_dst.s_addr));
//	printf("table[IP2IDX(ip->ip_dst.s_addr)].ip:%s\n", inet_ntoa(temp));
//
//	//deal dst mac address
//	if (table[IP2IDX(ip->ip_dst.s_addr)].ip == ip->ip_dst.s_addr)
//		memcpy(&eth->d_addr, &table[IP2IDX(ip->ip_dst.s_addr)], sizeof(struct ether_addr));
//	else
//		memcpy(&eth->d_addr, &def.dst, sizeof(struct ether_addr));
//
//	ether_format_addr(d_addr, ETHER_ADDR_FMT_SIZE, &eth->d_addr);
//	printf("kni send\tdst ip:%s\tmac:%s\n", inet_ntoa(ip->ip_dst), d_addr);
//}