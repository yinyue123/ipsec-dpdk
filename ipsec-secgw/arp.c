//
// Created by 殷悦 on 17/05/2019.
//

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
//#include <net/if_arp.h>

#include <rte_ether.h>
#include <rte_arp.h>

#include "uthash.h"
#include "iptables.h"

//#include "../lib/rte_ether.h"
//#include "../lib/rte_arp.h"

static void printHex(unsigned char *ptr, int len) {
//void printHex(unsigned char *ptr, int len) {
	int i;
	for (i = 0; i < len; i++) {
		printf("%02X ", *(ptr + i));
		if (i % 8 == 7)
			printf("  ");
		if (i % 16 == 15)
			printf("\n");
	}
	printf("\n");
}

static char *addr(uint32_t ip) {
	struct in_addr temp;
	temp.s_addr = ip;
	return inet_ntoa(temp);
}

void print_ip_mac(uint32_t ip, struct ether_addr *ha) {
	printf("%s(%02X:%02X:%02X:%02X:%02X:%02X)\n", addr(ip),
		   ha->addr_bytes[0], ha->addr_bytes[1], ha->addr_bytes[2],
		   ha->addr_bytes[3], ha->addr_bytes[4], ha->addr_bytes[5]);
}

struct ether_addr *find_tab(struct gateway_ctx *ctx, uint32_t ip) {
	struct arp_table *obj = NULL;
	printf("----------------------\n");
	printf("find tab test\n");
	HASH_FIND(hh, ctx->arp_tab, &ip, sizeof(uint32_t), obj);
	if (obj) {
		print_ip_mac(ip, &(obj->mac));
		printf("----------------------\n\n");
		return &(obj->mac);
	} else {
		printf("arp table not found\n");
		printf("----------------------\n\n");
		return NULL;
	}
}

void add_tab(struct gateway_ctx *ctx, uint32_t ip, struct ether_addr *mac) {
	struct arp_table *obj = NULL;
	HASH_FIND(hh, ctx->arp_tab, &ip, sizeof(uint32_t), obj);
	if (!obj) {
		printf("new arp\t");
		obj = (struct arp_table *) malloc(sizeof(struct arp_table));
		if (obj == NULL) {
			printf("malloc error\n");
		}
		memset(obj, 0, sizeof(struct arp_table));
		obj->ip = ip;
		memcpy(&(obj->mac.addr_bytes), mac->addr_bytes, ETHER_ADDR_LEN);
		HASH_ADD(hh, ctx->arp_tab, ip, sizeof(uint32_t), obj);
	} else if (memcmp(obj->mac.addr_bytes, mac->addr_bytes, ETHER_ADDR_LEN)) {
		printf("renew arp\t");
		memcpy(obj->mac.addr_bytes, mac->addr_bytes, ETHER_ADDR_LEN);
	}
	print_ip_mac(ip, mac);
}

//// send
//void prepare_arp(struct gateway_ctx *ctx, unsigned char *pkt, uint32_t arp_op, struct arp_table *target) {
//	struct ether_hdr *eth = (struct ether_hdr *) pkt;
//	struct arp_hdr *arp = (struct arp_hdr *) (pkt + sizeof(struct ether_hdr));
//	printf("----------------------\n");
//	printf("prepare arp packet\n");
//
//	//ether hdr
//	memcpy(eth->s_addr.addr_bytes, ctx->wan_ha.addr_bytes, ETHER_ADDR_LEN);
//	eth->ether_type = htons(ETHER_TYPE_ARP);
//
//	//arp body
//	arp->arp_hrd = htons(ARP_HRD_ETHER);
//	arp->arp_pro = htons(ETHER_TYPE_IPv4);
//	arp->arp_hln = ETHER_ADDR_LEN;
//	arp->arp_pln = 4;
//
//	arp->arp_data.arp_sip = ctx->wan_ip;
//	arp->arp_data.arp_tip = target->ip;
//
//	memcpy(arp->arp_data.arp_sha.addr_bytes, ctx->wan_ha.addr_bytes, ETHER_ADDR_LEN);
//
//	switch (arp_op) {
//		case ARP_OP_REQUEST:
//			memset(eth->d_addr.addr_bytes, 0xff, ETHER_ADDR_LEN);
//			arp->arp_op = htons(ARP_OP_REQUEST);
//			memset(arp->arp_data.arp_tha.addr_bytes, 0x00, ETHER_ADDR_LEN);
//			break;
//		case ARP_OP_REPLY:
//			memcpy(eth->s_addr.addr_bytes, target->mac.addr_bytes, ETHER_ADDR_LEN);
//			arp->arp_op = htons(ARP_OP_REPLY);
//			memcpy(arp->arp_data.arp_tha.addr_bytes, target->mac.addr_bytes, ETHER_ADDR_LEN);
//			break;
//		default:
//			break;
//	}
//	printHex(pkt, sizeof(struct ether_hdr) + sizeof(struct arp_hdr));
//	printf("----------------------\n\n");
//}

// send
void prepare_arp(struct gateway_ctx *ctx, unsigned char *pkt, uint32_t arp_op, struct arp_table *target) {
	struct ether_hdr *eth = (struct ether_hdr *) pkt;
	struct arp_hdr *arp = (struct arp_hdr *) (pkt + sizeof(struct ether_hdr));
	printf("----------------------\n");
	printf("prepare arp packet\n");

	//ether hdr
	eth->ether_type = htons(ETHER_TYPE_ARP);

	//arp body
	arp->arp_hrd = htons(ARP_HRD_ETHER);
	arp->arp_pro = htons(ETHER_TYPE_IPv4);
	arp->arp_hln = ETHER_ADDR_LEN;
	arp->arp_pln = 4;

	arp->arp_data.arp_sip = ctx->wan_ip;
	arp->arp_data.arp_tip = target->ip;

	memcpy(arp->arp_data.arp_sha.addr_bytes, ctx->wan_ha.addr_bytes, ETHER_ADDR_LEN);

	switch (arp_op) {
		case ARP_OP_REQUEST:
			memset(eth->d_addr.addr_bytes, 0xff, ETHER_ADDR_LEN);
			memcpy(eth->s_addr.addr_bytes, ctx->wan_ha.addr_bytes, ETHER_ADDR_LEN);
			arp->arp_op = htons(ARP_OP_REQUEST);
			memset(arp->arp_data.arp_tha.addr_bytes, 0x00, ETHER_ADDR_LEN);
			break;
		case ARP_OP_REPLY:
//			DONT KNOW WHY,DONT CHANGE IT
//			memcpy(eth->d_addr.addr_bytes, target->mac.addr_bytes, ETHER_ADDR_LEN);
//			memcpy(eth->s_addr.addr_bytes, ctx->wan_ha.addr_bytes, ETHER_ADDR_LEN);
			arp->arp_op = htons(ARP_OP_REPLY);
			memcpy(arp->arp_data.arp_tha.addr_bytes, target->mac.addr_bytes, ETHER_ADDR_LEN);
			break;
		default:
			break;
	}
	printHex(pkt, sizeof(struct ether_hdr) + sizeof(struct arp_hdr));
	printf("----------------------\n\n");
}

//recv
//return need reply
int parse_arp(struct gateway_ctx *ctx, unsigned char *pkt, struct arp_table *result) {
	struct ether_addr bdcst_ha = {.addr_bytes = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}};
	struct ether_addr zero_ha = {.addr_bytes = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}};
	struct ether_hdr *eth = (struct ether_hdr *) pkt;
	struct arp_hdr *arp_pkt = (struct arp_hdr *) (eth + 1);

	printf("----------------------\n");
	printf("parse arp packet\n");
	printHex(pkt, sizeof(struct ether_hdr) + sizeof(struct arp_hdr));
	if (memcmp(eth->d_addr.addr_bytes, ctx->wan_ha.addr_bytes, ETHER_ADDR_LEN) && //not to me
		memcmp(eth->d_addr.addr_bytes, bdcst_ha.addr_bytes, ETHER_ADDR_LEN)) { //not to everyone
		printf("not to me\n");
		printf("----------------------\n\n");
		return 0;
	}
	if (!(arp_pkt->arp_hrd == htons(ARP_HRD_ETHER) &&
		  arp_pkt->arp_pro == htons(ETHER_TYPE_IPv4) &&
		  arp_pkt->arp_hln == ETHER_ADDR_LEN &&
		  arp_pkt->arp_pln == 4)) {
		printf("packet incorrect\n");
		printf("----------------------\n\n");
		return 0;
	}
	switch (htons(arp_pkt->arp_op)) {
		case ARP_OP_REQUEST:
			if (memcmp(arp_pkt->arp_data.arp_tha.addr_bytes, zero_ha.addr_bytes, ETHER_ADDR_LEN) ||
				arp_pkt->arp_data.arp_tip != ctx->wan_ip) {
				printf("not to me2\n");
				return 0;
			}
			result->ip = arp_pkt->arp_data.arp_sip;
			memcpy(result->mac.addr_bytes, arp_pkt->arp_data.arp_sha.addr_bytes, ETHER_ADDR_LEN);
			printf("----------------------\n\n");
			return 1;
		case ARP_OP_REPLY:
			if (memcmp(arp_pkt->arp_data.arp_tha.addr_bytes, ctx->wan_ha.addr_bytes, ETHER_ADDR_LEN) ||
				arp_pkt->arp_data.arp_tip != ctx->wan_ip) {
				printf("not to me 2\n");
				return 0;
			}
			result->ip = arp_pkt->arp_data.arp_sip;
			memcpy(result->mac.addr_bytes, arp_pkt->arp_data.arp_sha.addr_bytes, ETHER_ADDR_LEN);
			printf("----------------------\n\n");
			return 0;
		default:
			return 0;
	}
	return 0;
}

//void init(struct gateway_ctx *ctx, uint32_t wan_ip, struct ether_addr *wan_ha) {
//	memset(ctx, 0, sizeof(struct gateway_ctx));
//	ctx->wan_ip = wan_ip;
//	memcpy(&(ctx->wan_ha), wan_ha, ETHER_ADDR_LEN);
//	printf("------ arp init ------\n");
//	printf("wan_ha:\t");
//	print_ip_mac(wan_ip, wan_ha);
//	printf("----------------------\n\n");
//}

//void prepare_arp(struct gateway_ctx *ctx, unsigned char *pkt, uint32_t target_ip) {    // send
//	struct ether_hdr *eth = (struct ether_hdr *) pkt;
//	struct arp_hdr *arp = (struct arp_hdr *) (pkt + sizeof(struct ether_hdr));
//	printf("----------------------\n");
//	printf("prepare arp packet\n");
//	memset(eth->d_addr.addr_bytes, 0xff, ETHER_ADDR_LEN);
//	memcpy(eth->s_addr.addr_bytes, ctx->wan_ha.addr_bytes, ETHER_ADDR_LEN);
//	eth->ether_type = htons(ETHER_TYPE_ARP);
//
//	arp->arp_hrd = htons(ARP_HRD_ETHER);
//	arp->arp_pro = htons(ETHER_TYPE_IPv4);
//	arp->arp_hln = ETHER_ADDR_LEN;
//	arp->arp_pln = 4;
//	arp->arp_op = htons(ARP_OP_REQUEST);
//	arp->arp_data.arp_sip = ctx->wan_ip;
//	arp->arp_data.arp_tip = target_ip;
//	memset(arp->arp_data.arp_tha.addr_bytes, 0x00, ETHER_ADDR_LEN);
//	memcpy(arp->arp_data.arp_sha.addr_bytes, ctx->wan_ha.addr_bytes, ETHER_ADDR_LEN);
//	printHex(pkt, sizeof(struct ether_hdr) + sizeof(struct arp_hdr));
//	printf("----------------------\n\n");
//}

////void parse_arp(struct gateway_ctx *ctx, unsigned char *pkt) {        //recv
//void parse_arp(struct gateway_ctx *ctx, unsigned char *pkt, struct arp_table *result) {
//	struct ether_hdr *eth = (struct ether_hdr *) pkt;
//	struct arp_hdr *arp_pkt = (struct arp_hdr *) (pkt + sizeof(struct ether_hdr));
//	struct arp_hdr chk = {
//			.arp_hrd=htons(ARP_HRD_ETHER),
//			.arp_pro=htons(ETHER_TYPE_IPv4),
//			.arp_hln=ETHER_ADDR_LEN,
//			.arp_pln=4,
//			.arp_op=htons(ARP_OP_REPLY),
//	};
//	printf("----------------------\n");
//	printf("parse arp packet\n");
//	printHex(pkt, sizeof(struct ether_hdr) + sizeof(struct arp_hdr));
////	printHex(arp_pkt, sizeof(struct arp_hdr));
//	if (eth->ether_type != htons(ETHER_TYPE_ARP) ||
//		memcmp(eth->d_addr.addr_bytes, ctx->wan_ha.addr_bytes, ETHER_ADDR_LEN) ||
//		memcmp(eth->s_addr.addr_bytes, arp_pkt->arp_data.arp_sha.addr_bytes, ETHER_ADDR_LEN)) {
//		printf("not interest\n");
//		return;
//	}
//	chk.arp_data.arp_sip = arp_pkt->arp_data.arp_sip;
//	chk.arp_data.arp_tip = ctx->wan_ip;
//	memcpy(chk.arp_data.arp_sha.addr_bytes, arp_pkt->arp_data.arp_sha.addr_bytes, ETHER_ADDR_LEN);
//	memcpy(chk.arp_data.arp_tha.addr_bytes, arp_pkt->arp_data.arp_tha.addr_bytes, ETHER_ADDR_LEN);
//	if (memcmp(&chk, arp_pkt, sizeof(struct arp_hdr))) {
//		printf("arp reply not match\n");
//		return;
//	}
////	add_tab(ctx, arp_pkt->arp_data.arp_sip, &(arp_pkt->arp_data.arp_sha));
//	printf("----------------------\n\n");
//
//	result->ip = arp_pkt->arp_data.arp_sip;
//	memcpy(result->mac.addr_bytes, arp_pkt->arp_data.arp_sha.addr_bytes, ETHER_ADDR_LEN);
//}

//void show_table(struct gateway_ctx *ctx) {
//	struct arp_table *s, *tmp;
//	printf("----------------------\n");
//	printf("show tab test\n");
//	HASH_ITER(hh, ctx->arp_tab, s, tmp) {
//		print_ip_mac(s->ip, &(s->mac));
//	}
//	printf("----------------------\n\n");
//}

//int main() {
//	struct gateway_ctx *ctx = (struct gateway_ctx *) malloc(sizeof(struct gateway_ctx));
//	unsigned char *packet = (unsigned char *) malloc(sizeof(struct ether_hdr) + sizeof(struct arp_hdr));
//	struct ether_hdr eth = {
//			.s_addr={0x02, 0x02, 0x02, 0x02, 0x02, 0x02},
//			.d_addr={0x01, 0x01, 0x01, 0x01, 0x01, 0x01},
//			.ether_type=htons(ETHER_TYPE_ARP)
//	};
//	struct arp_hdr arp_pkt = {
//			.arp_hrd=htons(ARP_HRD_ETHER),
//			.arp_pro=htons(ETHER_TYPE_IPv4),
//			.arp_hln=ETHER_ADDR_LEN,
//			.arp_pln=4,
//			.arp_op=htons(ARP_OP_REPLY),
//			.arp_data.arp_sha={0x02, 0x02, 0x02, 0x02, 0x02, 0x02},
//			.arp_data.arp_tha={0x01, 0x01, 0x01, 0x01, 0x01, 0x01}
//	};
//	struct ether_addr *mac;
//
//	arp_pkt.arp_data.arp_sip = inet_addr("192.168.1.2");
//	arp_pkt.arp_data.arp_tip = inet_addr("192.168.1.1");
//
//	init(ctx, inet_addr("192.168.1.1"), &(eth.d_addr));
//
//	//prepare packet from send
//	prepare_arp(ctx, packet, inet_addr("192.168.1.2"));
//
//	//recv packet and save to hash table
//	memcpy(packet, &eth, sizeof(struct ether_hdr));
//	memcpy(packet + sizeof(struct ether_hdr), &arp_pkt, sizeof(struct arp_hdr));
//	parse_arp(ctx, packet);
//
//	//recv again
//	parse_arp(ctx, packet);
//
//	//change mac address and recv again
//	memset(&(eth.s_addr.addr_bytes), 0x03, ETHER_ADDR_LEN);
//	memset(&(arp_pkt.arp_data.arp_sha.addr_bytes), 0x03, ETHER_ADDR_LEN);
//	memcpy(packet, &eth, sizeof(struct ether_hdr));
//	memcpy(packet + sizeof(struct ether_hdr), &arp_pkt, sizeof(struct arp_hdr));
//	parse_arp(ctx, packet);
//
//	//change mac address and recv again
//	arp_pkt.arp_data.arp_sip = inet_addr("192.168.1.4");
//
//	memset(&(arp_pkt.arp_data.arp_sha), 0x03, ETHER_ADDR_LEN);
//	memcpy(packet + sizeof(struct ether_hdr), &arp_pkt, sizeof(struct arp_hdr));
//	parse_arp(ctx, packet);
//
//	//test add tab
//	printf("----------------------\n");
//	printf("add tab test\n");
//	add_tab(ctx, inet_addr("192.168.1.3"), &(arp_pkt.arp_data.arp_sha));
//	printf("----------------------\n\n");
//
//	//test find
//
//	mac = find_tab(ctx, inet_addr("192.168.1.3"));
//
//	show_table(ctx);
//}