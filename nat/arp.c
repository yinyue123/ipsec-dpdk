#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
//#include <net/if_arp.h>
#include "uthash.h"

// rte_ether.h
#define ETHER_ADDR_LEN  6
#define ETHER_TYPE_ARP  0x0806

struct ether_addr {
	uint8_t addr_bytes[ETHER_ADDR_LEN];
} __attribute__((__packed__));

struct ether_hdr {
	struct ether_addr d_addr;
	struct ether_addr s_addr;
	uint16_t ether_type;
} __attribute__((__packed__));
//

// net/if_arp.h
struct arp_hdr {
	unsigned short ar_hrd;    /* format of hardware address */
#define ARPHRD_ETHER    1    /* ethernet hardware format */
#define ARPHRD_FRELAY    15    /* frame relay hardware format */
	unsigned short ar_pro;    /* format of protocol address */
	unsigned char ar_hln;    /* length of hardware address */
	unsigned char ar_pln;    /* length of protocol address */
	unsigned short ar_op;    /* one of: */
#define    ARPOP_REQUEST    1    /* request to resolve address */
#define    ARPOP_REPLY        2    /* response to previous request */
#define    ARPOP_REVREQUEST 3    /* request protocol address given hardware */
#define    ARPOP_REVREPLY    4    /* response giving protocol address */
#define ARPOP_INVREQUEST 8    /* request to identify peer */
#define ARPOP_INVREPLY    9    /* response identifying peer */

	unsigned char ar_sha[ETHER_ADDR_LEN];    /* sender hardware address */
	unsigned char ar_sip[4];    /* sender protocol address */
	unsigned char ar_tha[ETHER_ADDR_LEN];    /* target hardware address */
	unsigned char ar_tip[4];    /* target protocol address */
} __attribute__((__packed__));
//

// netinet/if_ether.h
#define    ETHERTYPE_IP    0x0800        /* IP protocol */
//

// linux/if_ether.h
#define ETH_ALEN 6
//

struct arp_table {
	uint32_t ip;
	unsigned char mac[ETHER_ADDR_LEN];
	UT_hash_handle hh;
};

struct arp {
	uint32_t local_ip;
	unsigned char local_mac[ETHER_ADDR_LEN];
	struct arp_table *atap;

};

void printHex(unsigned char *ptr, int len) {
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

char *addr(uint32_t ip) {
	struct in_addr temp;
	temp.s_addr = ip;
	return inet_ntoa(temp);
}

void init(struct arp *ctx, uint32_t local_ip, unsigned char *local_mac) {
	memset(ctx, 0, sizeof(struct arp));
	ctx->local_ip = local_ip;
	memcpy(&(ctx->local_mac), local_mac, ETHER_ADDR_LEN);
	printf("------ arp init ------\n");
	printf("local:\t%s(%02X:%02X:%02X:%02X:%02X:%02X)\n", addr(local_ip),
		   local_mac[0], local_mac[1], local_mac[2], local_mac[3], local_mac[4], local_mac[5]);
	printf("----------------------\n\n");
}

unsigned char *find_tab(struct arp *ctx, uint32_t ip) {
	struct arp_table *obj = NULL;
	printf("----------------------\n");
	printf("find tab test\n");
	HASH_FIND(hh, ctx->atap, &ip, sizeof(uint32_t), obj);
	if (obj) {
		printf("%s(%02X:%02X:%02X:%02X:%02X:%02X)\n", addr(ip),
			   obj->mac[0], obj->mac[1], obj->mac[2],
			   obj->mac[3], obj->mac[4], obj->mac[5]);
		printf("----------------------\n\n");
		return obj->mac;
	} else {
		printf("arp table not found\n");
		printf("----------------------\n\n");
		return NULL;
	}
}

void add_tab(struct arp *ctx, uint32_t ip, unsigned char *mac) {
	struct arp_table *obj = NULL;
	HASH_FIND(hh, ctx->atap, &ip, sizeof(uint32_t), obj);
	if (!obj) {
		printf("new arp\t");
		obj = (struct arp_table *) malloc(sizeof(struct arp_table));
		memset(obj, 0, sizeof(struct arp_table));
		obj->ip = ip;
		memcpy(&(obj->mac), mac, ETHER_ADDR_LEN);
		HASH_ADD(hh, ctx->atap, ip, sizeof(uint32_t), obj);
	} else if (memcmp(obj->mac, mac, ETHER_ADDR_LEN)) {
		printf("renew arp\t");
		memcpy(obj->mac, mac, ETHER_ADDR_LEN);
	}

	printf("%s(%02X:%02X:%02X:%02X:%02X:%02X)\n", addr(ip), mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void prepare_arp(struct arp *ctx, unsigned char *pkt, uint32_t target_ip) {    // send
	struct ether_hdr *eth = (struct ether_hdr *) pkt;
	struct arp_hdr *arp = (struct arp_hdr *) (pkt + sizeof(struct ether_hdr));
	printf("----------------------\n");
	printf("prepare arp packet\n");
	memset(&(eth->d_addr), 0xff, ETHER_ADDR_LEN);
	memcpy(&(eth->s_addr), &(ctx->local_mac), ETHER_ADDR_LEN);
	eth->ether_type = htons(ETHER_TYPE_ARP);

	arp->ar_hrd = htons(ARPHRD_ETHER);
	arp->ar_pro = htons(ETHERTYPE_IP);
	arp->ar_hln = ETH_ALEN;
	arp->ar_pln = 4;
	arp->ar_op = htons(ARPOP_REQUEST);
	((uint32_t *) arp->ar_sip)[0] = ctx->local_ip;
	((uint32_t *) arp->ar_tip)[0] = target_ip;
	memset(&(arp->ar_tha), 0x00, ETHER_ADDR_LEN);
	memcpy(&(arp->ar_sha), ctx->local_mac, ETHER_ADDR_LEN);
	printHex(pkt, sizeof(struct ether_hdr) + sizeof(struct arp_hdr));
	printf("----------------------\n\n");
}

void parse_arp(struct arp *ctx, unsigned char *pkt) {        //recv
	struct ether_hdr *eth = (struct ether_hdr *) pkt;
	struct arp_hdr *arp_pkt = (struct arp_hdr *) (pkt + sizeof(struct ether_hdr));
	struct arp_hdr chk = {
			.ar_hrd=htons(ARPHRD_ETHER),
			.ar_pro=htons(ETHERTYPE_IP),
			.ar_hln=ETH_ALEN,
			.ar_pln=4,
			.ar_op=htons(ARPOP_REPLY),
	};
	printf("----------------------\n");
	printf("parse arp packet\n");
	printHex(pkt, sizeof(struct ether_hdr) + sizeof(struct arp_hdr));
//	printHex(arp_pkt, sizeof(struct arp_hdr));
	if (eth->ether_type != htons(ETHER_TYPE_ARP) ||
		memcmp(eth->d_addr.addr_bytes, ctx->local_mac, ETHER_ADDR_LEN) ||
		memcmp(eth->s_addr.addr_bytes, arp_pkt->ar_sha, ETHER_ADDR_LEN)) {
		printf("not interest\n");
		return;
	}
	*((uint32_t *) chk.ar_sip) = *((uint32_t *) arp_pkt->ar_sip);
	*((uint32_t *) chk.ar_tip) = ctx->local_ip;
	memcpy(&(chk.ar_sha), &(arp_pkt->ar_sha), ETHER_ADDR_LEN);
	memcpy(&(chk.ar_tha), &(arp_pkt->ar_tha), ETHER_ADDR_LEN);
	if (memcmp(&chk, arp_pkt, sizeof(struct arp_hdr))) {
		printf("arp reply not match\n");
		return;
	}
	add_tab(ctx, *((uint32_t *) arp_pkt->ar_sip), arp_pkt->ar_sha);
	printf("----------------------\n\n");
}

void show_table(struct arp *ctx) {
	struct arp_table *s, *tmp;
	printf("----------------------\n");
	printf("show tab test\n");
	HASH_ITER(hh, ctx->atap, s, tmp) {
		printf("key:%s\tvalue:%02X:%02X:%02X:%02X:%02X:%02X\n",
			   addr(s->ip),s->mac[0],s->mac[1],s->mac[2],
			   s->mac[3],s->mac[4],s->mac[5]);
	}
	printf("----------------------\n\n");
}


int main() {
	struct arp *ctx = (struct arp *) malloc(sizeof(struct arp));
	unsigned char *packet = (unsigned char *) malloc(sizeof(struct ether_hdr) + sizeof(struct arp_hdr));
	struct ether_hdr eth = {
			.s_addr={0x02, 0x02, 0x02, 0x02, 0x02, 0x02},
			.d_addr={0x01, 0x01, 0x01, 0x01, 0x01, 0x01},
			.ether_type=htons(ETHER_TYPE_ARP)
	};
	struct arp_hdr arp_pkt = {
			.ar_hrd=htons(ARPHRD_ETHER),
			.ar_pro=htons(ETHERTYPE_IP),
			.ar_hln=ETH_ALEN,
			.ar_pln=4,
			.ar_op=htons(ARPOP_REPLY),
			.ar_sha={0x02, 0x02, 0x02, 0x02, 0x02, 0x02},
			.ar_tha={0x01, 0x01, 0x01, 0x01, 0x01, 0x01}
	};
	unsigned char *mac;

	((uint32_t *) arp_pkt.ar_sip)[0] = inet_addr("192.168.1.2");
	((uint32_t *) arp_pkt.ar_tip)[0] = inet_addr("192.168.1.1");

	init(ctx, inet_addr("192.168.1.1"), arp_pkt.ar_tha);

	//prepare packet from send
	prepare_arp(ctx, packet, inet_addr("192.168.1.2"));

	//recv packet and save to hash table
	memcpy(packet, &eth, sizeof(struct ether_hdr));
	memcpy(packet + sizeof(struct ether_hdr), &arp_pkt, sizeof(struct arp_hdr));
	parse_arp(ctx, packet);

	//recv again
	parse_arp(ctx, packet);

	//change mac address and recv again
	memset(&(eth.s_addr), 0x03, ETHER_ADDR_LEN);
	memset(&(arp_pkt.ar_sha), 0x03, ETHER_ADDR_LEN);
	memcpy(packet, &eth, sizeof(struct ether_hdr));
	memcpy(packet + sizeof(struct ether_hdr), &arp_pkt, sizeof(struct arp_hdr));
	parse_arp(ctx, packet);

	//change mac address and recv again
	*((uint32_t *) arp_pkt.ar_sip) = inet_addr("192.168.1.4");
	memset(&(arp_pkt.ar_sha), 0x03, ETHER_ADDR_LEN);
	memcpy(packet + sizeof(struct ether_hdr), &arp_pkt, sizeof(struct arp_hdr));
	parse_arp(ctx, packet);

	//test add tab
	printf("----------------------\n");
	printf("add tab test\n");
	add_tab(ctx, inet_addr("192.168.1.3"), arp_pkt.ar_sha);
	printf("----------------------\n\n");

	//test find

	mac = find_tab(ctx, inet_addr("192.168.1.3"));

	show_table(ctx);
}