//
// Created by 殷悦 on 17/05/2019.
//

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "uthash.h"
#include "iptables.h"

static char *addr(uint32_t ip) {
	struct in_addr temp;
	temp.s_addr = ip;
	return inet_ntoa(temp);
}

//void init(struct gateway_ctx *ctx, uint32_t lan_ip, uint32_t lan_netmask, uint32_t wan_ip) {
//	memset(ctx, 0, sizeof(struct gateway_ctx));
//	ctx->lan_ip = lan_ip;
//	ctx->lan_netmask = lan_netmask;
//	ctx->wan_ip = wan_ip;
//	printf("====== init =====\n");
//	printf("lan_ip:%s(%#x)\t", addr(ctx->lan_ip));
//	printf("lan_netmask:%s(%#x)\t", addr(ctx->lan_netmask));
//	printf("wan_ip:%s(%#x)\n", addr(ctx->wan_ip));
//	printf("=================\n\n");
//}

static int16_t malloc_port(struct tuple *packet) {
	//It will be complex if i find an unused port
	//So i use local area network source port
	return packet->src_port;
}

static void snat(struct gateway_ctx *ctx, struct tuple *packet) {
	struct nat_table *obj;

	HASH_FIND(shh, ctx->snat_tab, packet, sizeof(struct tuple), obj);
	if (!obj) {
		printf("new connection\n");
		obj = (struct nat_table *) malloc(sizeof(struct nat_table));
		if (obj == NULL) {
			printf("malloc error\n");
		}
		memset(obj, 0, sizeof(struct nat_table));

		memcpy(&(obj->snat), packet, sizeof(struct tuple));
		obj->dnat.dst_ip = ctx->wan_ip;
		obj->dnat.dst_port = malloc_port(packet);
		obj->dnat.src_ip = packet->dst_ip;
		obj->dnat.src_port = packet->dst_port;
		obj->dnat.proto = packet->proto;

		HASH_ADD(shh, ctx->snat_tab, snat, sizeof(struct tuple), obj);
		HASH_ADD(dhh, ctx->dnat_tab, dnat, sizeof(struct tuple), obj);
	}
	packet->src_ip = ctx->wan_ip;
	packet->src_port = obj->dnat.dst_port;
}

static int dnat(struct gateway_ctx *ctx, struct tuple *packet) {
	struct nat_table *obj;

	HASH_FIND(dhh, ctx->dnat_tab, packet, sizeof(struct tuple), obj);
	if (!obj) {
		printf("unsupport packet\n");
		return 0;
	}
	packet->dst_ip = obj->snat.src_ip;
	packet->dst_port = obj->snat.src_port;
	return 1;
}

static void forward(struct tuple *packet) {
	(void)(packet);
	return;
}

void print_tuple(struct tuple *packet) {
	printf("src_ip:%s(%#x)\tsrc_port:%d\t",
		   addr(packet->src_ip), packet->src_ip, ntohs(packet->src_port));
	printf("pro:%d(%s)\t",
		   packet->proto,
		   packet->proto == IPPROTO_TCP ? "TCP" :
		   packet->proto == IPPROTO_UDP ? "UDP" :
		   packet->proto == IPPROTO_ICMP ? "ICMP" : "OTHER");
	printf("dst_ip:%s(%#x)\tdst_port:%d\n",
		   addr(packet->dst_ip), packet->dst_ip, ntohs(packet->dst_port));
}

int check_dnat(struct gateway_ctx *ctx, struct tuple *packet) {
	if ((packet->src_ip & ctx->lan_netmask) != (ctx->lan_ip & ctx->lan_netmask) &&
		packet->dst_ip == ctx->wan_ip) {
		printf("DNAT:internet to local\n");
		return dnat(ctx, packet);
	}
	return 0;
}

int check_snat(struct gateway_ctx *ctx, struct tuple *packet) {
	if ((packet->src_ip & ctx->lan_netmask) == (ctx->lan_ip & ctx->lan_netmask) &&
		(packet->dst_ip & ctx->lan_netmask) != (ctx->lan_ip & ctx->lan_netmask)) {
		printf("SNAT:local to internet\n");
		snat(ctx, packet);
		return 1;
	}
	return 0;
}

int check_forward(struct gateway_ctx *ctx, struct tuple *packet) {
	if ((packet->src_ip & ctx->lan_netmask) == (ctx->lan_ip & ctx->lan_netmask) &&
		(packet->dst_ip & ctx->lan_netmask) == (ctx->lan_ip & ctx->lan_netmask)) {
		printf("FORWARD:local to local\n");
		forward(packet);
		return 1;
	}
	return 0;
}

//static void cal_nat(struct gateway_ctx *ctx, struct tuple *packet) {
//	printf("=================\n");
//	print_tuple(packet);
//	printf("-----------------\n");
//	if (check_forward(ctx, packet)) {
//
//	} else if (check_snat(ctx, packet)) {
//
//	} else if (check_dnat(ctx, packet)) {
//
//	} else {
//		printf("not interest\n");
//	}
//	print_tuple(packet);
//	printf("=================\n\n");
//}

//int main() {
//	struct tuple packet1 = {
//			.src_ip=inet_addr("192.168.1.2"),
//			.src_port=htons(11111),
//			.dst_ip=inet_addr("114.114.114.114"),
//			.dst_port=htons(53),
//			.proto=IPPROTO_UDP
//	};
//
//	struct tuple packet2 = {
//			.src_ip=inet_addr("192.168.1.2"),
//			.src_port=htons(11111),
//			.dst_ip=inet_addr("114.114.114.114"),
//			.dst_port=htons(53),
//			.proto=IPPROTO_UDP
//	};
//
//	struct tuple packet3 = {
//			.src_ip=inet_addr("114.114.114.114"),
//			.src_port=htons(53),
//			.dst_ip=inet_addr("1.1.1.1"),
//			.dst_port=htons(11111),
//			.proto=IPPROTO_UDP
//	};
//
//	struct tuple packet4 = {
//			.src_ip=inet_addr("114.114.114.114"),
//			.src_port=htons(53),
//			.dst_ip=inet_addr("1.1.1.1"),
//			.dst_port=htons(11112),
//			.proto=IPPROTO_UDP
//	};
//
//	struct tuple packet5 = {
//			.src_ip=inet_addr("192.168.1.2"),
//			.src_port=htons(12344),
//			.dst_ip=inet_addr("192.168.1.3"),
//			.dst_port=htons(80),
//			.proto=IPPROTO_TCP
//	};
//
//	struct tuple packet6 = {
//			.src_ip=inet_addr("114.114.114.114"),
//			.src_port=htons(12345),
//			.dst_ip=inet_addr("8.8.8.8"),
//			.dst_port=htons(80),
//			.proto=IPPROTO_TCP
//	};
//	struct gateway_ctx *ctx = (struct gateway_ctx *) malloc(sizeof(struct gateway_ctx));
//	if (ctx == NULL) {
//		printf("malloc error\n");
//	}
//
//	init(ctx, inet_addr("192.168.1.1"), inet_addr("255.255.255.0"), inet_addr("1.1.1.1"));
//
//	cal_nat(ctx, &packet1);
//	cal_nat(ctx, &packet2);
//	cal_nat(ctx, &packet3);
//	cal_nat(ctx, &packet4);
//	cal_nat(ctx, &packet5);
//	cal_nat(ctx, &packet6);
//
//	return 0;
//}