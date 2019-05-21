#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "uthash.h"

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

struct nat {
	uint32_t in_ip;
	uint32_t in_netmask;
	uint32_t out_ip;
	struct nat_table *stab;
	struct nat_table *dtab;
};

char *addr(uint32_t ip) {
	struct in_addr temp;
	temp.s_addr = ip;
	return inet_ntoa(temp);
}

void init(struct nat *ctx, uint32_t in_ip, uint32_t in_netmask, uint32_t out_ip) {
	memset(ctx, 0, sizeof(struct nat));
	ctx->in_ip = in_ip;
	ctx->in_netmask = in_netmask;
	ctx->out_ip = out_ip;
	printf("====== init =====\n");
	printf("in_ip:%s(%#x)\t", addr(ctx->in_ip));
	printf("in_netmask:%s(%#x)\t", addr(ctx->in_netmask));
	printf("out_ip:%s(%#x)\n", addr(ctx->out_ip));
	printf("=================\n\n");
}

uint16_t malloc_port(struct tuple *packet) {
	//It will be complex if i find an unused port
	//So i use local area network source port
	return packet->src_port;
}

void snat(struct nat *ctx, struct tuple *packet) {
	struct nat_table *obj;

	HASH_FIND(shh, ctx->stab, packet, sizeof(struct tuple), obj);
	if (!obj) {
		printf("new connection\n");
		obj = (struct nat_table *) malloc(sizeof(struct nat_table));
		memset(obj, 0, sizeof(struct nat_table));

		memcpy(&(obj->snat), packet, sizeof(struct tuple));
		obj->dnat.dst_ip = ctx->out_ip;
		obj->dnat.dst_port = malloc_port(packet);
		obj->dnat.src_ip = packet->dst_ip;
		obj->dnat.src_port = packet->dst_port;
		obj->dnat.proto = packet->proto;

		HASH_ADD(shh, ctx->stab, snat, sizeof(struct tuple), obj);
		HASH_ADD(dhh, ctx->dtab, dnat, sizeof(struct tuple), obj);
	}
	packet->src_ip = ctx->out_ip;
	packet->src_port = obj->dnat.dst_port;
}

void dnat(struct nat *ctx, struct tuple *packet) {
	struct nat_table *obj;

	HASH_FIND(dhh, ctx->dtab, packet, sizeof(struct tuple), obj);
	if (!obj) {
		printf("unsupport packet\n");
		return;
	}

	packet->dst_ip = obj->snat.src_ip;
	packet->dst_port = obj->snat.src_port;
}

void forward(struct tuple *packet) {
	return;
}

void deal(struct nat *ctx, struct tuple *packet) {
	printf("=================\n");
	printf("src_ip:%s(%#x)\tsrc_port:%d\tpro:%d\t",
		   addr(packet->src_ip), packet->src_ip, ntohs(packet->src_port), packet->proto);
	printf("dst_ip:%s(%#x)\tdst_port:%d\n",
		   addr(packet->dst_ip), packet->dst_ip, ntohs(packet->dst_port));
	printf("-----------------\n");
	if ((packet->src_ip & ctx->in_netmask) == (ctx->in_ip & ctx->in_netmask) &&
		(packet->dst_ip & ctx->in_netmask) == (ctx->in_ip & ctx->in_netmask)) {
		printf("local to local\n");
		forward(packet);
	} else if ((packet->src_ip & ctx->in_netmask) == (ctx->in_ip & ctx->in_netmask) &&
			   (packet->dst_ip & ctx->in_netmask) != (ctx->in_ip & ctx->in_netmask)) {
		printf("local to internet\n");
		snat(ctx, packet);
	} else if ((packet->src_ip & ctx->in_netmask) != (ctx->in_ip & ctx->in_netmask) &&
			   packet->dst_ip == ctx->out_ip) {
		printf("internet to local\n");
		dnat(ctx, packet);
	} else {
		printf("not interest\n");
	}
	printf("src_ip:%s(%#x)\tsrc_port:%d\tpro:%d\t",
		   addr(packet->src_ip), packet->src_ip, ntohs(packet->src_port), packet->proto);
	printf("dst_ip:%s(%#x)\tdst_port:%d\n",
		   addr(packet->dst_ip), packet->dst_ip, ntohs(packet->dst_port));
	printf("=================\n\n");
}

int main() {
	struct tuple packet1 = {
			.src_ip=inet_addr("192.168.1.2"),
			.src_port=htons(11111),
			.dst_ip=inet_addr("114.114.114.114"),
			.dst_port=htons(53),
			.proto=IPPROTO_UDP
	};

	struct tuple packet2 = {
			.src_ip=inet_addr("192.168.1.2"),
			.src_port=htons(11111),
			.dst_ip=inet_addr("114.114.114.114"),
			.dst_port=htons(53),
			.proto=IPPROTO_UDP
	};

	struct tuple packet3 = {
			.src_ip=inet_addr("114.114.114.114"),
			.src_port=htons(53),
			.dst_ip=inet_addr("1.1.1.1"),
			.dst_port=htons(11111),
			.proto=IPPROTO_UDP
	};

	struct tuple packet4 = {
			.src_ip=inet_addr("114.114.114.114"),
			.src_port=htons(53),
			.dst_ip=inet_addr("1.1.1.1"),
			.dst_port=htons(11112),
			.proto=IPPROTO_UDP
	};

	struct tuple packet5 = {
			.src_ip=inet_addr("192.168.1.2"),
			.src_port=htons(12344),
			.dst_ip=inet_addr("192.168.1.3"),
			.dst_port=htons(80),
			.proto=IPPROTO_TCP
	};

	struct tuple packet6 = {
			.src_ip=inet_addr("114.114.114.114"),
			.src_port=htons(12345),
			.dst_ip=inet_addr("8.8.8.8"),
			.dst_port=htons(80),
			.proto=IPPROTO_TCP
	};
	struct nat *ctx = (struct nat *) malloc(sizeof(struct nat));

	init(ctx, inet_addr("192.168.1.1"), inet_addr("255.255.255.0"), inet_addr("1.1.1.1"));

	deal(ctx, &packet1);
	deal(ctx, &packet2);
	deal(ctx, &packet3);
	deal(ctx, &packet4);
	deal(ctx, &packet5);
	deal(ctx, &packet6);

	return 0;
}