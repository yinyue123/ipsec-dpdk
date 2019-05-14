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

struct dnat_key {
	uint32_t aim_ip;
	uint16_t aim_port;
	uint16_t out_port;
	uint8_t proto;
};

struct nat_table {
	struct dnat_key dnat_key;
	struct tuple snat_key;
	uint32_t in_ip;
//	uint32_t aim_ip;	//not use
	uint16_t in_port;
	uint16_t out_port;
//	uint16_t aim_port;	//not use
//	uint8_t proto;		//not use
	UT_hash_handle shh;
	UT_hash_handle dhh;
};

struct nat_ip {
	uint32_t in_ip;
	uint32_t in_netmask;
	uint32_t out_ip;
};

struct nat_ip nat_ip;
struct nat_table *snat_table = NULL;
struct nat_table *dnat_table = NULL;

char *addr(uint32_t ip) {
	struct in_addr temp;
	temp.s_addr = ip;
	return inet_ntoa(temp);
}

void init(uint32_t in_ip, uint32_t in_netmask, uint32_t out_ip) {
	nat_ip.in_ip = in_ip;
	nat_ip.in_netmask = in_netmask;
	nat_ip.out_ip = out_ip;
	printf("====== init =====\n");
	printf("in_ip:%s(%#x)\t", addr(nat_ip.in_ip));
	printf("in_netmask:%s(%#x)\t", addr(nat_ip.in_netmask));
	printf("out_ip:%s(%#x)\n", addr(nat_ip.out_ip));
	printf("=================\n\n");
}

uint16_t malloc_port(struct tuple *packet) {
	//It will be complex if i find an unused port
	//So i use local area network source port
	return packet->src_port;
}

void snat(struct tuple *packet) {
	struct nat_table *s_obj;

	HASH_FIND(shh, snat_table, packet, sizeof(struct tuple), s_obj);
	if (!s_obj) {
		printf("new connection\n");
		s_obj = (struct nat_table *) malloc(sizeof(struct nat_table));
		memset(s_obj, 0, sizeof(struct nat_table));

//		s_obj->aim_ip = packet->dst_ip;
//		s_obj->aim_port = packet->dst_port;
		s_obj->in_ip = packet->src_ip;
		s_obj->in_port = packet->src_port;
		s_obj->out_port = malloc_port(packet);
//		s_obj->proto = packet->proto;

		s_obj->snat_key.proto = packet->proto;
		s_obj->snat_key.src_ip = packet->src_ip;
		s_obj->snat_key.dst_ip = packet->dst_ip;
		s_obj->snat_key.src_port = packet->src_port;
		s_obj->snat_key.dst_port = packet->dst_port;

		s_obj->dnat_key.aim_ip = packet->dst_ip;
		s_obj->dnat_key.out_port = s_obj->out_port;
		s_obj->dnat_key.aim_port = packet->dst_port;
		s_obj->dnat_key.proto = packet->proto;

		HASH_ADD(shh, snat_table, snat_key, sizeof(struct tuple), s_obj);
		HASH_ADD(dhh, dnat_table, dnat_key, sizeof(struct dnat_key), s_obj);
	}
	packet->src_ip = nat_ip.out_ip;
	packet->src_port = s_obj->out_port;
}

void dnat(struct tuple *packet) {
	struct nat_table *d_obj;
	struct dnat_key key;
	memset(&key, 0, sizeof(struct dnat_key));
	key.proto = packet->proto;
	key.aim_ip = packet->src_ip;
	key.aim_port = packet->src_port;
	key.out_port = packet->dst_port;

	HASH_FIND(dhh, dnat_table, &key, sizeof(struct dnat_key), d_obj);
	if(!d_obj){
		printf("unsupport packet\n");
		return ;
	}

	packet->dst_ip=d_obj->in_ip;
	packet->dst_port=d_obj->in_port;
}

void forward(struct tuple *packet) {
	return;
}

void deal(struct tuple packet) {
	printf("=================\n");
	printf("src_ip:%s(%#x)\tsrc_port:%d\tpro:%d\t",
		   addr(packet.src_ip), packet.src_ip, ntohs(packet.src_port), packet.proto);
	printf("dst_ip:%s(%#x)\tdst_port:%d\n",
		   addr(packet.dst_ip), packet.dst_ip, ntohs(packet.dst_port));
	printf("-----------------\n");
	if ((packet.src_ip & nat_ip.in_netmask) == (nat_ip.in_ip & nat_ip.in_netmask) &&
		(packet.dst_ip & nat_ip.in_netmask) == (nat_ip.in_ip & nat_ip.in_netmask)) {
		printf("local to local\n");
		forward(&packet);
	} else if ((packet.src_ip & nat_ip.in_netmask) == (nat_ip.in_ip & nat_ip.in_netmask) &&
			   (packet.dst_ip & nat_ip.in_netmask) != (nat_ip.in_ip & nat_ip.in_netmask)) {
		printf("local to internet\n");
		snat(&packet);
	} else if ((packet.src_ip & nat_ip.in_netmask) != (nat_ip.in_ip & nat_ip.in_netmask) &&
			   packet.dst_ip == nat_ip.out_ip) {
		printf("internet to local\n");
		dnat(&packet);
	} else {
		printf("not interest\n");
	}
	printf("src_ip:%s(%#x)\tsrc_port:%d\tpro:%d\t",
		   addr(packet.src_ip), packet.src_ip, ntohs(packet.src_port), packet.proto);
	printf("dst_ip:%s(%#x)\tdst_port:%d\n",
		   addr(packet.dst_ip), packet.dst_ip, ntohs(packet.dst_port));
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

	init(inet_addr("192.168.1.1"), inet_addr("255.255.255.0"), inet_addr("1.1.1.1"));

	deal(packet1);
	deal(packet2);
	deal(packet3);
	deal(packet4);
	deal(packet5);
	deal(packet6);

	return 0;
}