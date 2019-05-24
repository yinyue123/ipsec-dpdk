//
// Created by 殷悦 on 28/01/2019.
//

/*
    gcc xfrm_listen.c `pkg-config --cflags --libs libnl-3.0 libnl-xfrm-3.0`
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/xfrm.h>
#include <netlink/types.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <netlink/xfrm/sa.h>
#include <netlink/xfrm/sp.h>
#include <netlink/xfrm/selector.h>
#include <netlink/xfrm/template.h>

#include "xfrm.h"


struct shared_data {
	char localIp[16];

	uint32_t written;
	uint32_t n_tokens;
	char type[10];
	char *tokens[20];
	char tokens_save[20][100];
	struct parse_status status;
};

uint32_t spi_in, spi_out;
//static char localIp[16];

static struct shared_data *shared_mem;

void
dump_hex(char *buf, int len);

static int
parse_nlmsg(struct nl_msg *nlmsg, void *arg);

void
dump_hex(char *buf, int len) {
	int i;
	printf("0x");
	for (i = 0; i < len; i++) {
		printf("%02x", buf[i] & 0xff);
	}
	printf("\n");
}

static void
dump_hex_string(char *output, char *buf, int len) {
	int i, j;
	for (i = 0, j = 0; i < len; i++) {
		j += sprintf(output + j, "%02x:", buf[i] & 0xff);
	}
	output[strlen(output) - 1] = '\0';
}

static void
send_xfrm(const char *type, const char **tokens, uint32_t n_tokens, struct parse_status *status) {
	uint32_t i;
	while (shared_mem->written == 1) {
		//printf("wait to write xfrm data\n");
		usleep(10);
	}
	strcpy(shared_mem->type, type);
	shared_mem->n_tokens = n_tokens;
	for (i = 0; i < n_tokens; i++) {
		strcpy(shared_mem->tokens[i], tokens[i]);
	}
	shared_mem->status.status = status->status;
	strcpy(shared_mem->status.parse_msg, status->parse_msg);
	//memcpy(&shared_mem->status, status, sizeof(struct parse_status));
	shared_mem->written = 1;
}

void
recv_xfrm(void) {
	uint32_t i;
	if (shared_mem->written) {
		if (strcmp(shared_mem->type, "sa") == 0) {
			printf("recv_xfrm:sa\n");
			parse_sa_tokens(shared_mem->tokens, shared_mem->n_tokens, &shared_mem->status);
		}
		if (strcmp(shared_mem->type, "sp") == 0) {
			printf("recv_xfrm:sp\n");
			parse_sp4_tokens(shared_mem->tokens, shared_mem->n_tokens, &shared_mem->status);
		}
		for (i = 0; i < shared_mem->n_tokens; i++) {
			printf("%s ", shared_mem->tokens[i]);
		}
		printf("\n");
		shared_mem->written = 0;
	}
}

//void
//recv_xfrm(void) {
//	uint32_t i;
//	char* temp_tokens[20];
//	if (shared_mem->written) {
//		if (strcmp(shared_mem->type, "sa") == 0) {
//			printf("recv_xfrm:sa\n");
//			for (i = 0; i < shared_mem->n_tokens; i++) {
//				printf("%s ", shared_mem->tokens[i]);
//				temp_tokens[i]=(char *)malloc(sizeof(char)*(strlen(shared_mem->tokens[i])+1));
//				strcpy(temp_tokens[i],shared_mem->tokens[i]);
//			}
//			printf("\n");
//			parse_sa_tokens(temp_tokens, shared_mem->n_tokens, &shared_mem->status);
//			//parse_sa_tokens(shared_mem->tokens, shared_mem->n_tokens, &shared_mem->status);
//		}
//		shared_mem->written = 0;
//	}
//}

static void
add_sa(
		const char *in_out,
		const char *spi,
		const char *cipher_algo,
		const char *cipher_key,
		const char *auth_algo,
		const char *auth_key,
		const char *mode,
		const char *src,
		const char *dst
) {
	const char *tokens[16];
	struct parse_status status;
/*
	out--
	5--
	cipher_algo--
	aes-128-cbc--
	cipher_key--
	c3:c3:c3:c3:c3:c3:c3:c3:c3:c3:c3:c3:c3:c3:c3:c3--
    3f:dd:9f:49:6b:8e:1d:01:e2:3a:20:b8:e1:8f:bc:4a:
    f3:8a:cf:ab:7c:89:6f:b1:c2:10:72:c3:cc:62:26:6b
	auth_algo--sha1-hmac--
	auth_key--0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0--
	mode--ipv4-tunnel--
	src--172.16.1.5--
	dst--172.17.2.5--
	in--5--cipher_algo--aes-128-cbc--cipher_key--c3:c3:c3:c3:c3:c3:c3:c3:c3:c3:c3:c3:c3:c3:c3:c3--auth_algo--sha1-hmac--auth_key--0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0--mode--ipv4-tunnel--src--172.16.1.5--dst--172.17.2.5--
*/

	tokens[0] = in_out;
	tokens[1] = spi;
	tokens[2] = "cipher_algo";
	tokens[3] = cipher_algo;
	tokens[4] = "cipher_key";
	tokens[5] = cipher_key;
	tokens[6] = "auth_algo";
	tokens[7] = auth_algo;
	tokens[8] = "auth_key";
	tokens[9] = auth_key;
	tokens[10] = "mode";
	tokens[11] = mode;
	tokens[12] = "src";
	tokens[13] = src;
	tokens[14] = "dst";
	tokens[15] = dst;

	status.status = 0;
	status.parse_msg[0] = '\0';
	send_xfrm("sa", tokens, 16, &status);

}

static void
xfrm_add_addr(uint32_t addr) {
	struct in_addr addr_addr;
	addr_addr.s_addr = addr;
	if (strcmp(shared_mem->localIp, inet_ntoa(addr_addr))) {
		printf("---------------   KNI IP   ---------------\n");
		printf("localIp changed:\n");
		printf("origin localIp:\t%s\n", shared_mem->localIp);
		strcpy(shared_mem->localIp, inet_ntoa(addr_addr));
		printf("new localIp:\t%s\n", shared_mem->localIp);
		printf("------------------------------------------\n");
	}
}

static void
deal_sa(
		char *saddr,
		char *daddr,
		uint8_t proto,
		uint32_t spi,
		char *mode,
		char *auth_alg,
		char *auth_key,
		unsigned int auth_key_len,
		char *enc_alg,
		char *enc_key,
		unsigned int enc_key_len
) {
/*
 src : 192.168.10.120		 dst : 192.168.10.231
 proto : 50(esp:50 ah:51)		spi : 0x6a304f4
 repid : 1 		mode : tunnel
 replay window : 0
 hmac(sha1) 	0x47b224b8a178d11070b5fb561e0f047d7e160d35 len:160
 cbc(aes) 	0x39af2456054c8f07dbb3b9688e9c3454 len:128
 sel src : 00:00:00:00:00:	 dst : 00:00:00:00:00:
*/
	const char *s_in_out;
	char s_spi[20];
	const char *s_cipher_algo;
	char s_cipher_key[100];
	const char *s_auth_algo;
	char s_auth_key[100];
	const char *s_mode;
	const char *s_src;
	const char *s_dst;

	// check esp package
	if (proto != 50)
		return;

	// s_in_out
	//if (strcmp(saddr, localIp) == 0)
	printf("+++++++++ daddr:%s\tlocalIp:%s\n", daddr, shared_mem->localIp);
	if (strcmp(daddr, shared_mem->localIp) == 0) {
		spi_in = spi;
		s_in_out = "in";
	} else {
		spi_out = spi;
		s_in_out = "out";
	}

	// s_spi
	sprintf(s_spi, "%u", spi);

	// s_cipher_algo null aes-128-cbc aes-128-ctr aes-128-gcm
	if (strcmp(enc_alg, "cbc(aes)") == 0) {
		if (enc_key_len == 128) {
			s_cipher_algo = "aes-128-cbc";
		} else {
			printf("unsupport cipher algo length\n");
			return;
		}
	} else if (strcmp(enc_alg, "cbc(ctr)") == 0) {
		if (enc_key_len == 128) {
			s_cipher_algo = "aes-128-ctr";
		} else {
			printf("unsupport cipher algo length\n");
			return;
		}
	} else if (strcmp(enc_alg, "cbc(gcm)") == 0) {
		if (enc_key_len == 128) {
			s_cipher_algo = "aes-128-gcm";
		} else {
			printf("unsupport cipher algo length\n");
			return;
		}
	} else if (strcmp(enc_alg, "null") == 0) {
		s_cipher_algo = "null";
	}

	// s_cipher_key
	dump_hex_string(s_cipher_key, enc_key, enc_key_len / 8);

	// s_auth_algo
	if (strcmp(auth_alg, "hmac(sha1)") == 0) {
		if (auth_key_len == 160) {
			s_auth_algo = "sha1-hmac";
		} else {
			printf("unsupport cipher algo length\n");
			return;
		}
	} else if (strcmp(auth_alg, "hmac(sha256)") == 0) {
		if (auth_key_len == 256) {
			s_auth_algo = "sha256-hmac";
		} else {
			printf("unsupport cipher algo length\n");
			return;
		}
	} else if (strcmp(auth_alg, "gcm(aes)") == 0) {
		if (auth_key_len == 128) {
			s_auth_algo = "aes-128-gcm";
		} else {
			printf("unsupport cipher algo length\n");
			return;
		}
	} else if (strcmp(auth_alg, "null") == 0) {
		s_auth_algo = "null";
	}

	// s_auth_key
	dump_hex_string(s_auth_key, auth_key, auth_key_len / 8);

	//s_mode
	if (strcmp(mode, "tunnel") == 0) {
		s_mode = "ipv4-tunnel";
	} else if (strcmp(mode, "transport") == 0) {
		s_mode = "transport";
	} else
		s_mode = "";

	// s_src
	s_src = saddr;

	// s_dst
	s_dst = daddr;

	add_sa(s_in_out, s_spi, s_cipher_algo, s_cipher_key, s_auth_algo, s_auth_key, s_mode, s_src, s_dst);
}

static void
parse_sa(struct nlmsghdr *nlh) {
	//PFUNC();
	/*
	   libnl/include/netlink/xfrm/sa.h
	 */
	struct xfrmnl_sa *sa = xfrmnl_sa_alloc();
	xfrmnl_sa_parse(nlh, &sa);

//	struct xfrmnl_sel *sel = xfrmnl_sa_get_sel(sa);
//	struct nl_addr *sel_src = xfrmnl_sel_get_saddr(sel);
//	struct nl_addr *sel_dst = xfrmnl_sel_get_daddr(sel);
//	char src[16];
//	char dst[16];
//	nl_addr2str(sel_src, src, 16);
//	nl_addr2str(sel_dst, dst, 16);

	struct nl_addr *nlsaddr = xfrmnl_sa_get_saddr(sa);
	struct nl_addr *nldaddr = xfrmnl_sa_get_daddr(sa);
	char saddr[16];
	char daddr[16];
	nl_addr2str(nlsaddr, saddr, 16);
	nl_addr2str(nldaddr, daddr, 16);

/*
    # cat /etc/protocols |grep -i ipsec
    esp 50  IPSEC-ESP   # Encap Security Payload [RFC2406]
    ah  51  IPSEC-AH    # Authentication Header [RFC2402]
*/
	uint8_t proto = (uint8_t) xfrmnl_sa_get_proto(sa);
	uint32_t spi = (uint32_t) xfrmnl_sa_get_spi(sa);
	uint32_t reqid = xfrmnl_sa_get_reqid(sa);
	int mode = xfrmnl_sa_get_mode(sa);
	char s_mode[32];
	xfrmnl_sa_mode2str(mode, s_mode, 32);
	uint8_t replay_win = xfrmnl_sa_get_replay_window(sa);

	char enc_alg[64];
	char enc_key[1024];
	unsigned int enc_key_len;
	xfrmnl_sa_get_crypto_params(sa, enc_alg, &enc_key_len, enc_key);

	char auth_alg[64];
	char auth_key[1024];
	unsigned int auth_key_len;
	unsigned int auth_trunc_len;
	xfrmnl_sa_get_auth_params(sa, auth_alg, &auth_key_len, &auth_trunc_len,
							  auth_key);
/*
    dump to stdout
*/
	printf("---------------     SA     ---------------\n");
	printf(" src : %s\t\t dst : %s\n", saddr, daddr);
	printf(" proto : %d(esp:50 ah:51)\t\tspi : 0x%x \n", proto, spi);
	printf(" repid : %u \t\tmode : %s\n", reqid, s_mode);
	printf(" replay window : %d\n", replay_win);
	printf(" %s \t", auth_alg);
	dump_hex(auth_key, auth_key_len / 8);
	printf(" %s \t", enc_alg);
	dump_hex(enc_key, enc_key_len / 8);
//	printf(" sel src : %s\t dst : %s\n", src, dst);
	printf("------------------------------------------\n");
	if (nlh->nlmsg_type == XFRM_MSG_NEWSA || nlh->nlmsg_type == 26)
		deal_sa(saddr, daddr, proto, spi, s_mode, auth_alg, auth_key, auth_key_len, enc_alg, enc_key, enc_key_len);
	xfrmnl_sa_put(sa);
}

static void
add_sp(
		const char *ip_ver,
		const char *dir,
		const char *action,
		const char *priority,
		const char *src_ip,
		const char *dst_ip,
		const char *proto,
		const char *sport,
		const char *dport
) {
//		sp ipv4 out esp protect 5 dst 10.31.2.0/24 sport 0:65535 dport 0:65535
	const char *tokens[13];
	struct parse_status status;

	(void) proto;

	tokens[0] = ip_ver;
	tokens[1] = dir;
	tokens[2] = "esp";
	tokens[3] = action;
	tokens[4] = priority;
	tokens[5] = "src";
	tokens[6] = src_ip;
	tokens[7] = "dst";
	tokens[8] = dst_ip;
	tokens[9] = "sport";
	tokens[10] = sport;
	tokens[11] = "dport";
	tokens[12] = dport;

	status.status = 0;
	status.parse_msg[0] = '\0';
	send_xfrm("sp", tokens, 13, &status);
}

static void
deal_sp(
		int dir,
		int action,
		int priority,
		char *saddr,
		int prefixlen_s,
		char *daddr,
		int prefixlen_d,
		int proto,
		int sport,
		int sport_mask,
		int dport,
		int dport_mask
) {
	const char *ip_ver = "ipv4";
	const char *s_dir = dir ? (dir == 1 ? "out" : "fwd") : "in";
	const char *s_action = action ? "protect" : "discard";
//	char s_priority[20];
	char s_spi[20];
	char s_src_ip[20];
	char s_dst_ip[20];
	char s_proto[20];
	const char *s_sport = "0:65535";
	const char *s_dport = "0:65535";
//	sprintf(s_priority, "%d", priority);
	sprintf(s_spi, "%u", dir ? (dir == 1 ? spi_out : 0) : spi_in);
	sprintf(s_src_ip, "%s/%d", saddr, prefixlen_s);
	sprintf(s_dst_ip, "%s/%d", daddr, prefixlen_d);
	sprintf(s_proto, "%d", proto);
	(void) proto;
	(void) sport;
	(void) sport_mask;
	(void) dport;
	(void) dport_mask;
	(void) priority;

	add_sp(ip_ver, s_dir, s_action, s_spi, s_src_ip, s_dst_ip, s_proto, s_sport, s_dport);

};

static void
parse_sp(struct nlmsghdr *nlh) {
	struct xfrmnl_sp *sp = xfrmnl_sp_alloc();
	xfrmnl_sp_parse(nlh, &sp);

	struct xfrmnl_sel *sel = xfrmnl_sp_get_sel(sp);
	char saddr[16], daddr[16];
	int prefixlen_s, prefixlen_d, dport, dport_mask, sport, sport_mask;
	nl_addr2str(xfrmnl_sel_get_saddr(sel), saddr, 16);
	nl_addr2str(xfrmnl_sel_get_daddr(sel), daddr, 16);
	strtok(saddr, "/");
	strtok(daddr, "/");
	prefixlen_s = xfrmnl_sel_get_prefixlen_s(sel);
	prefixlen_d = xfrmnl_sel_get_prefixlen_d(sel);
	sport = xfrmnl_sel_get_sport(sel);
	sport_mask = xfrmnl_sel_get_sportmask(sel);
	dport = xfrmnl_sel_get_dport(sel);
	dport_mask = xfrmnl_sel_get_dportmask(sel);

	int dir, priority, userpolicy, index, action;
	dir = xfrmnl_sp_get_dir(sp);
	priority = xfrmnl_sp_get_priority(sp);
	userpolicy = xfrmnl_sp_get_userpolicy_type(sp);
	index = xfrmnl_sp_get_index(sp);
	action = xfrmnl_sp_get_action(sp);

	int family, proto, ifindex, userid;
	family = xfrmnl_sel_get_family(sel);
	proto = xfrmnl_sel_get_proto(sel);
	ifindex = xfrmnl_sel_get_ifindex(sel);
	userid = xfrmnl_sel_get_userid(sel);

	printf("---------------     SP     ---------------\n");
	printf(" src : %s/%d\tdst : %s/%d\n", saddr, prefixlen_s, daddr, prefixlen_d);
	printf(" sport : %d/%d\tdport : %d/%d\n", sport, sport_mask, dport, dport_mask);
	printf(" dir : %s\tpriority : %d\n", dir ? (dir == 1 ? "out" : "fwd") : "in", priority);
	printf(" ptype : %d\tindex : %d\taction : %d\n", userpolicy, index, action);
	printf(" family : %d\tproto : %d\n", family, proto);
	printf(" ifindex : %d\tuserid : %d\n", ifindex, userid);
	printf("------------------------------------------\n");

	if (nlh->nlmsg_type == XFRM_MSG_NEWPOLICY && dir != 2) {
		deal_sp(dir, action, priority, saddr, prefixlen_s, daddr, prefixlen_d, proto, sport, sport_mask, dport,
				dport_mask);
	}
	xfrmnl_sp_put(sp);
	/*
	   libnl/include/netlink/xfrm/sp.h
	 */
}

static int
parse_nlmsg(struct nl_msg *nlmsg, void *arg) {
	//PFUNC();
	//nlmsg_type_map();
	//nl_msg_dump(nlmsg, stdout);
	(void) arg;
	struct nlmsghdr *nlhdr;
	int len;
	nlhdr = nlmsg_hdr(nlmsg);
	len = nlhdr->nlmsg_len;

	for (; NLMSG_OK(nlhdr, len); nlhdr = NLMSG_NEXT(nlhdr, len)) {
		switch (nlhdr->nlmsg_type) {
			case XFRM_MSG_NEWSA:
			case 26:
				printf("XFRM_MSG_NEWSA runs\n");
				parse_sa(nlhdr);
				break;
			case XFRM_MSG_DELSA:
				printf("XFRM_MSG_DELSA runs\n");
				parse_sa(nlhdr);
				break;
			case XFRM_MSG_GETSA:
				printf("XFRM_MSG_GETSA runs\n");
				parse_sa(nlhdr);
				break;
			case XFRM_MSG_NEWPOLICY:
				printf("XFRM_MSG_NEWPOLICY runs\n");
				parse_sp(nlhdr);
				break;
			case XFRM_MSG_DELPOLICY:
				printf("XFRM_MSG_DELPOLICY runs\n");
				parse_sp(nlhdr);
				break;
			case XFRM_MSG_GETPOLICY:
				printf("XFRM_MSG_GETPOLICY runs\n");
				parse_sp(nlhdr);
				break;
		}
	}
	return 0;
}

int
xfrm_init(void) {
	struct nl_sock *sock;
	pid_t pid;
	int shmid;
	int i;

	// create share memory
	if ((shmid = shmget(IPC_PRIVATE, sizeof(struct shared_data), 0666)) < 0) {
		perror("Shmget faild\n");
		return -1;
	}
	printf("create shared memory\n");

	// create child process
	pid = fork();
	if (pid < 0) {
		perror("Fork faild\n");
	} else if (pid > 0) {
		// get parent shared memory
		if ((shared_mem = shmat(shmid, (void *) 0, 0)) == (void *) -1) {
			perror("parent: shmat error\n");
			return -1;
		}
		printf("parent attach share memory:%p\n", shared_mem);
		//prctl(PR_SET_PDEATHSIG,SIGHUP);
		memset(shared_mem, 0, sizeof(struct shared_data));
		for (i = 0; i < 20; i++) {
			shared_mem->tokens[i] = shared_mem->tokens_save[i];
		}
		xfrm_add_addr(inet_addr("192.168.100.1"));
		return 0;
	}

	// get child shared memory
	if ((shared_mem = shmat(shmid, (void *) 0, 0)) == (void *) -1) {
		perror("child: shmat error\n");
		return -1;
	}
	printf("child attach share memory:%p\n", shared_mem);

	sock = nl_socket_alloc();

	printf("------------xfrm_main------------\n");
/* broadcast group
#define XFRMGRP_ACQUIRE         1
#define XFRMGRP_EXPIRE          2
#define XFRMGRP_SA              4
#define XFRMGRP_POLICY          8
#define XFRMGRP_REPORT          0x20
*/
	nl_join_groups(sock, XFRMGRP_SA | XFRMGRP_POLICY);
//	nl_join_groups(sock, XFRMGRP_ACQUIRE | XFRMGRP_EXPIRE | XFRMGRP_SA | XFRMGRP_POLICY | XFRMGRP_REPORT);

	nl_connect(sock, NETLINK_XFRM);

	nl_socket_modify_cb(sock,
						NL_CB_MSG_IN, NL_CB_CUSTOM, parse_nlmsg, NULL);

	while (1)
		nl_recvmsgs_default(sock);
	return -1;

}