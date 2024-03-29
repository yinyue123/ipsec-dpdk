/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2016 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Security Policies
 */
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip6.h>

#include <rte_acl.h>
#include <rte_ip.h>

#include "ipsec.h"
#include "parser.h"

#define MAX_ACL_RULE_NUM    1024

enum {
	IP6_PROTO,
	IP6_SRC0,
	IP6_SRC1,
	IP6_SRC2,
	IP6_SRC3,
	IP6_DST0,
	IP6_DST1,
	IP6_DST2,
	IP6_DST3,
	IP6_SRCP,
	IP6_DSTP,
	IP6_NUM
};

#define IP6_ADDR_SIZE 16

struct rte_acl_field_def ip6_defs[IP6_NUM] = {
		{
				.type = RTE_ACL_FIELD_TYPE_BITMASK,
				.size = sizeof(uint8_t),
				.field_index = IP6_PROTO,
				.input_index = IP6_PROTO,
				.offset = 0,
		},
		{
				.type = RTE_ACL_FIELD_TYPE_MASK,
				.size = 4,
				.field_index = IP6_SRC0,
				.input_index = IP6_SRC0,
				.offset = 2
		},
		{
				.type = RTE_ACL_FIELD_TYPE_MASK,
				.size = 4,
				.field_index = IP6_SRC1,
				.input_index = IP6_SRC1,
				.offset = 6
		},
		{
				.type = RTE_ACL_FIELD_TYPE_MASK,
				.size = 4,
				.field_index = IP6_SRC2,
				.input_index = IP6_SRC2,
				.offset = 10
		},
		{
				.type = RTE_ACL_FIELD_TYPE_MASK,
				.size = 4,
				.field_index = IP6_SRC3,
				.input_index = IP6_SRC3,
				.offset = 14
		},
		{
				.type = RTE_ACL_FIELD_TYPE_MASK,
				.size = 4,
				.field_index = IP6_DST0,
				.input_index = IP6_DST0,
				.offset = 18
		},
		{
				.type = RTE_ACL_FIELD_TYPE_MASK,
				.size = 4,
				.field_index = IP6_DST1,
				.input_index = IP6_DST1,
				.offset = 22
		},
		{
				.type = RTE_ACL_FIELD_TYPE_MASK,
				.size = 4,
				.field_index = IP6_DST2,
				.input_index = IP6_DST2,
				.offset = 26
		},
		{
				.type = RTE_ACL_FIELD_TYPE_MASK,
				.size = 4,
				.field_index = IP6_DST3,
				.input_index = IP6_DST3,
				.offset = 30
		},
		{
				.type = RTE_ACL_FIELD_TYPE_RANGE,
				.size = sizeof(uint16_t),
				.field_index = IP6_SRCP,
				.input_index = IP6_SRCP,
				.offset = 34
		},
		{
				.type = RTE_ACL_FIELD_TYPE_RANGE,
				.size = sizeof(uint16_t),
				.field_index = IP6_DSTP,
				.input_index = IP6_SRCP,
				.offset = 36
		}
};

RTE_ACL_RULE_DEF(acl6_rules, RTE_DIM(ip6_defs)
);

struct acl6_rules acl6_rules_out[MAX_ACL_RULE_NUM];
uint32_t nb_acl6_rules_out;

struct acl6_rules acl6_rules_in[MAX_ACL_RULE_NUM];
uint32_t nb_acl6_rules_in;

void
parse_sp6_tokens(char **tokens, uint32_t n_tokens,
				 struct parse_status *status) {
	struct acl6_rules *rule_ipv6 = NULL;

	uint32_t *ri = NULL; /* rule index */
	uint32_t ti = 0; /* token index */

	uint32_t esp_p = 0;
	uint32_t protect_p = 0;
	uint32_t bypass_p = 0;
	uint32_t discard_p = 0;
	uint32_t pri_p = 0;
	uint32_t src_p = 0;
	uint32_t dst_p = 0;
	uint32_t proto_p = 0;
	uint32_t sport_p = 0;
	uint32_t dport_p = 0;

	if (strcmp(tokens[1], "in") == 0) {
		ri = &nb_acl6_rules_in;

		APP_CHECK(*ri <= MAX_ACL_RULE_NUM - 1, status, "too "
				"many sp rules, abort insertion\n");
		if (status->status < 0)
			return;

		rule_ipv6 = &acl6_rules_in[*ri];

	} else if (strcmp(tokens[1], "out") == 0) {
		ri = &nb_acl6_rules_out;

		APP_CHECK(*ri <= MAX_ACL_RULE_NUM - 1, status, "too "
				"many sp rules, abort insertion\n");
		if (status->status < 0)
			return;

		rule_ipv6 = &acl6_rules_out[*ri];

	} else {
		APP_CHECK(0, status, "unrecognized input \"%s\", expect"
				" \"in\" or \"out\"\n", tokens[ti]);
		return;
	}

	rule_ipv6->data.category_mask = 1;


	for (ti = 2; ti < n_tokens; ti++) {
		if (strcmp(tokens[ti], "esp") == 0) {
			/* currently do nothing */
			APP_CHECK_PRESENCE(esp_p, tokens[ti], status);
			if (status->status < 0)
				return;
			esp_p = 1;
			continue;
		}

		if (strcmp(tokens[ti], "protect") == 0) {
			APP_CHECK_PRESENCE(protect_p, tokens[ti], status);
			if (status->status < 0)
				return;
			APP_CHECK(bypass_p == 0, status, "conflict item "
					"between \"%s\" and \"%s\"", tokens[ti],
					  "bypass");
			if (status->status < 0)
				return;
			APP_CHECK(discard_p == 0, status, "conflict item "
					"between \"%s\" and \"%s\"", tokens[ti],
					  "discard");
			if (status->status < 0)
				return;
			INCREMENT_TOKEN_INDEX(ti, n_tokens, status);
			if (status->status < 0)
				return;
			APP_CHECK_TOKEN_IS_NUM(tokens, ti, status);
			if (status->status < 0)
				return;

			rule_ipv6->data.userdata =
					PROTECT(atoi(tokens[ti]));

			protect_p = 1;
			continue;
		}

		if (strcmp(tokens[ti], "bypass") == 0) {
			APP_CHECK_PRESENCE(bypass_p, tokens[ti], status);
			if (status->status < 0)
				return;
			APP_CHECK(protect_p == 0, status, "conflict item "
					"between \"%s\" and \"%s\"", tokens[ti],
					  "protect");
			if (status->status < 0)
				return;
			APP_CHECK(discard_p == 0, status, "conflict item "
					"between \"%s\" and \"%s\"", tokens[ti],
					  "discard");
			if (status->status < 0)
				return;

			rule_ipv6->data.userdata = BYPASS;

			bypass_p = 1;
			continue;
		}

		if (strcmp(tokens[ti], "discard") == 0) {
			APP_CHECK_PRESENCE(discard_p, tokens[ti], status);
			if (status->status < 0)
				return;
			APP_CHECK(protect_p == 0, status, "conflict item "
					"between \"%s\" and \"%s\"", tokens[ti],
					  "protect");
			if (status->status < 0)
				return;
			APP_CHECK(bypass_p == 0, status, "conflict item "
					"between \"%s\" and \"%s\"", tokens[ti],
					  "discard");
			if (status->status < 0)
				return;

			rule_ipv6->data.userdata = DISCARD;

			discard_p = 1;
			continue;
		}

		if (strcmp(tokens[ti], "pri") == 0) {
			APP_CHECK_PRESENCE(pri_p, tokens[ti], status);
			if (status->status < 0)
				return;
			INCREMENT_TOKEN_INDEX(ti, n_tokens, status);
			if (status->status < 0)
				return;
			APP_CHECK_TOKEN_IS_NUM(tokens, ti, status);
			if (status->status < 0)
				return;

			rule_ipv6->data.priority = atoi(tokens[ti]);

			pri_p = 1;
			continue;
		}

		if (strcmp(tokens[ti], "src") == 0) {
			struct in6_addr ip;
			uint32_t depth;

			APP_CHECK_PRESENCE(src_p, tokens[ti], status);
			if (status->status < 0)
				return;
			INCREMENT_TOKEN_INDEX(ti, n_tokens, status);
			if (status->status < 0)
				return;

			APP_CHECK(parse_ipv6_addr(tokens[ti], &ip,
									  &depth) == 0, status, "unrecognized "
							  "input \"%s\", expect valid ipv6 "
							  "addr", tokens[ti]);
			if (status->status < 0)
				return;

			rule_ipv6->field[1].value.u32 =
					(uint32_t) ip.s6_addr[0] << 24 |
					(uint32_t) ip.s6_addr[1] << 16 |
					(uint32_t) ip.s6_addr[2] << 8 |
					(uint32_t) ip.s6_addr[3];
			rule_ipv6->field[1].mask_range.u32 =
					(depth > 32) ? 32 : depth;
			depth = (depth > 32) ? (depth - 32) : 0;
			rule_ipv6->field[2].value.u32 =
					(uint32_t) ip.s6_addr[4] << 24 |
					(uint32_t) ip.s6_addr[5] << 16 |
					(uint32_t) ip.s6_addr[6] << 8 |
					(uint32_t) ip.s6_addr[7];
			rule_ipv6->field[2].mask_range.u32 =
					(depth > 32) ? 32 : depth;
			depth = (depth > 32) ? (depth - 32) : 0;
			rule_ipv6->field[3].value.u32 =
					(uint32_t) ip.s6_addr[8] << 24 |
					(uint32_t) ip.s6_addr[9] << 16 |
					(uint32_t) ip.s6_addr[10] << 8 |
					(uint32_t) ip.s6_addr[11];
			rule_ipv6->field[3].mask_range.u32 =
					(depth > 32) ? 32 : depth;
			depth = (depth > 32) ? (depth - 32) : 0;
			rule_ipv6->field[4].value.u32 =
					(uint32_t) ip.s6_addr[12] << 24 |
					(uint32_t) ip.s6_addr[13] << 16 |
					(uint32_t) ip.s6_addr[14] << 8 |
					(uint32_t) ip.s6_addr[15];
			rule_ipv6->field[4].mask_range.u32 =
					(depth > 32) ? 32 : depth;

			src_p = 1;
			continue;
		}

		if (strcmp(tokens[ti], "dst") == 0) {
			struct in6_addr ip;
			uint32_t depth;

			APP_CHECK_PRESENCE(dst_p, tokens[ti], status);
			if (status->status < 0)
				return;
			INCREMENT_TOKEN_INDEX(ti, n_tokens, status);
			if (status->status < 0)
				return;

			APP_CHECK(parse_ipv6_addr(tokens[ti], &ip,
									  &depth) == 0, status, "unrecognized "
							  "input \"%s\", expect valid ipv6 "
							  "addr", tokens[ti]);
			if (status->status < 0)
				return;

			rule_ipv6->field[5].value.u32 =
					(uint32_t) ip.s6_addr[0] << 24 |
					(uint32_t) ip.s6_addr[1] << 16 |
					(uint32_t) ip.s6_addr[2] << 8 |
					(uint32_t) ip.s6_addr[3];
			rule_ipv6->field[5].mask_range.u32 =
					(depth > 32) ? 32 : depth;
			depth = (depth > 32) ? (depth - 32) : 0;
			rule_ipv6->field[6].value.u32 =
					(uint32_t) ip.s6_addr[4] << 24 |
					(uint32_t) ip.s6_addr[5] << 16 |
					(uint32_t) ip.s6_addr[6] << 8 |
					(uint32_t) ip.s6_addr[7];
			rule_ipv6->field[6].mask_range.u32 =
					(depth > 32) ? 32 : depth;
			depth = (depth > 32) ? (depth - 32) : 0;
			rule_ipv6->field[7].value.u32 =
					(uint32_t) ip.s6_addr[8] << 24 |
					(uint32_t) ip.s6_addr[9] << 16 |
					(uint32_t) ip.s6_addr[10] << 8 |
					(uint32_t) ip.s6_addr[11];
			rule_ipv6->field[7].mask_range.u32 =
					(depth > 32) ? 32 : depth;
			depth = (depth > 32) ? (depth - 32) : 0;
			rule_ipv6->field[8].value.u32 =
					(uint32_t) ip.s6_addr[12] << 24 |
					(uint32_t) ip.s6_addr[13] << 16 |
					(uint32_t) ip.s6_addr[14] << 8 |
					(uint32_t) ip.s6_addr[15];
			rule_ipv6->field[8].mask_range.u32 =
					(depth > 32) ? 32 : depth;

			dst_p = 1;
			continue;
		}

		if (strcmp(tokens[ti], "proto") == 0) {
			uint16_t low, high;

			APP_CHECK_PRESENCE(proto_p, tokens[ti], status);
			if (status->status < 0)
				return;
			INCREMENT_TOKEN_INDEX(ti, n_tokens, status);
			if (status->status < 0)
				return;

			APP_CHECK(parse_range(tokens[ti], &low, &high)
					  == 0, status, "unrecognized input \"%s\""
							  ", expect \"from:to\"", tokens[ti]);
			if (status->status < 0)
				return;
			APP_CHECK(low <= 0xff, status, "proto low "
					"over-limit");
			if (status->status < 0)
				return;
			APP_CHECK(high <= 0xff, status, "proto high "
					"over-limit");
			if (status->status < 0)
				return;

			rule_ipv6->field[0].value.u8 = (uint8_t) low;
			rule_ipv6->field[0].mask_range.u8 = (uint8_t) high;

			proto_p = 1;
			continue;
		}

		if (strcmp(tokens[ti], "sport") == 0) {
			uint16_t port_low, port_high;

			APP_CHECK_PRESENCE(sport_p, tokens[ti], status);
			if (status->status < 0)
				return;
			INCREMENT_TOKEN_INDEX(ti, n_tokens, status);
			if (status->status < 0)
				return;

			APP_CHECK(parse_range(tokens[ti], &port_low,
								  &port_high) == 0, status, "unrecognized "
							  "input \"%s\", expect \"port_from:"
							  "port_to\"", tokens[ti]);
			if (status->status < 0)
				return;

			rule_ipv6->field[9].value.u16 = port_low;
			rule_ipv6->field[9].mask_range.u16 = port_high;

			sport_p = 1;
			continue;
		}

		if (strcmp(tokens[ti], "dport") == 0) {
			uint16_t port_low, port_high;

			APP_CHECK_PRESENCE(dport_p, tokens[ti], status);
			if (status->status < 0)
				return;
			INCREMENT_TOKEN_INDEX(ti, n_tokens, status);
			if (status->status < 0)
				return;

			APP_CHECK(parse_range(tokens[ti], &port_low,
								  &port_high) == 0, status, "unrecognized "
							  "input \"%s\", expect \"port_from:"
							  "port_to\"", tokens[ti]);
			if (status->status < 0)
				return;

			rule_ipv6->field[10].value.u16 = port_low;
			rule_ipv6->field[10].mask_range.u16 = port_high;

			dport_p = 1;
			continue;
		}

		/* unrecognizeable input */
		APP_CHECK(0, status, "unrecognized input \"%s\"",
				  tokens[ti]);
		return;
	}

	/* check if argument(s) are missing */
	APP_CHECK(esp_p == 1, status, "missing argument \"esp\"");
	if (status->status < 0)
		return;

	APP_CHECK(protect_p | bypass_p | discard_p, status, "missing "
			"argument \"protect\", \"bypass\", or \"discard\"");
	if (status->status < 0)
		return;

	*ri = *ri + 1;
}

static inline void
print_one_ip6_rule(const struct acl6_rules *rule, int32_t extra) {
	uint8_t a, b, c, d;

	uint32_t_to_char(rule->field[IP6_SRC0].value.u32,
					 &a, &b, &c, &d);
	printf("%.2x%.2x:%.2x%.2x", a, b, c, d);
	uint32_t_to_char(rule->field[IP6_SRC1].value.u32,
					 &a, &b, &c, &d);
	printf(":%.2x%.2x:%.2x%.2x", a, b, c, d);
	uint32_t_to_char(rule->field[IP6_SRC2].value.u32,
					 &a, &b, &c, &d);
	printf(":%.2x%.2x:%.2x%.2x", a, b, c, d);
	uint32_t_to_char(rule->field[IP6_SRC3].value.u32,
					 &a, &b, &c, &d);
	printf(":%.2x%.2x:%.2x%.2x/%u ", a, b, c, d,
		   rule->field[IP6_SRC0].mask_range.u32
		   + rule->field[IP6_SRC1].mask_range.u32
		   + rule->field[IP6_SRC2].mask_range.u32
		   + rule->field[IP6_SRC3].mask_range.u32);

	uint32_t_to_char(rule->field[IP6_DST0].value.u32,
					 &a, &b, &c, &d);
	printf("%.2x%.2x:%.2x%.2x", a, b, c, d);
	uint32_t_to_char(rule->field[IP6_DST1].value.u32,
					 &a, &b, &c, &d);
	printf(":%.2x%.2x:%.2x%.2x", a, b, c, d);
	uint32_t_to_char(rule->field[IP6_DST2].value.u32,
					 &a, &b, &c, &d);
	printf(":%.2x%.2x:%.2x%.2x", a, b, c, d);
	uint32_t_to_char(rule->field[IP6_DST3].value.u32,
					 &a, &b, &c, &d);
	printf(":%.2x%.2x:%.2x%.2x/%u ", a, b, c, d,
		   rule->field[IP6_DST0].mask_range.u32
		   + rule->field[IP6_DST1].mask_range.u32
		   + rule->field[IP6_DST2].mask_range.u32
		   + rule->field[IP6_DST3].mask_range.u32);

	printf("%hu : %hu %hu : %hu 0x%hhx/0x%hhx ",
		   rule->field[IP6_SRCP].value.u16,
		   rule->field[IP6_SRCP].mask_range.u16,
		   rule->field[IP6_DSTP].value.u16,
		   rule->field[IP6_DSTP].mask_range.u16,
		   rule->field[IP6_PROTO].value.u8,
		   rule->field[IP6_PROTO].mask_range.u8);
	if (extra)
		printf("0x%x-0x%x-0x%x ",
			   rule->data.category_mask,
			   rule->data.priority,
			   rule->data.userdata);
}

static inline void
dump_ip6_rules(const struct acl6_rules *rule, int32_t num, int32_t extra) {
	int32_t i;

	for (i = 0; i < num; i++, rule++) {
		printf("\t%d:", i + 1);
		print_one_ip6_rule(rule, extra);
		printf("\n");
	}
}

static struct rte_acl_ctx *
acl6_init(const char *name, int32_t socketid, const struct acl6_rules *rules,
		  uint32_t rules_nb) {
	char s[PATH_MAX];
	struct rte_acl_param acl_param;
	struct rte_acl_config acl_build_param;
	struct rte_acl_ctx *ctx;

	printf("Creating SP context with %u max rules\n", MAX_ACL_RULE_NUM);

	memset(&acl_param, 0, sizeof(acl_param));

	/* Create ACL contexts */
	snprintf(s, sizeof(s), "%s_%d", name, socketid);

	printf("IPv4 %s entries [%u]:\n", s, rules_nb);
	dump_ip6_rules(rules, rules_nb, 1);

	acl_param.name = s;
	acl_param.socket_id = socketid;
	acl_param.rule_size = RTE_ACL_RULE_SZ(RTE_DIM(ip6_defs));
	acl_param.max_rule_num = MAX_ACL_RULE_NUM;

	ctx = rte_acl_create(&acl_param);
	if (ctx == NULL)
		rte_exit(EXIT_FAILURE, "Failed to create ACL context\n");

	if (rte_acl_add_rules(ctx, (const struct rte_acl_rule *) rules,
						  rules_nb) < 0)
		rte_exit(EXIT_FAILURE, "add rules failed\n");

	/* Perform builds */
	memset(&acl_build_param, 0, sizeof(acl_build_param));

	acl_build_param.num_categories = DEFAULT_MAX_CATEGORIES;
	acl_build_param.num_fields = RTE_DIM(ip6_defs);
	memcpy(&acl_build_param.defs, ip6_defs, sizeof(ip6_defs));

	if (rte_acl_build(ctx, &acl_build_param) != 0)
		rte_exit(EXIT_FAILURE, "Failed to build ACL trie\n");

	rte_acl_dump(ctx);

	return ctx;
}

void
sp6_init(struct socket_ctx *ctx, int32_t socket_id) {
	const char *name;

	if (ctx == NULL)
		rte_exit(EXIT_FAILURE, "NULL context.\n");

	if (ctx->sp_ip6_in != NULL)
		rte_exit(EXIT_FAILURE, "Inbound IPv6 SP DB for socket %u "
				"already initialized\n", socket_id);

	if (ctx->sp_ip6_out != NULL)
		rte_exit(EXIT_FAILURE, "Outbound IPv6 SP DB for socket %u "
				"already initialized\n", socket_id);

	if (nb_acl6_rules_in > 0) {
		name = "sp_ip6_in";
		ctx->sp_ip6_in = (struct sp_ctx *) acl6_init(name,
													 socket_id, acl6_rules_in, nb_acl6_rules_in);
	} else
		RTE_LOG(WARNING, IPSEC, "No IPv6 SP Inbound rule "
				"specified\n");

	if (nb_acl6_rules_out > 0) {
		name = "sp_ip6_out";
		ctx->sp_ip6_out = (struct sp_ctx *) acl6_init(name,
													  socket_id, acl6_rules_out, nb_acl6_rules_out);
	} else
		RTE_LOG(WARNING, IPSEC, "No IPv6 SP Outbound rule "
				"specified\n");
}
