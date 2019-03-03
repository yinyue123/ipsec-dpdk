//
// Created by 殷悦 on 28/01/2019.
//

#ifndef BYSJ_XFRM_H
#define BYSJ_XFRM_H

#include "parser.h"

int
xfrm_init(void);

void
recv_xfrm(void);

void
parse_sa_tokens(char **tokens, uint32_t n_tokens,
				struct parse_status *status);

void
parse_sp4_tokens(char **tokens, uint32_t n_tokens,
				 struct parse_status *status);

#endif //BYSJ_XFRM_H
