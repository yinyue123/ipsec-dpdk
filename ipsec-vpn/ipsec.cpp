//
// Created by 殷悦 on 22/01/2019.
//

#include <rte_ether.h>

#include "ipsec.h"

int process_pkt(struct rte_mbuf *pkt){
    ehdr = rte_pktmbuf_mtod(pkt,
    struct ether_hdr*);
    

}