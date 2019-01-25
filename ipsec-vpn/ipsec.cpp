//
// Created by 殷悦 on 22/01/2019.
//

#include <rte_ether.h>
#include <rte_ip.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

#include "ipsec.h"

int process_pkt(struct rte_mbuf *pkt) {
    unsigned txpkts = 0;
    //uint8_t *nlp;
    struct ether_hdr *eth = rte_pktmbuf_mtod(pkt, struct ether_hdr*);
    struct ipv4_hdr *ip_hdr;
    /* If not ip packet, forward to kni */
    //return 0;
    if (eth->ether_type == rte_cpu_to_be_16(ETHER_TYPE_IPv4)) {
        //return txpkts;
        ip_hdr = rte_pktmbuf_mtod_offset(pkt, struct ipv4_hdr *, sizeof(struct ether_hdr));
        //if (ip_hdr->next_proto_id == IPPROTO_ESP) {
        if (ip_hdr->next_proto_id == IPPROTO_UDP) {
//            printf("Recieve esp package\n");
            printf("Recieve udp package\n");
            return txpkts;
        }else if(ip_hdr->next_proto_id == IPPROTO_ICMP) {
            printf("Recieve udp package\n");
            return txpkts;
        }else if(ip_hdr->next_proto_id == IPPROTO_TCP) {
            printf("Recieve tcp package\n");
            return txpkts;
        }

//        else
//            return txpkts;
    } else if (eth->ether_type == rte_cpu_to_be_16(ETHER_TYPE_IPv6)) {
        return txpkts;
    }
    return txpkts;

}