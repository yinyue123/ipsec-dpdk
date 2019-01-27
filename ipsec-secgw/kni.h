//
// Created by 殷悦 on 26/01/2019.
//

#ifndef __KNI_H__
#define __KNI_H__

int
check_kni_data(struct rte_mbuf *pkt);

void
send_to_kni(uint8_t port_id, struct rte_mbuf *pkts, uint32_t nb_rx);

void
forward_from_kni_to_eth(uint16_t tx_queue_id, uint8_t port_id);

void
kni_main(struct rte_eth_conf *portconf);

void
kni_free();

#endif /* __KNI_H__ */
