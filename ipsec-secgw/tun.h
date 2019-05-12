//
// Created by 殷悦 on 24/03/2019.
//

#ifndef BYSJ_TUN_H
#define BYSJ_TUN_H

int tun_write(int tun_fd,rte_mbuf *m);
int tun_create(char *name);
struct rte_mbuf* tun_read(int tun_fd);

#endif //BYSJ_TUN_H
