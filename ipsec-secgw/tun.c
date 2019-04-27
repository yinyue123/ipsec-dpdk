////
//// Created by 殷悦 on 24/03/2019.
////
//
//#include "tun.h"
//
///* Max size of a single packet */
//#define MAX_PACKET_SZ (2048)
//
//int tun_create(char *name) {
//	struct ifreq ifr;
//	int fd, ret;
//
//	fd = open("/dev/net/tun", O_RDWR | O_NONBLOCK);
//	if (fd < 0)
//		return fd;
//
//	memset(&ifr, 0, sizeof(ifr));
//
//	/* TUN device without packet information */
//	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
//
//	if (name && *name)
//		snprintf(ifr.ifr_name, IFNAMSIZ, "%s", name);
//
//	ret = ioctl(fd, TUNSETIFF, (void *) &ifr);
//	if (ret < 0) {
//		close(fd);
//		return ret;
//	}
//
//	if (name)
//		snprintf(name, IFNAMSIZ, "%s", ifr.ifr_name);
//
//	return fd;
//}
//
//struct rte_mbuf* tun_read() {
//	struct rte_mbuf *m = rte_pktmbuf_alloc(pktmbuf_pool);
//	if (m == NULL)
//		return tun_read();
//
//	ret = read(tun_fd, rte_pktmbuf_mtod(m, void * ),
//			   MAX_PACKET_SZ);
//
//	printf("tun recv data\n");
//
//	if (unlikely(ret < 0)) {
//		FATAL_ERROR("Reading from %s interface failed",
//					"tun");
//	}
//
//	m->nb_segs = 1;
//	m->next = NULL;
//	m->pkt_len = (uint16_t) ret;
//	m->data_len = (uint16_t) ret;
//
//	return m;
//}
//
//int tun_write(rte_mbuf *m){
//	int ret = write(tun_fd,
//					rte_pktmbuf_mtod(m, void * ),
//					rte_pktmbuf_data_len(m));
//	rte_pktmbuf_free(m);
//	return ret;
//}