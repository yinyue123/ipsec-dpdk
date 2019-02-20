main() {
	/*
 * Simple example to compute modular exponentiation with 1024-bit key
 *
 */
#define MAX_ASYM_SESSIONS   10
#define NUM_ASYM_BUFS       10

	struct rte_mempool *crypto_op_pool, *asym_session_pool;
	unsigned int asym_session_size;
	int ret;

/* Initialize EAL. */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");

	uint8_t socket_id = rte_socket_id();

/* Create crypto operation pool. */
	crypto_op_pool = rte_crypto_op_pool_create(
			"crypto_op_pool",
			RTE_CRYPTO_OP_TYPE_ASYMMETRIC,
			NUM_ASYM_BUFS, 0, 0,
			socket_id);
	if (crypto_op_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create crypto op pool\n");

/* Create the virtual crypto device. */
	char args[128];
	const char *crypto_name = "crypto_openssl";
	snprintf(args, sizeof(args), "socket_id=%d", socket_id);
	ret = rte_vdev_init(crypto_name, args);
	if (ret != 0)
		rte_exit(EXIT_FAILURE, "Cannot create virtual device");

	uint8_t cdev_id = rte_cryptodev_get_dev_id(crypto_name);

/* Get private asym session data size. */
	asym_session_size = rte_cryptodev_get_asym_private_session_size(cdev_id);

/*
 * Create session mempool, with two objects per session,
 * one for the session header and another one for the
 * private asym session data for the crypto device.
 */
	asym_session_pool = rte_mempool_create("asym_session_pool",
										   MAX_ASYM_SESSIONS * 2,
										   asym_session_size,
										   0,
										   0, NULL, NULL, NULL,
										   NULL, socket_id,
										   0);

/* Configure the crypto device. */
	struct rte_cryptodev_config conf = {
			.nb_queue_pairs = 1,
			.socket_id = socket_id
	};
	struct rte_cryptodev_qp_conf qp_conf = {
			.nb_descriptors = 2048
	};

	if (rte_cryptodev_configure(cdev_id, &conf) < 0)
		rte_exit(EXIT_FAILURE, "Failed to configure cryptodev %u", cdev_id);

	if (rte_cryptodev_queue_pair_setup(cdev_id, 0, &qp_conf,
									   socket_id, asym_session_pool) < 0)
		rte_exit(EXIT_FAILURE, "Failed to setup queue pair\n");

	if (rte_cryptodev_start(cdev_id) < 0)
		rte_exit(EXIT_FAILURE, "Failed to start device\n");

/* Setup crypto xform to do modular exponentiation with 1024 bit
     * length modulus
     */
	struct rte_crypto_asym_xform modex_xform = {
			.next = NULL,
			.xform_type = RTE_CRYPTO_ASYM_XFORM_MODEX,
			.modex = {
					.modulus = {
							.data =
							(uint8_t * )
									("\xb3\xa1\xaf\xb7\x13\x08\x00\x0a\x35\xdc\x2b\x20\x8d"
											 "\xa1\xb5\xce\x47\x8a\xc3\x80\xf4\x7d\x4a\xa2\x62\xfd\x61\x7f"
											 "\xb5\xa8\xde\x0a\x17\x97\xa0\xbf\xdf\x56\x5a\x3d\x51\x56\x4f"
											 "\x70\x70\x3f\x63\x6a\x44\x5b\xad\x84\x0d\x3f\x27\x6e\x3b\x34"
											 "\x91\x60\x14\xb9\xaa\x72\xfd\xa3\x64\xd2\x03\xa7\x53\x87\x9e"
											 "\x88\x0b\xc1\x14\x93\x1a\x62\xff\xb1\x5d\x74\xcd\x59\x63\x18"
											 "\x11\x3d\x4f\xba\x75\xd4\x33\x4e\x23\x6b\x7b\x57\x44\xe1\xd3"
											 "\x03\x13\xa6\xf0\x8b\x60\xb0\x9e\xee\x75\x08\x9d\x71\x63\x13"
											 "\xcb\xa6\x81\x92\x14\x03\x22\x2d\xde\x55"),
							.length = 128
					},
					.exponent = {
							.data = (uint8_t * )("\x01\x00\x01"),
							.length = 3
					}
			}
	};
/* Create asym crypto session and initialize it for the crypto device. */
	struct rte_cryptodev_asym_session *asym_session;
	asym_session = rte_cryptodev_asym_session_create(asym_session_pool);
	if (asym_session == NULL)
		rte_exit(EXIT_FAILURE, "Session could not be created\n");

	if (rte_cryptodev_asym_session_init(cdev_id, asym_session,
										&modex_xform, asym_session_pool) < 0)
		rte_exit(EXIT_FAILURE, "Session could not be initialized "
				"for the crypto device\n");

/* Get a burst of crypto operations. */
	struct rte_crypto_op *crypto_ops[1];
	if (rte_crypto_op_bulk_alloc(crypto_op_pool,
								 RTE_CRYPTO_OP_TYPE_ASYMMETRIC,
								 crypto_ops, 1) == 0)
		rte_exit(EXIT_FAILURE, "Not enough crypto operations available\n");

/* Set up the crypto operations. */
	struct rte_crypto_asym_op *asym_op = crypto_ops[0]->asym;

	/* calculate mod exp of value 0xf8 */
	static unsigned char base[] = {0xF8};
	asym_op->modex.base.data = base;
	asym_op->modex.base.length = sizeof(base);
	asym_op->modex.base.iova = base;

/* Attach the asym crypto session to the operation */
	rte_crypto_op_attach_asym_session(op, asym_session);

/* Enqueue the crypto operations in the crypto device. */
	uint16_t num_enqueued_ops = rte_cryptodev_enqueue_burst(cdev_id, 0,
															crypto_ops, 1);

/*
 * Dequeue the crypto operations until all the operations
 * are processed in the crypto device.
 */
	uint16_t num_dequeued_ops, total_num_dequeued_ops = 0;
	do {
		struct rte_crypto_op *dequeued_ops[1];
		num_dequeued_ops = rte_cryptodev_dequeue_burst(cdev_id, 0,
													   dequeued_ops, 1);
		total_num_dequeued_ops += num_dequeued_ops;

		/* Check if operation was processed successfully */
		if (dequeued_ops[0]->status != RTE_CRYPTO_OP_STATUS_SUCCESS)
			rte_exit(EXIT_FAILURE,
					 "Some operations were not processed correctly");

	} while (total_num_dequeued_ops < num_enqueued_ops);
}