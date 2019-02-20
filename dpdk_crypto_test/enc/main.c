/*
 * Simple example to encrypt several buffers with AES-CBC using
 * the Cryptodev APIs.
 */
void
main() {
#define MAX_SESSIONS         1024
#define NUM_MBUFS            1024
#define POOL_CACHE_SIZE      128
#define BURST_SIZE           32
#define BUFFER_SIZE          1024
#define AES_CBC_IV_LENGTH    16
#define AES_CBC_KEY_LENGTH   16
#define IV_OFFSET            (sizeof(struct rte_crypto_op) + \
                             sizeof(struct rte_crypto_sym_op))

	struct rte_mempool *mbuf_pool, *crypto_op_pool;
	struct rte_mempool *session_pool, *session_priv_pool;
	unsigned int session_size;
	int ret;

/* Initialize EAL. */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");

	uint8_t socket_id = rte_socket_id();

/* Create the mbuf pool. */
	mbuf_pool = rte_pktmbuf_pool_create("mbuf_pool",
										NUM_MBUFS,
										POOL_CACHE_SIZE,
										0,
										RTE_MBUF_DEFAULT_BUF_SIZE,
										socket_id);
	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

/*
 * The IV is always placed after the crypto operation,
 * so some private data is required to be reserved.
 */
	unsigned int crypto_op_private_data = AES_CBC_IV_LENGTH;

/* Create crypto operation pool. */
	crypto_op_pool = rte_crypto_op_pool_create("crypto_op_pool",
											   RTE_CRYPTO_OP_TYPE_SYMMETRIC,
											   NUM_MBUFS,
											   POOL_CACHE_SIZE,
											   crypto_op_private_data,
											   socket_id);
	if (crypto_op_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create crypto op pool\n");

/* Create the virtual crypto device. */
	char args[128];
	const char *crypto_name = "crypto_aesni_mb0";
	snprintf(args, sizeof(args), "socket_id=%d", socket_id);
	ret = rte_vdev_init(crypto_name, args);
	if (ret != 0)
		rte_exit(EXIT_FAILURE, "Cannot create virtual device");

	uint8_t cdev_id = rte_cryptodev_get_dev_id(crypto_name);

/* Get private session data size. */
	session_size = rte_cryptodev_sym_get_private_session_size(cdev_id);

#ifdef USE_TWO_MEMPOOLS
	/* Create session mempool for the session header. */
	session_pool = rte_cryptodev_sym_session_pool_create("session_pool",
									MAX_SESSIONS,
									0,
									POOL_CACHE_SIZE,
									0,
									socket_id);

	/*
	 * Create session private data mempool for the
	 * private session data for the crypto device.
	 */
	session_priv_pool = rte_mempool_create("session_pool",
									MAX_SESSIONS,
									session_size,
									POOL_CACHE_SIZE,
									0, NULL, NULL, NULL,
									NULL, socket_id,
									0);

#else
/* Use of the same mempool for session header and private data */
	session_pool = rte_cryptodev_sym_session_pool_create("session_pool",
														 MAX_SESSIONS * 2,
														 session_size,
														 POOL_CACHE_SIZE,
														 0,
														 socket_id);

	session_priv_pool = session_pool;

#endif

/* Configure the crypto device. */
	struct rte_cryptodev_config conf = {
			.nb_queue_pairs = 1,
			.socket_id = socket_id
	};

	struct rte_cryptodev_qp_conf qp_conf = {
			.nb_descriptors = 2048,
			.mp_session = session_pool,
			.mp_session_private = session_priv_pool
	};

	if (rte_cryptodev_configure(cdev_id, &conf) < 0)
		rte_exit(EXIT_FAILURE, "Failed to configure cryptodev %u", cdev_id);

	if (rte_cryptodev_queue_pair_setup(cdev_id, 0, &qp_conf, socket_id) < 0)
		rte_exit(EXIT_FAILURE, "Failed to setup queue pair\n");

	if (rte_cryptodev_start(cdev_id) < 0)
		rte_exit(EXIT_FAILURE, "Failed to start device\n");

/* Create the crypto transform. */
	uint8_t cipher_key[16] = {0};
	struct rte_crypto_sym_xform cipher_xform = {
			.next = NULL,
			.type = RTE_CRYPTO_SYM_XFORM_CIPHER,
			.cipher = {
					.op = RTE_CRYPTO_CIPHER_OP_ENCRYPT,
					.algo = RTE_CRYPTO_CIPHER_AES_CBC,
					.key = {
							.data = cipher_key,
							.length = AES_CBC_KEY_LENGTH
					},
					.iv = {
							.offset = IV_OFFSET,
							.length = AES_CBC_IV_LENGTH
					}
			}
	};

/* Create crypto session and initialize it for the crypto device. */
	struct rte_cryptodev_sym_session *session;
	session = rte_cryptodev_sym_session_create(session_pool);
	if (session == NULL)
		rte_exit(EXIT_FAILURE, "Session could not be created\n");

	if (rte_cryptodev_sym_session_init(cdev_id, session,
									   &cipher_xform, session_priv_pool) < 0)
		rte_exit(EXIT_FAILURE, "Session could not be initialized "
				"for the crypto device\n");

/* Get a burst of crypto operations. */
	struct rte_crypto_op *crypto_ops[BURST_SIZE];
	if (rte_crypto_op_bulk_alloc(crypto_op_pool,
								 RTE_CRYPTO_OP_TYPE_SYMMETRIC,
								 crypto_ops, BURST_SIZE) == 0)
		rte_exit(EXIT_FAILURE, "Not enough crypto operations available\n");

/* Get a burst of mbufs. */
	struct rte_mbuf *mbufs[BURST_SIZE];
	if (rte_pktmbuf_alloc_bulk(mbuf_pool, mbufs, BURST_SIZE) < 0)
		rte_exit(EXIT_FAILURE, "Not enough mbufs available");

/* Initialize the mbufs and append them to the crypto operations. */
	unsigned int i;
	for (i = 0; i < BURST_SIZE; i++) {
		if (rte_pktmbuf_append(mbufs[i], BUFFER_SIZE) == NULL)
			rte_exit(EXIT_FAILURE, "Not enough room in the mbuf\n");
		crypto_ops[i]->sym->m_src = mbufs[i];
	}

/* Set up the crypto operations. */
	for (i = 0; i < BURST_SIZE; i++) {
		struct rte_crypto_op *op = crypto_ops[i];
/* Modify bytes of the IV at the end of the crypto operation */
		uint8_t *iv_ptr = rte_crypto_op_ctod_offset(op, uint8_t * ,
													IV_OFFSET);

		generate_random_bytes(iv_ptr, AES_CBC_IV_LENGTH);

		op->sym->cipher.data.offset = 0;
		op->sym->cipher.data.length = BUFFER_SIZE;

/* Attach the crypto session to the operation */
		rte_crypto_op_attach_sym_session(op, session);
	}

/* Enqueue the crypto operations in the crypto device. */
	uint16_t num_enqueued_ops = rte_cryptodev_enqueue_burst(cdev_id, 0,
															crypto_ops, BURST_SIZE);

/*
 * Dequeue the crypto operations until all the operations
 * are proccessed in the crypto device.
 */
	uint16_t num_dequeued_ops, total_num_dequeued_ops = 0;
	do {
		struct rte_crypto_op *dequeued_ops[BURST_SIZE];
		num_dequeued_ops = rte_cryptodev_dequeue_burst(cdev_id, 0,
													   dequeued_ops, BURST_SIZE);
		total_num_dequeued_ops += num_dequeued_ops;

/* Check if operation was processed successfully */
		for (i = 0; i < num_dequeued_ops; i++) {
			if (dequeued_ops[i]->status != RTE_CRYPTO_OP_STATUS_SUCCESS)
				rte_exit(EXIT_FAILURE,
						 "Some operations were not processed correctly");
		}

		rte_mempool_put_bulk(crypto_op_pool, (void **) dequeued_ops,
							 num_dequeued_ops);
	} while (total_num_dequeued_ops < num_enqueued_ops);
}