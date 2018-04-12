/*                                                                                                  
 *                      Shadow-Box for ARM                                                          
 *                      ------------------                                                          
 *             ARM TrustZone-Based Kernel Protector                                                 
 *                                                                                                  
 *               Copyright (C) 2018 Seunghun Han                                                    
 *     at National Security Research Institute of South Korea                                       
 */                                                                                                 
                                                                                                    
/*
 * This software has dual license (MIT and GPL v2). See the GPL_LICENSE and
 * MIT_LICENSE file.
 */
#include <compiler.h>
#include <stdio.h>
#include <trace.h>
#include <kernel/pseudo_ta.h>
#include <mm/tee_pager.h>
#include <mm/tee_mm.h>
#include <string.h>
#include <string_ext.h>
#include <malloc.h>
#include <mm/tee_mm.h>
#include <tee/tee_cryp_utl.h>
#include <kernel/tee_time.h>
#include <mm/core_mmu.h>
#include <mm/core_memprot.h>
#include <crypto/crypto.h>

#include "aes.h"

//=============================================================================
// Macros
//=============================================================================
#define TA_NAME		"shadow_box.ta"

#define HASH_DUMP_HEADER_MAGIC 			"== SHADOW-BOX HASH DUMP FILE =="
#define REMOTE_ATTESTAION_HEADER_MAGIC 	"== SHADOW-BOX RA DATA =="
#define SHA1_HASH_SIZE                  20 
#define SHA256_HASH_SIZE                32

#define VERIFY_RESULT_PROCESSING		0
#define VERIFY_RESULT_SUCCESS			1
#define VERIFY_RESULT_FAIL				2

#define TA_CMD_REQUEST_SHA1_HASH		0
#define TA_CMD_REQUEST_SHA256_HASH		1
#define TA_CMD_SEND_HASH_TABLE			2
#define TA_CMD_REQUEST_PROTECTION		3
#define TA_CMD_GET_STATUS				4

/* This UUID is generated with uuidgen
   the ITU-T UUID generator at http://www.itu.int/ITU-T/asn1/uuid.html */
#define SHADOW_BOX_UUID { 0x8aaaf200, 0x2450, 0x11e4, \
        { 0xab, 0xe2, 0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b} }


//=============================================================================
// Structures
//=============================================================================
// Request sturecture for generating kernel hashes from normal world
struct request_hash
{
	unsigned long addr;		// physical addr
	unsigned long size;		// size
};

// Object structure of the hash dump file
struct sha1_hash_item
{
	unsigned long addr;
	unsigned long size;
	unsigned char hash[SHA1_HASH_SIZE];
};

// File header of the hash dump file
struct hash_dump_file_header
{
	char magic[32];
	unsigned int version;					// Dump file version
	unsigned long hash_count;				// Item count
	//struct sha1_hash_item* hash_table;	// Start point of sha1_hash_item
};

// Trusted data structure
struct trusted_data
{
	int initialized;
	unsigned long hash_count;
	unsigned char* message_buffer;		// Full message buffer from normal world
	struct sha1_hash_item* hash_table;	// Hash table of normal world kernel
	unsigned int* index_table;			// Radomized indexes for checking kernel hashes
	unsigned long index;				// Next check index of index table
	int verify_result;
	TEE_Time last_verify_success_time;
	TEE_Time last_verify_fail_time;
};

// Status request structure from remote attestation server of normal world
struct shadow_box_request_status
{
	char magic[24]; 
	unsigned int nonce;						// Nonce
	unsigned int pad;						// Pad for SHA1
} __attribute__((packed));

// Status result structure to remote attestation server of normal world
struct shadow_box_status
{
	char magic[24]; 
	unsigned int nonce;						// Received nonce
	int verify_result;						// VERIFY_RESULT_SUCCESS or VERIFY_RESULT_SUCCESS
	unsigned long time_success;				// Success time
	unsigned long time_fail;				// Fail time
	//char dummy[0];						// Pad for 32byte align
} __attribute__((packed));


//=============================================================================
// Global variables
//=============================================================================
struct trusted_data g_trusted_data = {0, };


/**
 * Initialize trusted data structure.
 */
static void init_trusted_data(void)
{
	if (g_trusted_data.message_buffer != NULL)
	{
		free(g_trusted_data.message_buffer);
	}

	if (g_trusted_data.index_table != NULL)
	{
		free(g_trusted_data.index_table);
	}

	g_trusted_data.hash_count = 0;
	g_trusted_data.message_buffer = NULL;
	g_trusted_data.hash_table = NULL;
	g_trusted_data.index_table = NULL;
	g_trusted_data.index = 0;
	g_trusted_data.verify_result = VERIFY_RESULT_PROCESSING;
	
	memset(&(g_trusted_data.last_verify_fail_time), 0, sizeof(g_trusted_data.last_verify_fail_time));
	memset(&(g_trusted_data.last_verify_success_time), 0, sizeof(g_trusted_data.last_verify_success_time));
}

/**
 * Change hex to ascii.
 */
static void add_hex_string(unsigned char* in_buffer, char data)
{
	char half;
	int i;

	for (i = 2 ; i > 0 ; i--)
	{
		half = data & 0x0f;

		if (half >= 10)
		{
			in_buffer[i - 1] = 'A' + half - 10;
		}
		else
		{
			in_buffer[i - 1] = '0' + half;
		}

		data = data >> 4;
	}
}

/**
 * Dump a hash value.
 */
static void dump_hash(unsigned char *hash, unsigned long len)
{
	size_t i;
	unsigned char buffer[100];
	unsigned long real_len;

	real_len = len;
	if (real_len > (sizeof(buffer) / 2) - 1)
	{
		real_len = (sizeof(buffer) / 2) - 1;
	}

	buffer[0] = '\0';
	for (i = 0 ; i < real_len; i++)
	{
		add_hex_string(buffer + i * 2, hash[i]);
	}

	// add NULL
	buffer[i * 2 - 1] = 0;
	DMSG("%s\n",  buffer);
}

/**
 * Generate a hash value of physical address in normal world and store it to 
 * buffer of normal world.
 */
static TEE_Result process_hash(TEE_Param params[4])
{
	TEE_Result res = TEE_SUCCESS;
	unsigned char* phy_addr;
	unsigned char* log_addr;
	struct request_hash* prot;
	unsigned long real_size;

	prot = (struct request_hash*) params[1].memref.buffer;

	phy_addr = (unsigned char*)prot->addr;
	log_addr = phys_to_virt((unsigned long)phy_addr, MEM_AREA_IO_NSEC);	
	DMSG("Physical = %lX, Virtual = %lX\n", (unsigned long)phy_addr, (unsigned long)log_addr);

	if (params[2].memref.size < SHA1_HASH_SIZE)
	{
		res = TEE_SUCCESS;
		goto EXIT;
	}

	real_size = SHA1_HASH_SIZE;
	if (real_size < params[2].memref.size)
	{
		real_size = params[2].memref.size;
	}

	// Use core api
	res = tee_hash_createdigest(TEE_ALG_SHA1, log_addr, prot->size, params[2].memref.buffer, real_size);
	if (res != TEE_SUCCESS)
	{
		DMSG("tee_hash_createdigest(TEE_ALG_SHA1) Fail\n");
		goto EXIT;
	}

	dump_hash(params[2].memref.buffer, SHA1_HASH_SIZE);

EXIT:

	return res;
}


/**
 * Verify an integrity of hash dump file from normal world.
 */
static int verify_hash_dump_file(struct hash_dump_file_header* header, unsigned long size)
{
	if (memcmp(header->magic, HASH_DUMP_HEADER_MAGIC, strlen(HASH_DUMP_HEADER_MAGIC)) != 0)
	{
		DMSG("Magic header error\n");
		DMSG("%s", header->magic);
		dump_hash((unsigned char*)header, 30);
		return -1;
	}

	if (size < (sizeof(struct hash_dump_file_header) + header->hash_count * sizeof(struct sha1_hash_item)))
	{
		DMSG("Size error, total size: %ld, item count = %ld x size of hash_item = %ld, multiple = %ld \n",
			size, header->hash_count, sizeof(struct sha1_hash_item), header->hash_count * sizeof(struct sha1_hash_item));
		return -1;
	}

	return 0;
}

/**
 * Suffle index table to prevent prediction attack.
 */
static void shuffle_index_table(void)
{
	unsigned long hash_count;
	unsigned long i;
	int left;
	int right;
	unsigned int temp;

	hash_count = g_trusted_data.hash_count;

	for (i = 0 ; i < hash_count ; i++)
	{
		g_trusted_data.index_table[i] = i;	
	}

	for (i = 0 ; i < hash_count * 2 ; i++)
	{
		rng_generate(&right, sizeof(right));
		rng_generate(&left, sizeof(left));
		right = right % hash_count;
		left = left % hash_count;
		
		// swap
		temp = g_trusted_data.index_table[left];
		g_trusted_data.index_table[left] = g_trusted_data.index_table[right];
		g_trusted_data.index_table[right] = temp; 
	}
}


/**
 * Decrypt data with key and iv.
 *  - key=52DA55AC3CB64D4C905F5688B47B7F8D
 *  - iv =13BE10DC8C89F640CB1B1771C668419F
 */
static void decrypt_data(unsigned char* enc_message, unsigned long enc_size, unsigned char* dec_message)
{
	unsigned char key[] = { 0x52, 0xDA, 0x55, 0xAC, 0x3C, 0xB6, 0x4D, 0x4C, 0x90, 0x5F, 0x56, 0x88, 0xB4, 0x7B, 0x7F, 0x8D };
	unsigned char iv[] = { 0x13, 0xBE, 0x10, 0xDC, 0x8C, 0x89, 0xF6, 0x40, 0xCB, 0x1B, 0x17, 0x71, 0xC6, 0x68, 0x41, 0x9F };

	AES128_CBC_decrypt_buffer(dec_message, enc_message, enc_size, key, iv);
}

/**
 * Encrypt data with key and iv.
 *  - key=52DA55AC3CB64D4C905F5688B47B7F8D
 *  - iv =13BE10DC8C89F640CB1B1771C668419F
 */
static void encrypt_data(unsigned char* plain_message, unsigned long plain_size, unsigned char* enc_message)
{
	unsigned char key[] = { 0x52, 0xDA, 0x55, 0xAC, 0x3C, 0xB6, 0x4D, 0x4C, 0x90, 0x5F, 0x56, 0x88, 0xB4, 0x7B, 0x7F, 0x8D };
	unsigned char iv[] = { 0x13, 0xBE, 0x10, 0xDC, 0x8C, 0x89, 0xF6, 0x40, 0xCB, 0x1B, 0x17, 0x71, 0xC6, 0x68, 0x41, 0x9F };

	AES128_CBC_encrypt_buffer(enc_message, plain_message, plain_size, key, iv);
}

/**
 * Process a hash table of normal world and make trusted data with it.
 */
static TEE_Result process_recved_hash_table(TEE_Param params[4])
{
	struct hash_dump_file_header* header;
	unsigned long size;
	unsigned char* message_buffer = NULL;
	unsigned int* index_buffer = NULL;
	unsigned char temp_buffer[128];

	DMSG("Hash table is received, size: %d\n", params[1].memref.size);
	header = (void*)temp_buffer;
	size = params[1].memref.size;

	// Decrypt and check
	decrypt_data(params[1].memref.buffer, sizeof(temp_buffer), temp_buffer);
	if (verify_hash_dump_file((void*)temp_buffer, size) != 0)
	{
		goto ERROR;
	}

	init_trusted_data();

	message_buffer = malloc(size);
	index_buffer = malloc(header->hash_count * sizeof(unsigned int));

	if ((message_buffer == NULL) || (index_buffer == NULL))
	{
		DMSG("malloc fail\n");
		goto ERROR;
	}

	memcpy(message_buffer, params[1].memref.buffer, size);
	decrypt_data(params[1].memref.buffer, params[1].memref.size, message_buffer);
	dump_hash(message_buffer, 100);

	g_trusted_data.message_buffer = message_buffer;
	g_trusted_data.hash_table = (void*)(message_buffer + sizeof(struct hash_dump_file_header));
	g_trusted_data.index_table = index_buffer;
	g_trusted_data.hash_count = header->hash_count;

	shuffle_index_table();

	return TEE_SUCCESS;

ERROR:
	if (message_buffer != NULL)
	{
		free(message_buffer);
	}
	
	if (index_buffer != NULL)
	{
		free(index_buffer);
	}

	return TEE_ERROR_BAD_PARAMETERS;
}

/**
 * Start kernel protection and check hashes periodically.
 */
static TEE_Result process_start_protection(void)
{
	TEE_Result res;
	struct sha1_hash_item* item;
	unsigned long index;
	unsigned char* phy_addr;
	unsigned char* log_addr;
	unsigned char hash_calc[SHA1_HASH_SIZE];
	
	if ((g_trusted_data.initialized == 0) || (g_trusted_data.hash_table == NULL) || (g_trusted_data.verify_result == VERIFY_RESULT_FAIL))
	{
		DMSG("Not initialized or no hash table or verification fail, initialize = %d, hash table = %lX\n", g_trusted_data.initialized, (unsigned long)g_trusted_data.hash_table);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (g_trusted_data.index == g_trusted_data.hash_count)
	{
		g_trusted_data.verify_result = VERIFY_RESULT_SUCCESS;
		tee_time_get_ree_time(&(g_trusted_data.last_verify_success_time));
		DMSG("====================================================\n");
		DMSG("           Verification Success, time: %d\n", g_trusted_data.last_verify_success_time.seconds);
		DMSG("====================================================\n");
	
		shuffle_index_table();
		g_trusted_data.index = 0;
	}
	
	index = g_trusted_data.index_table[g_trusted_data.index];
	item =  &(g_trusted_data.hash_table[index]);

	if (g_trusted_data.index % 100 == 0)
	{
		DMSG("[%ld/%ld] Verify index = %ld, addr = %lX, hash\n", g_trusted_data.index, g_trusted_data.hash_count, index, item->addr);
	}

	phy_addr = (unsigned char*)item->addr;
	log_addr = phys_to_virt((unsigned long)phy_addr, MEM_AREA_IO_NSEC);	
	
	res = tee_hash_createdigest(TEE_ALG_SHA1, log_addr, item->size, hash_calc, SHA1_HASH_SIZE);
	if (res != TEE_SUCCESS)
	{
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (memcmp(item->hash, hash_calc, SHA1_HASH_SIZE) != 0)
	{
		g_trusted_data.verify_result = VERIFY_RESULT_FAIL;
		tee_time_get_ree_time(&(g_trusted_data.last_verify_fail_time));

		DMSG("====================================================\n");
		DMSG("           Verification Fail, time: %d\n", g_trusted_data.last_verify_fail_time.seconds);
		DMSG("[%ld/%ld] Verify index = %ld, addr = %lX, hash\n", g_trusted_data.index, g_trusted_data.hash_count, index, item->addr);
		dump_hash(item->hash, SHA1_HASH_SIZE);
		dump_hash(hash_calc, SHA1_HASH_SIZE);
		DMSG("====================================================\n");
	}
	
	g_trusted_data.index++;

	return TEE_SUCCESS;
}

/**
 * Process a request from remote attestation server and send status data to it.
 */
static TEE_Result process_get_status(TEE_Param params[4])
{
	unsigned long size;
	struct shadow_box_status* data = NULL;
	struct shadow_box_request_status request;
	struct shadow_box_status temp;

	decrypt_data(params[1].memref.buffer, sizeof(struct shadow_box_request_status), (unsigned char*) &request);
	DMSG("Data size: %u, %lu\n", params[1].memref.size, sizeof(struct shadow_box_request_status));
	if (memcmp(request.magic, REMOTE_ATTESTAION_HEADER_MAGIC, strlen(REMOTE_ATTESTAION_HEADER_MAGIC)) != 0)
	{
		DMSG("Server Magic Error, %s\n", request.magic);
		goto ERROR;
	}

	DMSG("Server nonce: %u\n", request.nonce);

	data = (struct shadow_box_status*) params[2].memref.buffer;
	size = params[2].memref.size;

	// 정보를 반환함
	if (size < sizeof(struct shadow_box_status))
	{
		goto ERROR;
	}

	memset(&temp, 0, sizeof(struct shadow_box_status));
	memcpy(temp.magic, REMOTE_ATTESTAION_HEADER_MAGIC, strlen(REMOTE_ATTESTAION_HEADER_MAGIC));
	temp.nonce = request.nonce;
	temp.verify_result = g_trusted_data.verify_result;
	temp.time_success = g_trusted_data.last_verify_success_time.seconds;
	temp.time_fail = g_trusted_data.last_verify_fail_time.seconds;

	encrypt_data((void*)&temp, sizeof(struct shadow_box_status), (void*)data);

	return TEE_SUCCESS;

ERROR:
	return TEE_ERROR_BAD_PARAMETERS;
}


/**
 * Process reqeusts of normal world.
 */
static TEE_Result invoke_command(void *psess __unused,
				 uint32_t cmd, uint32_t ptypes,
				 TEE_Param params[4])
{
	TEE_Result res = TEE_SUCCESS;

	uint32_t exp_param_types = TEE_PARAM_TYPES(
									TEE_PARAM_TYPE_NONE,
									TEE_PARAM_TYPE_MEMREF_INPUT,
									TEE_PARAM_TYPE_MEMREF_OUTPUT, 
									TEE_PARAM_TYPE_NONE);
	if (ptypes != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	if (g_trusted_data.initialized == 0)
	{
		init_trusted_data();
		g_trusted_data.initialized = 1;
	}
	
	switch(cmd)
	{
		case TA_CMD_REQUEST_SHA1_HASH:
			res = process_hash(params);
			break;

		case TA_CMD_REQUEST_SHA256_HASH:
			res = process_hash(params);
			break;

		case TA_CMD_SEND_HASH_TABLE:
			res = process_recved_hash_table(params);
			break;

		case TA_CMD_REQUEST_PROTECTION:
			res = process_start_protection();
			break;
		
		case TA_CMD_GET_STATUS:
			res = process_get_status(params);
			break;

		default:
			DMSG("Undefined command cmd: %d\n", cmd);
			res = TEE_ERROR_BAD_PARAMETERS;
			break;
	}
	return res;
}

pseudo_ta_register(.uuid = SHADOW_BOX_UUID, .name = TA_NAME,
		   .flags = PTA_DEFAULT_FLAGS,
		   .invoke_command_entry_point = invoke_command);
