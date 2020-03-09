#include <kernel/pseudo_ta.h>
#include <kernel/thread.h>
#include <optee_rpc_cmd.h>
#include <pta_ocall.h>
#include <tee/uuid.h>

#define PTA_NAME "ocall.ta"

#pragma GCC push_options
#pragma GCC optimize ("-O0")

/*
 * TA Interface:
 * -------------
 * params[0]: VALUE IN/OUT
 *   IN: < HOST CMD ID, Num Params>
 *  OUT: < CMD Ret Val, CMD Ret Origin >
 * params[1]: < [INOUT] TEE_Param[] >
 * params[2]: < - >
 * params[3]: < - >
 * 
 * RPC Interface:
 * --------------
 * params[0]: VALUE IN/OUT
 *    IN: < HOST CMD ID,      -     ,        -       >
 *   OUT: <  Unchanged , CMD Ret Val, CMD Ret Origin >
 * params[1]: < [IN] UUID Octets Hi, [IN] UUID Octets Lo, - >
 * params[2]: < [INOUT] ??? >
 * params[3]: < - >
 * 
 * There are two return codes:
 *   res: Did sending the RPC work?
 *   ca_ret: If sending the RPC worked, what is the return value of the OCALL?
 */
static TEE_Result ocall_send(struct tee_ta_session *s, uint32_t param_types,
				TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_VALUE_INOUT,
		TEE_PARAM_TYPE_MEMREF_INOUT,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE);

	uint32_t ca_cmd_id;
	uint32_t ca_num_params;

	TEE_Param *ca_params;
	size_t ca_params_size;
	size_t ca_params_expected_size;

	uint32_t ca_cmd_ret;
	uint32_t ca_cmd_ret_origin;

	struct thread_param rpc_params[2];
	TEE_Result res;

	/* Check TA interface parameter types */
	if (param_types != exp_pt) {
		EMSG("Invalid parameter types: %u, %u", exp_pt, param_types);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Extract the parameters from the TA interface */
	ca_cmd_id = params[0].value.a;
	ca_num_params = params[0].value.b;
	ca_params = (TEE_Param *)params[1].memref.buffer;
	ca_params_size = params[1].memref.size;
	ca_params_expected_size = sizeof(*ca_params) * ca_num_params;

	/* Check TA interface parameters */
	if (ca_num_params > THREAD_RPC_MAX_NUM_PARAMS) {
		EMSG("Invalid CA parameter count: %u", ca_num_params);
		return TEE_ERROR_BAD_PARAMETERS;
	}
	if (ca_params_size != ca_params_expected_size) {
		EMSG("Invalid CA parameters: %u, %u", ca_params_expected_size,
			ca_params_size);
		return TEE_ERROR_BAD_PARAMETERS;
	}
	if (!ca_params && ca_params_size > 0) {
		EMSG("Null CA parameters with non-zero CA parameters buffer size");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Set up the parameters for the RPC interface */
	rpc_params[0] = THREAD_PARAM_VALUE(INOUT, ca_cmd_id, ca_num_params, 0);
	rpc_params[1] = THREAD_PARAM_VALUE(IN, 0, 0, 0);
	tee_uuid_to_octets((uint8_t *)&rpc_params[1].u.value, &s->clnt_id.uuid);

	/* Send RPC for OCALL */
	res = thread_rpc_cmd(OPTEE_RPC_CMD_OCALL, ARRAY_SIZE(rpc_params),
		rpc_params);
	if (res != TEE_SUCCESS) {
		EMSG("RPC failed with 0x%x", res);
		return res;
	}

	/* Extract CA return values */
	ca_cmd_ret = (uint32_t)rpc_params[0].u.value.b;
	ca_cmd_ret_origin = (uint32_t)rpc_params[0].u.value.c;

	/* Set output parameters */
	params[0].value.a = ca_cmd_ret;
	params[0].value.b = ca_cmd_ret_origin;

	return res;
}

static TEE_Result ocall_invoke_command(void *session_ctx, uint32_t cmd_id,
				uint32_t param_types, TEE_Param params[TEE_NUM_PARAMS])
{
	struct tee_ta_session *s;
	TEE_Result res;

	(void)session_ctx;

	res = tee_ta_get_current_session(&s);
	if (res != TEE_SUCCESS)
		return res;

	switch (cmd_id) {
	case PTA_OCALL_SEND:
		return ocall_send(s, param_types, params);
	default:
		break;
	}

	return TEE_ERROR_NOT_IMPLEMENTED;
}

pseudo_ta_register(.uuid = PTA_UUID, .name = PTA_NAME,
	.flags = PTA_DEFAULT_FLAGS,
	.invoke_command_entry_point = ocall_invoke_command);

#pragma GCC pop_options
