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
 *   IN: < HOST CMD ID,  Param Types   >
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
	const uint32_t pt1 = TEE_PARAM_TYPE_GET(param_types, 0);
	const uint32_t pt2 = TEE_PARAM_TYPE_GET(param_types, 1);
	const uint32_t pt3 = TEE_PARAM_TYPE_GET(param_types, 2);
	const uint32_t pt4 = TEE_PARAM_TYPE_GET(param_types, 3);

	uint32_t ca_cmd_id;
	uint32_t ca_param_types;

	TEE_Param *ca_params;
	size_t ca_params_size;
	size_t ca_params_expected_size;

	uint32_t ca_cmd_ret;
	uint32_t ca_cmd_ret_origin;

	struct thread_param rpc_params[2];
	TEE_Result res;

	/* Check TA interface parameter types */
	if (pt1 != TEE_PARAM_TYPE_VALUE_INOUT ||
		!(pt2 == TEE_PARAM_TYPE_NONE || pt2 == TEE_PARAM_TYPE_MEMREF_INOUT) ||
		pt3 != TEE_PARAM_TYPE_NONE ||
		pt4 != TEE_PARAM_TYPE_NONE) {
		EMSG("Invalid parameter types: %u, %u, %u, %u", pt1, pt2, pt3, pt4);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Extract the parameters from the TA interface */
	ca_cmd_id = params[0].value.a;
	if (pt2 == TEE_PARAM_TYPE_MEMREF_INOUT) {
		ca_param_types = params[0].value.b;
		ca_params = (TEE_Param *)params[1].memref.buffer;
		ca_params_size = params[1].memref.size;
		ca_params_expected_size = sizeof(*ca_params) * TEE_NUM_PARAMS;

		/* Check TA interface parameters */
		if (ca_params_size != ca_params_expected_size) {
			EMSG("Invalid CA parameters: %u, %u", ca_params_expected_size,
				ca_params_size);
			return TEE_ERROR_BAD_PARAMETERS;
		}
		if (!ca_params) {
			EMSG("Null CA parameters");
			return TEE_ERROR_BAD_PARAMETERS;
		}
	}

	/* Set up the parameters for the RPC interface */
	rpc_params[0] = THREAD_PARAM_VALUE(INOUT, ca_cmd_id, 0, 0);
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
