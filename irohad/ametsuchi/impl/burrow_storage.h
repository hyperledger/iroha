/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_AMETSUCHI_BURROW_STORAGE_H
#define IROHA_AMETSUCHI_BURROW_STORAGE_H

#ifdef __cplusplus
extern "C" {
#endif

struct Iroha_Result {
  char *result;
  char *error;
};

extern struct Iroha_Result Iroha_GetAccount(void *storage, char *address);

extern struct Iroha_Result Iroha_UpdateAccount(void *storage,
                                               char *address,
                                               char *account);

extern struct Iroha_Result Iroha_RemoveAccount(void *storage, char *address);

extern struct Iroha_Result Iroha_GetStorage(void *storage,
                                            char *address,
                                            char *key);

extern struct Iroha_Result Iroha_SetStorage(void *storage,
                                            char *address,
                                            char *key,
                                            char *value);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif
