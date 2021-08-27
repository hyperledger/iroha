/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_REPORT_ABORT_H
#define IROHA_REPORT_ABORT_H

#include <stdio.h>

#define assert_in_release(e) \
  ((void)((e) ? ((void)0) : __print_failed_assertion(#e, __FILE__, __LINE__)))
#define __print_failed_assertion(e, file, line) \
  ((void)printf("%s:%d: failed assertion `%s'\n", file, line, e), abort())

#define report_abort(msg) \
  ((void)fprintf(stderr, "%s:%d: `%s'\n", __FILE__, __LINE__, msg), abort())

#endif  // IROHA_REPORT_ABORT_H
