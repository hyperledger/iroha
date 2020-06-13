/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_CRYPTO_UTIMACO_CLEANUP_HPP
#define IROHA_CRYPTO_UTIMACO_CLEANUP_HPP

#include "cxi.h"

// there are no #undef's at all...
#undef LOG_LEVEL_NONE
#undef LOG_LEVEL_ERROR
#undef LOG_LEVEL_WARNING
#undef LOG_LEVEL_INFO
#undef LOG_LEVEL_TRACE
#undef LOG_LEVEL_DEBUG
#undef CS_MUTEX_DECLARE
#undef CS_MUTEX_DECLARE_INIT
#undef CS_MUTEX_INIT
#undef INIT_MUTEX_ONCE
#undef CS_MUTEX_LOCK
#undef CS_MUTEX_UNLOCK
#undef CS_MUTEX_DESTROY
#undef CS_MUTEX_DECLARE
#undef CS_MUTEX_DECLARE_INIT
#undef CS_MUTEX_INIT
#undef CS_MUTEX_LOCK
#undef CS_MUTEX_UNLOCK
#undef CS_MUTEX_DESTROY
#undef NULL_REF
#undef Blob  // woo-hoo!
#undef MIN
#undef MAX
#undef GMTIME
#undef LOCALTIME
#undef GMTIME
#undef LOCALTIME

#endif
