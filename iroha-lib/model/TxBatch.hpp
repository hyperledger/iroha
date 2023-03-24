#ifndef TX_BATCH_HPP
#define TX_BATCH_HPP

#include "transaction.pb.h"
#include <endpoint.pb.h>


namespace iroha_lib {

using namespace iroha::protocol;
using iroha::protocol::Transaction_Payload_BatchMeta_BatchType;

class TxBatch {

public:
    Transaction_Payload_BatchMeta_BatchType getBatchType(bool atomic) const
    {
        return atomic ? Transaction_Payload_BatchMeta_BatchType_ATOMIC
                      : Transaction_Payload_BatchMeta_BatchType_ORDERED;
    }

    TxList batch(std::vector<Transaction>& transactions, bool atomic = true)
    {
        TxList tx_list;

        if (atomic) {
            Transaction::Payload::BatchMeta meta;
            meta.set_type(getBatchType(atomic));

            for (auto& tx: transactions) {
                tx.payload().batch().New()->CopyFrom(meta);
                *tx_list.add_transactions() = tx;
            }
        } else {
            for (const auto& tx: transactions) {
                *tx_list.add_transactions() = tx;
            }
        }
        return tx_list;
    }
};

}

#endif
