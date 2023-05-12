#pragma once

#include <endpoint.grpc.pb.h>
#include <grpc++/grpc++.h>


namespace iroha_lib {

using namespace iroha::protocol;

class GrpcClient {

public:
    GrpcClient(
            const std::string& target_ip,
            const uint16_t port);
    grpc::Status send(const Transaction& tx);
    grpc::Status send(const TxList& tx_list);
    QueryResponse send(const iroha::protocol::Query& query);
    ToriiResponse getTxStatus(const std::string& tx_hash);

private:
    std::shared_ptr<CommandService_v1::StubInterface> command_stub_;
    std::shared_ptr<QueryService_v1::StubInterface> query_stub_;
};

}
