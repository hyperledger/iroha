/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>

#include "endpoint.grpc.pb.h"
#include "framework/result_gtest_checkers.hpp"
#include "framework/test_client_factory.hpp"
#include "framework/test_logger.hpp"
#include "logger/logger_manager.hpp"
#include "main/server_runner.hpp"
#include "module/shared_model/interface_mocks.hpp"
#include "network/impl/client_factory.hpp"
#include "network/impl/peer_tls_certificates_provider_root.hpp"
#include "network/impl/tls_credentials.hpp"

namespace {
  // two key/cert pairs:
  // * one with CN=public_key_1,
  //   subjectAltName=IP:127.0.0.1,otherName:1.3.101.112;UTF8:public_key_1
  // * another with CN=public_key_2,
  //   subjectAltName=IP:127.0.0.1,otherName:1.3.101.112;UTF8:public_key_2
  // * third one with CN=another_public_key
  //   subjectAltName=IP:127.0.0.1,otherName:1.3.101.112;UTF8:another_public_key

  static const shared_model::crypto::PublicKey kPeer2Key("deadbeef");
  static const auto kPeer2TlsCreds =
      std::make_shared<const iroha::network::TlsCredentials>(
          R"(-----BEGIN PRIVATE KEY-----
MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBALRPxvMGB3JhqXZV
bm52QtLc3djGfxJ82szidEeQheG8JcUlJI8QnFTME669Yvv407J40JgT/UG2sSNl
O2ZglhlECEWXpaxx9zwaNfFaOaGzySM+rzElZbMmPuvpkxxNEyE4tAtkeboG6cm9
hcKu3ry2gX9nb0PH7z1Y4RFUjY1JAgMBAAECgYA9Nffr+Ff+1Hia21Wp2ivFOYV2
Waw5snj0pMukn8NTZnPMAVfv2Uu43a6w20oHD+mN5MWrWt3WuRZZVbxcfN13FEzP
0IaTrzY5gwWULA6wcnkglx3ZrDJM9RyenzIIHpa0s9cOXjHsStezkjltMwNNrGEP
a88OpBMId6R15xLGIQJBAN+Eu11P5p44ZF2sGyK0v47jBR7c+DvrkrbxLNh9TCtl
dy+VmQEmNQS6DCTeRTb/MqzQV0qDeT2Ouida3JmB6d8CQQDOg609HXrURpzmbt/d
FwMV99lEBBsnwFmbSXgMwE2vXJ6Xe2Up+Udevv5hLkM9UlJZbLeo85ZnAmG/UlDz
SD3XAkA7L+CVYvUEbJZXH53H4Ojgo0jV1Vl+NHETNGXVpcgnraST2x866K0dZU6V
7K2TVJxMmpaiypGuNT8h8LN9iqMtAkEAzfaBxtwp7qBmR2P5HPWgfD5uj+lQc/rg
44EInB8G24iSGx5ULOKTDamK5r1PDk+WFd3Z5kTake3MMxYT6i74jQJBAJUs+Oez
y7oScHGNmXS7qpYwK9pVLxggDbKo6qyzHabZToG1mCOjcnklZeshSoCrW9a75i40
BYHcf5sNEAv1+sU=
-----END PRIVATE KEY-----)",
          R"(-----BEGIN CERTIFICATE-----
MIICmjCCAgMCAQEwDQYJKoZIhvcNAQEFBQAweTELMAkGA1UEBhMCSlAxEjAQBgNV
BAgMCU9ORSBXT1JMRDEUMBIGA1UEBwwLT05FIEVDT05PTVkxFjAUBgNVBAoMDVNv
cmFtaXRzdSBMdGQxDTALBgNVBAsMBHRlc3QxGTAXBgNVBAMMEGlyb2hhIHBlZXIg
ZGVhZGIwHhcNMTkwOTIzMTU1MTA3WhcNMjAwOTIyMTU1MTA3WjB5MQswCQYDVQQG
EwJKUDESMBAGA1UECAwJT05FIFdPUkxEMRQwEgYDVQQHDAtPTkUgRUNPTk9NWTEW
MBQGA1UECgwNU29yYW1pdHN1IEx0ZDENMAsGA1UECwwEdGVzdDEZMBcGA1UEAwwQ
aXJvaGEgcGVlciBkZWFkYjCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAtE/G
8wYHcmGpdlVubnZC0tzd2MZ/EnzazOJ0R5CF4bwlxSUkjxCcVMwTrr1i+/jTsnjQ
mBP9QbaxI2U7ZmCWGUQIRZelrHH3PBo18Vo5obPJIz6vMSVlsyY+6+mTHE0TITi0
C2R5ugbpyb2Fwq7evLaBf2dvQ8fvPVjhEVSNjUkCAwEAAaM3MDUwMwYDVR0RAQH/
BCkwJ4IFaXJvaGGCHmlyb2hhLW5vZGUtcHVibGljLWtleS5kZWFkYmVlZjANBgkq
hkiG9w0BAQUFAAOBgQALU8MGLGwJCjb3xOAif0YZ7l1K2ND9PV0BmJjJz+N71OCF
gwST1teaC4skxzt1Mdzv5gYuEix2zHCbE4IK56EUBkMIxDQxphWrx9kTWF97GvAe
CySW3ZvsOIR0ngxlnBIOi0LuWrpzmSEmDDtEljoFpkeAAMS/abK6izWMai5DQw==
-----END CERTIFICATE-----)");
  static const shared_model::crypto::PublicKey kPeer1Key("b16b00b5");
  static const auto kPeer1TlsCreds =
      std::make_shared<const iroha::network::TlsCredentials>(
          R"(-----BEGIN PRIVATE KEY-----
MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAMR05oJ1KDPDgknX
0PRSUsIJa3B1wXulPAwJKmkQL7NowOtbv+ErIULVKlRDAV6fWKZKH+dzc7/W5qjH
ytkDOj3t6BK+Ktvn2Wdh4T2L6eMNBQKkqh6pzFzkdNWOy651FHbqh/OkFrSOia2k
5jwEYFNVY9qIfV/pyhPnZeZT0TuNAgMBAAECgYBp5ppbuMvzG3EgXTZGfhoefvVr
qg6imG/GDSrPd+o+zDkypkLJHnbPkBlBUt1qJHulKFAKdDHxN+cfFJREZ3j89qtY
ovg8BtPQ+NXzEjZobNUg1wWasrzBTNPy954CJt2wVBXDUF1IAp+PWusqwOEDSjRK
hOrDeg/UzHm8nhvYAQJBAPNbsvLZfqKSqFqAeGbWnLf3yo8QcNGIy+XdoOaYFmec
bOTFC1OitDf8DdSCgnZnAowwxcPNsYU73Mx1Md6t+5cCQQDOqXsNg7DBc48rRRbw
1SstpinZ9ZvQNb1yYPJBHzu6OUMrSE2aa3oT8phvCbZz6uiWtbasLygY0kgPPZ/h
BLZ7AkBmPepq2TG4/8C3dS4glp31NKfnf1LG1aBEjN6iwtb25ONjId3mX38z3jO5
SrOhJxoM6BjOcMbaYRIc3Ef9dD81AkBMPSfBH5DofOoXK2DALdPE/mS4HKyDjh+6
f1s/fPc6xv8pi33ddsLNcxSa+flOIB3340dlk+v15DVjMfe2OlfbAkEAyu6bROo+
4O6ef8UIXFxAnkMWmU+kv8febgLsrhZ//6eqXWwv8Z3Da6s+DOsvPt8lZjn7m7v5
7V76NoysmF+cWA==
-----END PRIVATE KEY-----)",
          R"(-----BEGIN CERTIFICATE-----
MIICmjCCAgMCAQEwDQYJKoZIhvcNAQEFBQAweTELMAkGA1UEBhMCSlAxEjAQBgNV
BAgMCU9ORSBXT1JMRDEUMBIGA1UEBwwLT05FIEVDT05PTVkxFjAUBgNVBAoMDVNv
cmFtaXRzdSBMdGQxDTALBgNVBAsMBHRlc3QxGTAXBgNVBAMMEGlyb2hhIHBlZXIg
YjE2YjAwHhcNMTkwOTIzMTU1MzE4WhcNMjAwOTIyMTU1MzE4WjB5MQswCQYDVQQG
EwJKUDESMBAGA1UECAwJT05FIFdPUkxEMRQwEgYDVQQHDAtPTkUgRUNPTk9NWTEW
MBQGA1UECgwNU29yYW1pdHN1IEx0ZDENMAsGA1UECwwEdGVzdDEZMBcGA1UEAwwQ
aXJvaGEgcGVlciBiMTZiMDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAxHTm
gnUoM8OCSdfQ9FJSwglrcHXBe6U8DAkqaRAvs2jA61u/4SshQtUqVEMBXp9Ypkof
53Nzv9bmqMfK2QM6Pe3oEr4q2+fZZ2HhPYvp4w0FAqSqHqnMXOR01Y7LrnUUduqH
86QWtI6JraTmPARgU1Vj2oh9X+nKE+dl5lPRO40CAwEAAaM3MDUwMwYDVR0RAQH/
BCkwJ4IFaXJvaGGCHmlyb2hhLW5vZGUtcHVibGljLWtleS5iMTZiMDBiNTANBgkq
hkiG9w0BAQUFAAOBgQCC+K3fmd+5TzK8m6IT6wuu4KY2tnmhP5xHpl1G/fTfLWXD
y11zQNyRxMsYFhX7ssKvuoYHSLZ1fYr/6WlsdbTH1mkRhaeEuPVY7TtDwf31RvK8
4xh2xtYPDIUt3GG4mnkb+rPioVPjGXsm8zZd4f/X0Em5xV9WEtDsexjxG9qMHA==
-----END CERTIFICATE-----)");
  static const auto kPeer3TlsCreds =
      std::make_shared<const iroha::network::TlsCredentials>(
          R"(-----BEGIN PRIVATE KEY-----
MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAL5kxPj4YdQEKD5N
K8pN/ILTTbN/JQwXjG/pU7+WebNdADD42r1cHTOmmIebFNhe/wh9hlONwvS3whn7
a2PCgpSZpeid5caUSSpE4TU3bLAS+GtfYwkN+IKA1D2zcB9CnAlp8h+Pe4kLnN5A
Ee5CY5wu9hOD38tE+hfO16G9iwFxAgMBAAECgYBtXRrb3GjtTToEl3V47pUGXPP8
ECOqr3gm7IMDwR7FDb3HY5raPKg1fBOPiWBO7TpXmSroobyDr24aWJYWJqu0TFZ1
npUF2Yhkbzwj2OPlrXUHkV9UCnYT9K2m8M2LdmO+YT1EZ5lxwcauhBjDOaSDbZ1b
8wE0zVLuALJ5giuaMQJBAOMPPlWS6WgSrUnTn0dKOilim6GJyCQU+gau/1dIRQBP
vdJhiYY8ZrkU6XlSd0RF4+0hD0X9RJo9oFPOCEQPdp0CQQDWqSYcNkypOPGAM1BI
F6TmjeHQcshioOuuv8Apkjqe5bTZK53YBswgTPDHfLzEvIBLyFECN6QMOKqfOBJk
9VPlAkEAptdgmkilMU/n/UN+2kd0jUxjx0MSyVCQl7Cm91+nNB9j/96jyvs/D+iJ
1hf+gzBH1spgCrGbYyq9UFcoQ7qJEQJAIZy+4PAHtP+7oQ1n5sH9CjTxRQiUJA16
mhRgbKH/F950IQVZY/g8glpJ4ZLApDW4CSXGuYgo4dkFroTDLJfVmQJAdI5+Qkp9
FybA7EwGHZGO7Akh0DGdFcGo3VyGpQUvd7A/KsZJ5AlFwkZiA9qLpcKFEZLLEx33
uJgvijc7Q7JQ8A==
-----END PRIVATE KEY-----)",
          R"(-----BEGIN CERTIFICATE-----
MIICmTCCAgICAQEwDQYJKoZIhvcNAQEFBQAweTELMAkGA1UEBhMCSlAxEjAQBgNV
BAgMCU9ORSBXT1JMRDEUMBIGA1UEBwwLT05FIEVDT05PTVkxFjAUBgNVBAoMDVNv
cmFtaXRzdSBMdGQxDTALBgNVBAsMBHRlc3QxGTAXBgNVBAMMEGlyb2hhIHBlZXIg
YmFkZDAwHhcNMTkwOTIzMTYxNTIzWhcNMjAwOTIyMTYxNTIzWjB5MQswCQYDVQQG
EwJKUDESMBAGA1UECAwJT05FIFdPUkxEMRQwEgYDVQQHDAtPTkUgRUNPTk9NWTEW
MBQGA1UECgwNU29yYW1pdHN1IEx0ZDENMAsGA1UECwwEdGVzdDEZMBcGA1UEAwwQ
aXJvaGEgcGVlciBiYWRkMDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAvmTE
+Phh1AQoPk0ryk38gtNNs38lDBeMb+lTv5Z5s10AMPjavVwdM6aYh5sU2F7/CH2G
U43C9LfCGftrY8KClJml6J3lxpRJKkThNTdssBL4a19jCQ34goDUPbNwH0KcCWny
H497iQuc3kAR7kJjnC72E4Pfy0T6F87Xob2LAXECAwEAAaM2MDQwMgYDVR0RAQH/
BCgwJoIFaXJvaGGCHWlyb2hhLW5vZGUtcHVibGljLWtleS5iYWRkMDBkMA0GCSqG
SIb3DQEBBQUAA4GBACW7TGshUKZ+mThpyMit04sl8KremeHa8kJ4No5+k/d1XZ4D
Is2sOzOnedElSptjufMx2zOSyRf/arqKsGN/FvrGKQM3z+u8kBIXbyCGUWY4ztVl
foAaWCjkHEXorw9JjXRNtU4QWYQ6R9geyvafXXqjG0rZigEbyVA/qe5ynNWc
-----END CERTIFICATE-----)");

  constexpr auto kLocalhost = "127.0.0.1";
  constexpr auto kLocalhostAnyPort = "127.0.0.1:0";

  class MockQueryService : public iroha::protocol::QueryService_v1::Service {
   public:
    grpc::Status Find(grpc::ServerContext *context,
                      const iroha::protocol::Query *request,
                      iroha::protocol::QueryResponse *response) override {
      return grpc::Status::OK;
    }
  };
}  // namespace

class ClientFactoryTest : public ::testing::Test {
 protected:
  void SetUp() override {
    insecure_client_factory_ = iroha::network::getTestInsecureClientFactory();
    insecure_server_runner_ = std::make_unique<iroha::network::ServerRunner>(
        kLocalhostAnyPort,
        getTestLoggerManager()->getChild("InsecureServerRunner"),
        false);
    insecure_server_runner_->append(std::make_shared<MockQueryService>());
    auto insecure_port_optional =
        iroha::expected::resultToOptionalValue(insecure_server_runner_->run());
    ASSERT_TRUE(insecure_port_optional) << "Could not create insecure server";
    insecure_address_ =
        std::string(kLocalhost) + ":" + std::to_string(*insecure_port_optional);

    auto server_cert_provider =
        std::make_shared<iroha::network::PeerTlsCertificatesProviderRoot>(
            kPeer1TlsCreds->certificate);

    tls_client_factory_ = iroha::network::getTestTlsClientFactory(
        std::string(kPeer2TlsCreds->certificate), kPeer1TlsCreds);
    tls_server_runner_ = std::make_unique<iroha::network::ServerRunner>(
        kLocalhostAnyPort,
        getTestLoggerManager()->getChild("TlsServerRunner"),
        false,
        kPeer2TlsCreds,
        std::shared_ptr<const iroha::network::PeerTlsCertificatesProvider>(
            server_cert_provider));
    tls_server_runner_->append(std::make_shared<MockQueryService>());
    auto tls_port_optional =
        iroha::expected::resultToOptionalValue(tls_server_runner_->run());
    ASSERT_TRUE(tls_port_optional) << "Could not create TLS server";
    tls_address_ =
        std::string(kLocalhost) + ":" + std::to_string(*tls_port_optional);

    outside_client_factory_ = iroha::network::getTestTlsClientFactory(
        std::string(kPeer2TlsCreds->certificate), kPeer3TlsCreds);
  }

  auto makeRequestAndCheckStatus(
      const std::shared_ptr<iroha::protocol::QueryService_v1::StubInterface>
          &client,
      grpc::StatusCode code) {
    iroha::protocol::Query query;
    iroha::protocol::QueryResponse response;

    grpc::ClientContext client_context;

    auto status = client->Find(&client_context, query, &response);

    ASSERT_EQ(status.error_code(), code) << status.error_message();
  }

  auto makeClient(
      const std::unique_ptr<iroha::network::GenericClientFactory> &factory,
      const std::string &address) {
    return framework::expected::assertAndGetResultValue(
        factory->createClient<iroha::protocol::QueryService_v1>(
            *makePeer(address, kPeer2Key, kPeer2TlsCreds->certificate)));
  }

  std::string insecure_address_;
  std::unique_ptr<iroha::network::ServerRunner> insecure_server_runner_;
  std::unique_ptr<iroha::network::GenericClientFactory>
      insecure_client_factory_;

  std::string tls_address_;
  std::unique_ptr<iroha::network::ServerRunner> tls_server_runner_;
  std::unique_ptr<iroha::network::GenericClientFactory> tls_client_factory_;

  std::unique_ptr<iroha::network::GenericClientFactory> outside_client_factory_;
};

TEST_F(ClientFactoryTest, InsecureConnectionToInsecureServer) {
  makeRequestAndCheckStatus(
      makeClient(insecure_client_factory_, insecure_address_), grpc::OK);
}

TEST_F(ClientFactoryTest, SecureConnectionToInsecureServer) {
  makeRequestAndCheckStatus(makeClient(tls_client_factory_, insecure_address_),
                            grpc::UNAVAILABLE);
}

TEST_F(ClientFactoryTest, InsecureConnectionToSecureServer) {
  makeRequestAndCheckStatus(makeClient(insecure_client_factory_, tls_address_),
                            grpc::UNAVAILABLE);
}

TEST_F(ClientFactoryTest, SecureConnectionToSecureServer) {
  makeRequestAndCheckStatus(makeClient(tls_client_factory_, tls_address_),
                            grpc::OK);
}

TEST_F(ClientFactoryTest, SecureConnectionToSecureServerWrongClientPublicKey) {
  makeRequestAndCheckStatus(makeClient(outside_client_factory_, tls_address_),
                            grpc::CANCELLED);
}
