/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_RXCPP_SUBJECT_USAGE_HPP
#define IROHA_RXCPP_SUBJECT_USAGE_HPP
#include <gtest/gtest.h>

#include <iostream>
#include "rxcpp/rx.hpp"

using namespace rxcpp;
using namespace rxcpp::sources;
using namespace rxcpp::subjects;
using namespace rxcpp::util;
using namespace std;

struct Person {
  string name;
  string gender;
  int age;
};

TEST(rxcppTest, usage_subject_test) {
  subject<Person> person;

  // group ages by gender
  auto agebygender = person.get_observable().subscribe(
      [](auto val) { cout << val.name << " " << val.gender << endl; });

  person.get_observable().subscribe([](auto val) {
    cout << "YET ANOTHER " << val.name << " " << val.gender << endl;
  });

  for (auto i = 0; i < 10; i++) {
    person.get_subscriber().on_next(Person{"Tom", "Male", 32});
    cout << "next" << endl;
  }
  person.get_subscriber().on_completed();
  person.get_subscriber().on_next(Person{"Vasya", "Male", 32});
}
#endif  // IROHA_RXCPP_SUBJECT_USAGE_HPP
