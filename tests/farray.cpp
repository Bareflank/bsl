//
// Copyright (C) 2019 Assured Information Security, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#define BAREFLANK_THROW_ON_CONTRACT_VIOLATION
#define BAREFLANK_CORE_GUIDELINE_COMPLIANT
#include "../include/bsl.h"

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

// --------------------------------------------------------------------------
// Tests
// --------------------------------------------------------------------------

TEST_CASE("default")
{
    auto fa = bsl::ifarray();
    auto ifa = bsl::ifarray();

    CHECK(fa.empty());
    CHECK(ifa.empty());
}

TEST_CASE("does not exist")
{
    CHECK_THROWS(bsl::ifarray("this_file_does_not_exist"));
}

TEST_CASE("success")
{
    std::string msg = "The answer is: 42";
    if (auto strm = std::ofstream("test.txt")) {
        CHECK_THROWS(bsl::ifarray<char>("test.txt"));
        strm << msg;
    }

    auto ifa = bsl::ifarray<char>("test.txt");

    CHECK(ifa.size() == msg.size());
    CHECK(ifa.front() == 'T');
    CHECK(ifa.back() == '2');

    for (const auto &c : ifa) {
        std::cout << c;
    }

    std::cout << '\n';
}
