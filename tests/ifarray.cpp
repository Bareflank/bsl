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

#define BSL_THROW_ON_CONTRACT_VIOLATION
#define BSL_CORE_GUIDELINE_COMPLIANT
#include "../include/bsl.h"

#include <fstream>
#include <catch2/catch.hpp>

// --------------------------------------------------------------------------
// Tests
// --------------------------------------------------------------------------

TEST_CASE("default")
{
    auto ifa = bsl::ifarray<>();
    CHECK(ifa.empty());
}

TEST_CASE("does not exist")
{
    CHECK_THROWS(bsl::ifarray<>("this_file_does_not_exist"));
}

TEST_CASE("fstat fails")
{
    auto ifa = bsl::ifarray<>();
    CHECK_THROWS(ifa.file_size(42));
}

TEST_CASE("map fails")
{
    auto ifa = bsl::ifarray<>();
    CHECK_THROWS(ifa.map_file(42, 42, 42, 42));
}

TEST_CASE("success")
{
    std::string msg = "The answer is: 42";
    if (auto strm = std::ofstream("test.txt")) {
        CHECK_THROWS(bsl::ifarray<char>("test.txt"));
        strm << msg;
    }

    CHECK_NOTHROW(bsl::ifarray<char>("test.txt"));
}

TEST_CASE("operator=")
{
    auto ifa1 = bsl::ifarray<char>("test.txt");
    CHECK(ifa1);

    auto ifa2 = bsl::ifarray<char>("test.txt");
    CHECK(ifa2);

    ifa1 = std::move(ifa2);
    CHECK(ifa1);
}

TEST_CASE("reset and release")
{
    auto ifa1 = bsl::ifarray<char>("test.txt");
    auto ifa2 = bsl::ifarray<char>("test.txt");
    ifa1.reset(ifa2.release());

    CHECK(!ifa1.empty());
    CHECK(ifa2.empty());
}

TEST_CASE("swap")
{
    bsl::ifarray<char> ifa1("test.txt");
    bsl::ifarray<char> ifa2("test.txt");
    ifa1.swap(ifa2);

    CHECK(ifa1.size() == 17);
    CHECK(ifa2.size() == 17);
}

TEST_CASE("get")
{
    bsl::ifarray<char> ifa("test.txt");
    CHECK(ifa.get() != nullptr);
}

TEST_CASE("get_deleter")
{
    bsl::ifarray<char> ifa("test.txt");
    CHECK_NOTHROW(ifa.get_deleter());
}

TEST_CASE("bool operator")
{
    bsl::ifarray<char> ifa1;
    bsl::ifarray<char> ifa2("test.txt");

    CHECK(!ifa1);
    CHECK(ifa2);
}

TEST_CASE("operator[]")
{
    bsl::ifarray<char> ifa1;
    bsl::ifarray<char> ifa2{"test.txt"};

    CHECK(ifa2[0] == 'T');
    CHECK_THROWS(ifa1[0]);
    CHECK_THROWS(ifa2[42]);
}

TEST_CASE("at")
{
    bsl::ifarray<char> ifa1;
    bsl::ifarray<char> ifa2{"test.txt"};

    CHECK(ifa2.at(0) == 'T');
    CHECK_THROWS(ifa1.at(0));
    CHECK_THROWS(ifa2.at(42));
}

TEST_CASE("front")
{
    bsl::ifarray<char> ifa1;
    bsl::ifarray<char> ifa2{"test.txt"};

    CHECK(ifa2.front() == 'T');
    CHECK_THROWS(ifa1.front());
}

TEST_CASE("back")
{
    bsl::ifarray<char> ifa1;
    bsl::ifarray<char> ifa2{"test.txt"};

    CHECK(ifa2.back() == '2');
    CHECK_THROWS(ifa1.back());
}

TEST_CASE("data")
{
    bsl::ifarray<char> ifa{"test.txt"};
    CHECK(ifa.data()[0] == 'T');
}

TEST_CASE("begin / end")
{
    bsl::ifarray<char> ifa{"test.txt"};

    for (auto it = ifa.begin(); it != ifa.end(); ++it) {
        CHECK_NOTHROW(*it);
    }

    for (auto it = ifa.cbegin(); it != ifa.cend(); ++it) {
        CHECK_NOTHROW(*it);
    }
}

TEST_CASE("rbegin / rend")
{
    bsl::ifarray<char> ifa{"test.txt"};

    for (auto it = ifa.rbegin(); it != ifa.rend(); ++it) {
        CHECK_NOTHROW(*it);
    }

    for (auto it = ifa.crbegin(); it != ifa.crend(); ++it) {
        CHECK_NOTHROW(*it);
    }
}

TEST_CASE("empty")
{
    bsl::ifarray<char> ifa1;
    bsl::ifarray<char> ifa2{"test.txt"};

    CHECK(ifa1.empty());
    CHECK(!ifa2.empty());
}

TEST_CASE("size")
{
    bsl::ifarray<char> ifa1;
    bsl::ifarray<char> ifa2{"test.txt"};

    CHECK(ifa1.size() == 0);    // NOLINT
    CHECK(ifa2.size() == 17);
}

TEST_CASE("ssize")
{
    bsl::ifarray<char> ifa1;
    bsl::ifarray<char> ifa2{"test.txt"};

    CHECK(ifa1.ssize() == 0);
    CHECK(ifa2.ssize() == 17);
}

TEST_CASE("size_bytes")
{
    bsl::ifarray<char> ifa1;
    bsl::ifarray<char> ifa2{"test.txt"};

    CHECK(ifa1.size_bytes() == 0);
    CHECK(ifa2.size_bytes() == 17);
}

TEST_CASE("max_size")
{
    bsl::ifarray<char> ifa;
    CHECK(ifa.max_size() == std::numeric_limits<ptrdiff_t>::max());
}

TEST_CASE("comparison operators")
{
    bsl::ifarray<char> ifa1;
    bsl::ifarray<char> ifa2{"test.txt"};
    bsl::ifarray<char> ifa3{"test.txt"};

    CHECK((ifa1 != ifa2));
    CHECK((ifa2 == ifa3));
}

TEST_CASE("ostream")
{
    bsl::ifarray<char> ifa{"test.txt"};
    std::cout << "testing os: " << ifa << '\n';
}
