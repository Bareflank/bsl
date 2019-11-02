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

#include "boost/ut.hpp"
using namespace boost::ut;

#include <fstream>

auto
main() -> int
{
    std::string msg = "The answer is: 42";
    if (auto strm = std::ofstream("test.txt")) {
        strm << msg;
    }

    "nodiscard"_test = [] {
        uint8_t ui = 0;
        uint8_t &ui1 = ui;
        uint8_t const &ui2 = ui;

        bsl::discard(ui1);
        bsl::discard(ui2);
    };

    "default"_test = [] {
        auto ifa = bsl::ifarray<>();
        expect(ifa.empty());
    };

    "does not exist"_test = [] {
        expect(throws([] {
            bsl::ifarray<>("this_file_does_not_exist");
        }));
    };

    "fstat fails"_test = [] {
        auto ifa = bsl::ifarray<>();
        expect(throws([&] {
            ifa.file_size(42);
        }));
    };

    "map fails"_test = [] {
        auto ifa = bsl::ifarray<>();
        expect(throws([&] {
            ifa.map_file(42, 42, 42, 42);
        }));
    };

    "operator="_test = [] {
        auto ifa1 = bsl::ifarray("test.txt");
        expect(!!ifa1);

        auto ifa2 = bsl::ifarray("test.txt");
        expect(!!ifa2);

        ifa1 = std::move(ifa2);
        expect(!!ifa1);
    };

    "reset and release"_test = [] {
        auto ifa1 = bsl::ifarray("test.txt");
        auto ifa2 = bsl::ifarray("test.txt");
        ifa1.reset(ifa2.release());

        expect(!ifa1.empty());
        expect(ifa2.empty());
    };

    "swap"_test = [] {
        bsl::ifarray ifa1("test.txt");
        bsl::ifarray ifa2("test.txt");
        ifa1.swap(ifa2);

        expect(ifa1.size() == 17);
        expect(ifa2.size() == 17);
    };

    "get"_test = [] {
        bsl::ifarray ifa("test.txt");
        expect(ifa.get() != nullptr);
    };

    "get_deleter"_test = [] {
        bsl::ifarray ifa("test.txt");
        expect(nothrow([&] {
            auto d = ifa.get_deleter();
            bsl::discard(d);
        }));
    };

    "bool operator"_test = [] {
        bsl::ifarray ifa1;
        bsl::ifarray ifa2("test.txt");

        expect(!ifa1);
        expect(!!ifa2);
    };

    "operator[]"_test = [] {
        bsl::ifarray ifa1;
        bsl::ifarray ifa2{"test.txt"};

        expect(ifa2[0] == 'T');
        expect(throws([&] {
            bsl::discard(ifa1[0]);
        }));
        expect(throws([&] {
            bsl::discard(ifa2[42]);
        }));
    };

    "at"_test = [] {
        bsl::ifarray ifa1;
        bsl::ifarray ifa2{"test.txt"};

        expect(ifa2.at(0) == 'T');
        expect(throws([&] {
            bsl::discard(ifa1.at(0));
        }));
        expect(throws([&] {
            bsl::discard(ifa2.at(42));
        }));
    };

    "front"_test = [] {
        bsl::ifarray ifa1;
        bsl::ifarray ifa2{"test.txt"};

        expect(ifa2.front() == 'T');
        expect(throws([&] {
            bsl::discard(ifa1.front());
        }));
    };

    "back"_test = [] {
        bsl::ifarray ifa1;
        bsl::ifarray ifa2{"test.txt"};

        expect(ifa2.back() == '2');
        expect(throws([&] {
            bsl::discard(ifa1.back());
        }));
    };

    "data"_test = [] {
        bsl::ifarray ifa{"test.txt"};
        expect(ifa.data()[0] == 'T');
    };

    "begin / end"_test = [] {
        bsl::ifarray ifa{"test.txt"};

        for (auto it = ifa.begin(); it != ifa.end(); ++it) {
            expect(nothrow([&] {
                *it;
            }));
        }

        for (auto it = ifa.cbegin(); it != ifa.cend(); ++it) {
            expect(nothrow([&] {
                *it;
            }));
        }
    };

    "rbegin / rend"_test = [] {
        bsl::ifarray ifa{"test.txt"};

        for (auto it = ifa.rbegin(); it != ifa.rend(); ++it) {
            expect(nothrow([&] {
                *it;
            }));
        }

        for (auto it = ifa.crbegin(); it != ifa.crend(); ++it) {
            expect(nothrow([&] {
                *it;
            }));
        }
    };

    "empty"_test = [] {
        bsl::ifarray ifa1;
        bsl::ifarray ifa2{"test.txt"};

        expect(ifa1.empty());
        expect(!ifa2.empty());
    };

    "size"_test = [] {
        bsl::ifarray ifa1;
        bsl::ifarray ifa2{"test.txt"};

        expect(ifa1.size() == 0);    // NOLINT
        expect(ifa2.size() == 17);
    };

    "ssize"_test = [] {
        bsl::ifarray ifa1;
        bsl::ifarray ifa2{"test.txt"};

        expect(ifa1.ssize() == 0);
        expect(ifa2.ssize() == 17);
    };

    "size_bytes"_test = [] {
        bsl::ifarray ifa1;
        bsl::ifarray ifa2{"test.txt"};

        expect(ifa1.size_bytes() == 0);
        expect(ifa2.size_bytes() == 17);
    };

    "max_size"_test = [] {
        bsl::ifarray ifa;
        expect(ifa.max_size() <= std::numeric_limits<size_t>::max());
    };

    "comparison operators"_test = [] {
        bsl::ifarray ifa1;
        bsl::ifarray ifa2{"test.txt"};
        bsl::ifarray ifa3{"test.txt"};

        expect(ifa1 != ifa2);
        expect(ifa2 == ifa3);
    };

    "ostream"_test = [] {
        bsl::ifarray ifa{"test.txt"};
        std::cout << "testing os: " << ifa << '\n';
    };
}
