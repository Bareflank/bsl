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

auto
main() -> int
{
    "nodiscard"_test = [] {
        int i = 0;
        int &i1 = i;
        int const &i2 = i;

        bsl::discard(i1);
        bsl::discard(i2);
    };

    "nodelete"_test = [] {
        auto f = new int[1];
        bsl::dynarray<int, bsl::nodelete> da(f, 1);

        delete[] f;
    };

    "default constructor"_test = [] {
        bsl::dynarray<int> da1;
        bsl::dynarray<int> da2 = {};
    };

    "ptr, count constructor"_test = [] {
        auto f = new int[1];
        expect(throws([&] {
            bsl::dynarray<int>(nullptr, 1);
        }));
        expect(throws([&] {
            bsl::dynarray<int>(f, 0);
        }));

        bsl::dynarray<int>(f, 1);
    };

    "ptr, count, copy deleter"_test = [] {
        auto f = new int[1];
        auto d = bsl::default_deleter<int>();
        expect(throws([&] {
            bsl::dynarray<int>(nullptr, 1, d);
        }));
        expect(throws([&] {
            bsl::dynarray<int>(f, 0, d);
        }));

        bsl::dynarray<int>(f, 1, d);
    };

    "ptr, count, move deleter"_test = [] {
        auto f = new int[1];
        using d = bsl::default_deleter<int>;
        expect(throws([&] {
            bsl::dynarray<int>(nullptr, 1, d());
        }));
        expect(throws([&] {
            bsl::dynarray<int>(f, 0, d());
        }));

        bsl::dynarray<int>(f, 1, d());
    };

    "move constructor"_test = [] {
        auto da1 = bsl::dynarray<int>(new int[1], 1);
        expect(!!da1);

        auto da2 = bsl::dynarray<int>(std::move(da1));
        expect(!!da2);
    };

    "move operator=, self assignment"_test = [] {
        auto da = bsl::dynarray<int>(new int[1], 1);
        da = std::move(da);
    };

    "move operator=, empty"_test = [] {
        auto da1 = bsl::dynarray<int>(new int[1], 1);
        expect(!!da1);

        auto da2 = bsl::dynarray<int>();
        expect(!da2);

        da1 = std::move(da2);
        expect(!da1);
    };

    "move operator=, valid"_test = [] {
        auto da1 = bsl::dynarray<int>(new int[1], 1);
        expect(!!da1);

        auto da2 = bsl::dynarray<int>(new int[1], 1);
        expect(!!da2);

        da1 = std::move(da2);
        expect(!!da1);
    };

    "reset, empty"_test = [] {
        auto da = bsl::dynarray<int>();

        expect(!da);
        da.reset();
        expect(!da);
    };

    "reset, default"_test = [] {
        auto da = bsl::dynarray<int>(new int[1], 1);

        expect(!!da);
        da.reset();
        expect(!da);
    };

    "reset, release"_test = [] {
        auto da1 = bsl::dynarray<int>(new int[1], 1);
        auto da2 = bsl::dynarray<int>(new int[1], 1);
        da1.reset(da2.release());

        expect(!!da1);
        expect(!da2);
    };

    "swap"_test = [] {
        bsl::dynarray<int> da1{new int[1], 1};
        bsl::dynarray<int> da2{new int[2], 2};

        da1.front() = 23;
        da2.front() = 42;

        expect(da1.front() == 23);
        expect(da1.size() == 1);
        expect(da2.front() == 42);
        expect(da2.size() == 2);

        da1.swap(da2);

        expect(da1.front() == 42);
        expect(da1.size() == 2);
        expect(da2.front() == 23);
        expect(da2.size() == 1);

        da1.swap(da2);

        expect(da1.front() == 23);
        expect(da1.size() == 1);
        expect(da2.front() == 42);
        expect(da2.size() == 2);
    };

    "get"_test = [] {
        auto f = new int[1];
        auto da1 = bsl::dynarray<int>();
        auto da2 = bsl::dynarray<int>(f, 1);

        expect(da1.get() == nullptr);
        expect(da2.get() == f);
    };

    "get_deleter"_test = [] {
        class test
        {
            bsl::dynarray<int> da;

        public:
            auto
            test1() -> void
            {
                expect(nothrow([&] {
                    bsl::discard(da.get_deleter());
                }));
            }

            auto
            test2() const -> void
            {
                expect(nothrow([&] {
                    bsl::discard(da.get_deleter());
                }));
            }
        };

        test t;
        t.test1();
        t.test2();
    };

    "operator bool"_test = [] {
        auto da1 = bsl::dynarray<int>();
        auto da2 = bsl::dynarray<int>(new int[1], 1);

        expect(!da1);
        expect(!!da2);
    };

    "operator[]"_test = [] {
        class test
        {
            bsl::dynarray<int> da1;
            bsl::dynarray<int> da2{new int[1], 1};

        public:
            auto
            test1() -> void
            {
                da2[0] = 23;
                expect(da2[0] == 23);
                da2[0] = 42;
                expect(da2[0] == 42);

                expect(throws([&] {
                    bsl::discard(da1[0]);
                }));
                expect(throws([&] {
                    bsl::discard(da2[42]);
                }));
            }

            auto
            test2() const -> void
            {
                expect(da2[0] == 42);

                expect(throws([&] {
                    bsl::discard(da1[0]);
                }));
                expect(throws([&] {
                    bsl::discard(da2[42]);
                }));
            }
        };

        test t;
        t.test1();
        t.test2();
    };

    "at"_test = [] {
        class test
        {
            bsl::dynarray<int> da1;
            bsl::dynarray<int> da2{new int[1], 1};

        public:
            auto
            test1() -> void
            {
                da2.at(0) = 23;
                expect(da2.at(0) == 23);
                da2.at(0) = 42;
                expect(da2.at(0) == 42);

                expect(throws([&] {
                    bsl::discard(da1.at(0));
                }));
                expect(throws([&] {
                    bsl::discard(da2.at(42));
                }));
            }

            auto
            test2() const -> void
            {
                expect(da2.at(0) == 42);

                expect(throws([&] {
                    bsl::discard(da1.at(0));
                }));
                expect(throws([&] {
                    bsl::discard(da2.at(42));
                }));
            }
        };

        test t;
        t.test1();
        t.test2();
    };

    "front"_test = [] {
        class test
        {
            bsl::dynarray<int> da1;
            bsl::dynarray<int> da2{new int[1], 1};

        public:
            auto
            test1() -> void
            {
                da2.front() = 23;
                expect(da2.front() == 23);
                da2.front() = 42;
                expect(da2.front() == 42);

                expect(throws([&] {
                    bsl::discard(da1.front());
                }));
            }

            auto
            test2() const -> void
            {
                expect(da2.front() == 42);

                expect(throws([&] {
                    bsl::discard(da1.front());
                }));
            }
        };

        test t;
        t.test1();
        t.test2();
    };

    "back"_test = [] {
        class test
        {
            bsl::dynarray<int> da1;
            bsl::dynarray<int> da2{new int[1], 1};

        public:
            auto
            test1() -> void
            {
                da2.back() = 23;
                expect(da2.back() == 23);
                da2.back() = 42;
                expect(da2.back() == 42);

                expect(throws([&] {
                    bsl::discard(da1.back());
                }));
            }

            auto
            test2() const -> void
            {
                expect(da2.back() == 42);

                expect(throws([&] {
                    bsl::discard(da1.back());
                }));
            }
        };

        test t;
        t.test1();
        t.test2();
    };

    "data"_test = [] {
        class test
        {
            bsl::dynarray<int> da1;
            bsl::dynarray<int> da2{new int[1], 1};

        public:
            auto
            test1() -> void
            {
                da2.data()[0] = 23;
                expect(da2.data()[0] == 23);
                da2.data()[0] = 42;
                expect(da2.data()[0] == 42);
            }

            auto
            test2() const -> void
            {
                expect(da2.data()[0] == 42);
            }
        };

        test t;
        t.test1();
        t.test2();
    };

    "begin / end"_test = [] {
        class test
        {
            bsl::dynarray<int> da{new int[1], 1};

        public:
            auto
            test1() -> void
            {
                for (auto it = da.begin(); it != da.end(); ++it) {
                    *it = 42;
                }
            }

            auto
            test2() const -> void
            {
                for (auto it = da.begin(); it != da.end(); ++it) {
                    expect(*it == 42);
                }

                for (auto it = da.cbegin(); it != da.cend(); ++it) {
                    expect(*it == 42);
                }
            }
        };

        test t;
        t.test1();
        t.test2();
    };

    "rbegin / rend"_test = [] {
        class test
        {
            bsl::dynarray<int> da{new int[1], 1};

        public:
            auto
            test1() -> void
            {
                for (auto it = da.rbegin(); it != da.rend(); ++it) {
                    *it = 42;
                }
            }

            auto
            test2() const -> void
            {
                for (auto it = da.rbegin(); it != da.rend(); ++it) {
                    expect(*it == 42);
                }

                for (auto it = da.crbegin(); it != da.crend(); ++it) {
                    expect(*it == 42);
                }
            }
        };

        test t;
        t.test1();
        t.test2();
    };

    "empty"_test = [] {
        auto da1 = bsl::dynarray<int>();
        auto da2 = bsl::dynarray<int>(new int[1], 1);

        expect(da1.empty());
        expect(!da2.empty());
    };

    "size"_test = [] {
        auto da1 = bsl::dynarray<int>();
        auto da2 = bsl::dynarray<int>(new int[1], 1);

        expect(da1.size() == 0);    // NOLINT
        expect(da2.size() == 1);
    };

    "ssize"_test = [] {
        auto da1 = bsl::dynarray<int>();
        auto da2 = bsl::dynarray<int>(new int[1], 1);

        expect(da1.ssize() == 0);
        expect(da2.ssize() == 1);
    };

    "size_bytes"_test = [] {
        auto da1 = bsl::dynarray<int>();
        auto da2 = bsl::dynarray<int>(new int[1], 1);

        expect(da1.size_bytes() == 0);
        expect(da2.size_bytes() == sizeof(int));
    };

    "max_size"_test = [] {
        auto da1 = bsl::dynarray<int>();
        auto da2 = bsl::dynarray<int>(new int[1], 1);

        expect(da1.max_size() != 0);
        expect(da2.max_size() != 0);
    };

    "fill"_test = [] {
        auto da = bsl::dynarray<int>(new int[1], 1);

        da.fill(23);
        expect(da.front() == 23);

        da.fill(42);
        expect(da.front() == 42);
    };

    "comparison operators"_test = [] {
        auto da1 = bsl::dynarray<int>(new int[1], 1);
        auto da2 = bsl::dynarray<int>(new int[1], 1);
        auto da3 = bsl::dynarray<int>(new int[1], 1);
        auto da4 = bsl::dynarray<int>(new int[2], 2);
        auto da5 = bsl::dynarray<int>(new int[2], 2);
        auto da6 = bsl::dynarray<int>(new int[2], 2);

        da1.at(0) = 23;
        da2.at(0) = 23;
        da3.at(0) = 42;
        da4.at(0) = 42;
        da4.at(1) = 42;
        da5.at(0) = 42;
        da5.at(1) = 42;
        da6.at(0) = 23;
        da6.at(1) = 42;

        expect(da1 == da2);
        expect(da2 != da3);
        expect(da3 != da4);
        expect(da4 == da5);
        expect(da5 != da6);
    };

    "ostream"_test = [] {
        auto da1 = bsl::dynarray<int>();
        auto da2 = bsl::dynarray<int>(new int[1], 1);

        std::cout << "testing os: " << da1 << '\n';
        std::cout << "testing os: " << da2 << '\n';
    };

    "make_dynarray"_test = [] {
        expect(throws([&] {
            bsl::make_dynarray<int>(0);
        }));
        expect(throws([&] {
            bsl::make_dynarray_default_init<int>(0);
        }));

        auto da1 = bsl::make_dynarray<int>(1);
        auto da2 = bsl::make_dynarray_default_init<int>(1);

        expect(da1.size() == 1);
        expect(da2.size() == 1);
    };
}
