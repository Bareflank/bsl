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
    struct Foo
    {
        int m_data;
    };

    "iterator concept checks"_test = [] {
        using it_t = bsl::dynarray<int>::iterator;

        static_assert(std::is_default_constructible_v<it_t>);
        static_assert(std::is_destructible_v<it_t>);
        static_assert(std::is_copy_constructible_v<it_t>);
        static_assert(std::is_copy_assignable_v<it_t>);
        static_assert(std::is_move_constructible_v<it_t>);
        static_assert(std::is_move_assignable_v<it_t>);
        static_assert(std::is_swappable_v<it_t>);
    };

    "constructors"_test = [] {
        {
            bsl::dynarray<int>::iterator it;
            expect(throws([&] {
                *it;
            }));
        }

        {
            auto da = bsl::make_dynarray<int>(1);
            auto it = da.begin();
            expect(nothrow([&] {
                *it;
            }));
        }
    };

    "operator*"_test = [] {
        class test
        {
            bsl::dynarray<Foo> da1;
            bsl::dynarray<Foo> da2;

        public:
            test() : da2{bsl::make_dynarray<Foo>(1)} {}

            auto
            test1() -> void
            {
                auto it1 = da1.begin();
                auto it2 = da2.begin();

                expect(throws([&] {
                    (*it1).m_data = 42;
                }));
                expect(nothrow([&] {
                    (*it2).m_data = 42;
                }));
            }

            auto
            test2() const -> void
            {
                auto it = da2.begin();
                expect((*it).m_data == 42);
            }
        };

        test t;
        t.test1();
        t.test2();
    };

    "operator->"_test = [] {
        class test
        {
            bsl::dynarray<Foo> da1;
            bsl::dynarray<Foo> da2;

        public:
            test() : da2{bsl::make_dynarray<Foo>(1)} {}

            auto
            test1() -> void
            {
                auto it1 = da1.begin();
                auto it2 = da2.begin();

                expect(throws([&] {
                    it1->m_data = 42;
                }));
                expect(nothrow([&] {
                    it2->m_data = 42;
                }));
            }

            auto
            test2() const -> void
            {
                auto it = da2.begin();
                expect(it->m_data == 42);
            }
        };

        test t;
        t.test1();
        t.test2();
    };

    "operator[]"_test = [] {
        class test
        {
            bsl::dynarray<Foo> da1;
            bsl::dynarray<Foo> da2;

        public:
            test() : da2{bsl::make_dynarray<Foo>(1)} {}

            auto
            test1() -> void
            {
                auto it1 = da1.begin();
                auto it2 = da2.begin();

                expect(throws([&] {
                    it1[0].m_data = 42;
                }));
                expect(nothrow([&] {
                    it2[0].m_data = 42;
                }));
            }

            auto
            test2() const -> void
            {
                auto it = da2.begin();
                expect(it[0].m_data == 42);
            }
        };

        test t;
        t.test1();
        t.test2();
    };

    "operator++"_test = [] {
        class test
        {
            bsl::dynarray<Foo> da1;
            bsl::dynarray<Foo> da2;

        public:
            test() :
                da1{bsl::make_dynarray<Foo>(1)}, da2{bsl::make_dynarray<Foo>(2)}
            {}

            auto
            test1() -> void
            {
                auto it1 = da1.begin();
                auto it2 = da2.begin();

                ++it1;
                ++it2;

                expect(throws([&] {
                    (*it1).m_data;
                }));
                expect(throws([&] {
                    it1->m_data;
                }));
                expect(throws([&] {
                    it1[1].m_data;
                }));

                expect(nothrow([&] {
                    (*it2).m_data;
                }));
                expect(nothrow([&] {
                    it2->m_data;
                }));
                expect(nothrow([&] {
                    it2[1].m_data;
                }));

                ++it1;
                ++it2;

                expect(throws([&] {
                    (*it1).m_data;
                }));
                expect(throws([&] {
                    it1->m_data;
                }));
                expect(throws([&] {
                    it1[2].m_data;
                }));

                expect(throws([&] {
                    (*it2).m_data;
                }));
                expect(throws([&] {
                    it2->m_data;
                }));
                expect(throws([&] {
                    it2[2].m_data;
                }));
            }

            auto
            test2() const -> void
            {
                auto it1 = da1.begin();
                auto it2 = da2.begin();

                ++it1;
                ++it2;

                expect(throws([&] {
                    (*it1).m_data;
                }));
                expect(throws([&] {
                    it1->m_data;
                }));
                expect(throws([&] {
                    it1[1].m_data;
                }));

                expect(nothrow([&] {
                    (*it2).m_data;
                }));
                expect(nothrow([&] {
                    it2->m_data;
                }));
                expect(nothrow([&] {
                    it2[1].m_data;
                }));

                ++it1;
                ++it2;

                expect(throws([&] {
                    (*it1).m_data;
                }));
                expect(throws([&] {
                    it1->m_data;
                }));
                expect(throws([&] {
                    it1[2].m_data;
                }));

                expect(throws([&] {
                    (*it2).m_data;
                }));
                expect(throws([&] {
                    it2->m_data;
                }));
                expect(throws([&] {
                    it2[2].m_data;
                }));
            }
        };

        test t;
        t.test1();
        t.test2();
    };

    "operator++(int)"_test = [] {
        class test
        {
            bsl::dynarray<Foo> da1;
            bsl::dynarray<Foo> da2;

        public:
            test() :
                da1{bsl::make_dynarray<Foo>(1)}, da2{bsl::make_dynarray<Foo>(2)}
            {}

            auto
            test1() -> void
            {
                auto it1 = da1.begin();
                auto it2 = da2.begin();

                it1++;
                it2++;

                expect(throws([&] {
                    (*it1).m_data;
                }));
                expect(throws([&] {
                    it1->m_data;
                }));
                expect(throws([&] {
                    it1[1].m_data;
                }));

                expect(nothrow([&] {
                    (*it2).m_data;
                }));
                expect(nothrow([&] {
                    it2->m_data;
                }));
                expect(nothrow([&] {
                    it2[1].m_data;
                }));

                it1++;
                it2++;

                expect(throws([&] {
                    (*it1).m_data;
                }));
                expect(throws([&] {
                    it1->m_data;
                }));
                expect(throws([&] {
                    it1[2].m_data;
                }));

                expect(throws([&] {
                    (*it2).m_data;
                }));
                expect(throws([&] {
                    it2->m_data;
                }));
                expect(throws([&] {
                    it2[2].m_data;
                }));
            }

            auto
            test2() const -> void
            {
                auto it1 = da1.begin();
                auto it2 = da2.begin();

                it1++;
                it2++;

                expect(throws([&] {
                    (*it1).m_data;
                }));
                expect(throws([&] {
                    it1->m_data;
                }));
                expect(throws([&] {
                    it1[1].m_data;
                }));

                expect(nothrow([&] {
                    (*it2).m_data;
                }));
                expect(nothrow([&] {
                    it2->m_data;
                }));
                expect(nothrow([&] {
                    it2[1].m_data;
                }));

                it1++;
                it2++;

                expect(throws([&] {
                    (*it1).m_data;
                }));
                expect(throws([&] {
                    it1->m_data;
                }));
                expect(throws([&] {
                    it1[2].m_data;
                }));

                expect(throws([&] {
                    (*it2).m_data;
                }));
                expect(throws([&] {
                    it2->m_data;
                }));
                expect(throws([&] {
                    it2[2].m_data;
                }));
            }
        };

        test t;
        t.test1();
        t.test2();
    };

    "operator--"_test = [] {
        class test
        {
            bsl::dynarray<Foo> da1;
            bsl::dynarray<Foo> da2;

        public:
            test() :
                da1{bsl::make_dynarray<Foo>(1)}, da2{bsl::make_dynarray<Foo>(2)}
            {}

            auto
            test1() -> void
            {
                auto it1 = da1.end();
                auto it2 = da2.end();

                --it1;
                --it2;

                expect(nothrow([&] {
                    (*it1).m_data;
                }));
                expect(nothrow([&] {
                    it1->m_data;
                }));
                expect(nothrow([&] {
                    it1[0].m_data;
                }));

                expect(nothrow([&] {
                    (*it2).m_data;
                }));
                expect(nothrow([&] {
                    it2->m_data;
                }));
                expect(nothrow([&] {
                    it2[1].m_data;
                }));

                --it1;
                --it2;

                expect(throws([&] {
                    (*it1).m_data;
                }));
                expect(throws([&] {
                    it1->m_data;
                }));
                expect(throws([&] {
                    it1[-1].m_data;
                }));

                expect(nothrow([&] {
                    (*it2).m_data;
                }));
                expect(nothrow([&] {
                    it2->m_data;
                }));
                expect(nothrow([&] {
                    it2[0].m_data;
                }));
            }

            auto
            test2() const -> void
            {
                auto it1 = da1.end();
                auto it2 = da2.end();

                --it1;
                --it2;

                expect(nothrow([&] {
                    (*it1).m_data;
                }));
                expect(nothrow([&] {
                    it1->m_data;
                }));
                expect(nothrow([&] {
                    it1[0].m_data;
                }));

                expect(nothrow([&] {
                    (*it2).m_data;
                }));
                expect(nothrow([&] {
                    it2->m_data;
                }));
                expect(nothrow([&] {
                    it2[1].m_data;
                }));

                --it1;
                --it2;

                expect(throws([&] {
                    (*it1).m_data;
                }));
                expect(throws([&] {
                    it1->m_data;
                }));
                expect(throws([&] {
                    it1[-1].m_data;
                }));

                expect(nothrow([&] {
                    (*it2).m_data;
                }));
                expect(nothrow([&] {
                    it2->m_data;
                }));
                expect(nothrow([&] {
                    it2[0].m_data;
                }));
            }
        };

        test t;
        t.test1();
        t.test2();
    };

    "operator--(int)"_test = [] {
        class test
        {
            bsl::dynarray<Foo> da1;
            bsl::dynarray<Foo> da2;

        public:
            test() :
                da1{bsl::make_dynarray<Foo>(1)}, da2{bsl::make_dynarray<Foo>(2)}
            {}

            auto
            test1() -> void
            {
                auto it1 = da1.end();
                auto it2 = da2.end();

                it1--;
                it2--;

                expect(nothrow([&] {
                    (*it1).m_data;
                }));
                expect(nothrow([&] {
                    it1->m_data;
                }));
                expect(nothrow([&] {
                    it1[0].m_data;
                }));

                expect(nothrow([&] {
                    (*it2).m_data;
                }));
                expect(nothrow([&] {
                    it2->m_data;
                }));
                expect(nothrow([&] {
                    it2[1].m_data;
                }));

                it1--;
                it2--;

                expect(throws([&] {
                    (*it1).m_data;
                }));
                expect(throws([&] {
                    it1->m_data;
                }));
                expect(throws([&] {
                    it1[-1].m_data;
                }));

                expect(nothrow([&] {
                    (*it2).m_data;
                }));
                expect(nothrow([&] {
                    it2->m_data;
                }));
                expect(nothrow([&] {
                    it2[0].m_data;
                }));
            }

            auto
            test2() const -> void
            {
                auto it1 = da1.end();
                auto it2 = da2.end();

                it1--;
                it2--;

                expect(nothrow([&] {
                    (*it1).m_data;
                }));
                expect(nothrow([&] {
                    it1->m_data;
                }));
                expect(nothrow([&] {
                    it1[0].m_data;
                }));

                expect(nothrow([&] {
                    (*it2).m_data;
                }));
                expect(nothrow([&] {
                    it2->m_data;
                }));
                expect(nothrow([&] {
                    it2[1].m_data;
                }));

                it1--;
                it2--;

                expect(throws([&] {
                    (*it1).m_data;
                }));
                expect(throws([&] {
                    it1->m_data;
                }));
                expect(throws([&] {
                    it1[-1].m_data;
                }));

                expect(nothrow([&] {
                    (*it2).m_data;
                }));
                expect(nothrow([&] {
                    it2->m_data;
                }));
                expect(nothrow([&] {
                    it2[0].m_data;
                }));
            }
        };

        test t;
        t.test1();
        t.test2();
    };

    "operator+ n"_test = [] {
        class test
        {
            bsl::dynarray<Foo> da1;
            bsl::dynarray<Foo> da2;

        public:
            test() : da2{bsl::make_dynarray<Foo>(1)} {}

            auto
            test1() -> void
            {
                auto it1 = da1.begin();
                auto it2 = da2.begin();

                auto it3 = it1 + 1;
                auto it4 = it2 + 1;

                expect(throws([&] {
                    (*it1).m_data;
                }));
                expect(throws([&] {
                    it1->m_data;
                }));
                expect(throws([&] {
                    it1[0].m_data;
                }));

                expect(nothrow([&] {
                    (*it2).m_data;
                }));
                expect(nothrow([&] {
                    it2->m_data;
                }));
                expect(nothrow([&] {
                    it2[0].m_data;
                }));

                expect(throws([&] {
                    (*it3).m_data;
                }));
                expect(throws([&] {
                    it3->m_data;
                }));
                expect(throws([&] {
                    it3[1].m_data;
                }));

                expect(throws([&] {
                    (*it4).m_data;
                }));
                expect(throws([&] {
                    it4->m_data;
                }));
                expect(throws([&] {
                    it4[1].m_data;
                }));
            }

            auto
            test2() const -> void
            {
                auto it1 = da1.begin();
                auto it2 = da2.begin();

                auto it3 = it1 + 1;
                auto it4 = it2 + 1;

                expect(throws([&] {
                    (*it1).m_data;
                }));
                expect(throws([&] {
                    it1->m_data;
                }));
                expect(throws([&] {
                    it1[0].m_data;
                }));

                expect(nothrow([&] {
                    (*it2).m_data;
                }));
                expect(nothrow([&] {
                    it2->m_data;
                }));
                expect(nothrow([&] {
                    it2[0].m_data;
                }));

                expect(throws([&] {
                    (*it3).m_data;
                }));
                expect(throws([&] {
                    it3->m_data;
                }));
                expect(throws([&] {
                    it3[1].m_data;
                }));

                expect(throws([&] {
                    (*it4).m_data;
                }));
                expect(throws([&] {
                    it4->m_data;
                }));
                expect(throws([&] {
                    it4[1].m_data;
                }));
            }
        };

        test t;
        t.test1();
        t.test2();
    };

    "operator- n"_test = [] {
        class test
        {
            bsl::dynarray<Foo> da1;
            bsl::dynarray<Foo> da2;

        public:
            test() : da2{bsl::make_dynarray<Foo>(1)} {}

            auto
            test1() -> void
            {
                auto it1 = da1.end();
                auto it2 = da2.end();

                auto it3 = it1 - 1;
                auto it4 = it2 - 1;

                expect(throws([&] {
                    (*it1).m_data;
                }));
                expect(throws([&] {
                    it1->m_data;
                }));
                expect(throws([&] {
                    it1[0].m_data;
                }));

                expect(throws([&] {
                    (*it2).m_data;
                }));
                expect(throws([&] {
                    it2->m_data;
                }));
                expect(throws([&] {
                    it2[1].m_data;
                }));

                expect(throws([&] {
                    (*it3).m_data;
                }));
                expect(throws([&] {
                    it3->m_data;
                }));
                expect(throws([&] {
                    it3[-1].m_data;
                }));

                expect(nothrow([&] {
                    (*it4).m_data;
                }));
                expect(nothrow([&] {
                    it4->m_data;
                }));
                expect(nothrow([&] {
                    it4[0].m_data;
                }));
            }

            auto
            test2() const -> void
            {
                auto it1 = da1.end();
                auto it2 = da2.end();

                auto it3 = it1 - 1;
                auto it4 = it2 - 1;

                expect(throws([&] {
                    (*it1).m_data;
                }));
                expect(throws([&] {
                    it1->m_data;
                }));
                expect(throws([&] {
                    it1[0].m_data;
                }));

                expect(throws([&] {
                    (*it2).m_data;
                }));
                expect(throws([&] {
                    it2->m_data;
                }));
                expect(throws([&] {
                    it2[1].m_data;
                }));

                expect(throws([&] {
                    (*it3).m_data;
                }));
                expect(throws([&] {
                    it3->m_data;
                }));
                expect(throws([&] {
                    it3[-1].m_data;
                }));

                expect(nothrow([&] {
                    (*it4).m_data;
                }));
                expect(nothrow([&] {
                    it4->m_data;
                }));
                expect(nothrow([&] {
                    it4[0].m_data;
                }));
            }
        };

        test t;
        t.test1();
        t.test2();
    };

    "operator+= n"_test = [] {
        class test
        {
            bsl::dynarray<Foo> da1;
            bsl::dynarray<Foo> da2;

        public:
            test() : da2{bsl::make_dynarray<Foo>(1)} {}

            auto
            test1() -> void
            {
                auto it1 = da1.begin();
                auto it2 = da2.begin();

                expect(throws([&] {
                    (*it1).m_data;
                }));
                expect(throws([&] {
                    it1->m_data;
                }));
                expect(throws([&] {
                    it1[0].m_data;
                }));

                expect(nothrow([&] {
                    (*it2).m_data;
                }));
                expect(nothrow([&] {
                    it2->m_data;
                }));
                expect(nothrow([&] {
                    it2[0].m_data;
                }));

                it1 += 1;
                it2 += 1;

                expect(throws([&] {
                    (*it1).m_data;
                }));
                expect(throws([&] {
                    it1->m_data;
                }));
                expect(throws([&] {
                    it1[1].m_data;
                }));

                expect(throws([&] {
                    (*it2).m_data;
                }));
                expect(throws([&] {
                    it2->m_data;
                }));
                expect(throws([&] {
                    it2[1].m_data;
                }));
            }

            auto
            test2() const -> void
            {
                auto it1 = da1.begin();
                auto it2 = da2.begin();

                expect(throws([&] {
                    (*it1).m_data;
                }));
                expect(throws([&] {
                    it1->m_data;
                }));
                expect(throws([&] {
                    it1[0].m_data;
                }));

                expect(nothrow([&] {
                    (*it2).m_data;
                }));
                expect(nothrow([&] {
                    it2->m_data;
                }));
                expect(nothrow([&] {
                    it2[0].m_data;
                }));

                it1 += 1;
                it2 += 1;

                expect(throws([&] {
                    (*it1).m_data;
                }));
                expect(throws([&] {
                    it1->m_data;
                }));
                expect(throws([&] {
                    it1[1].m_data;
                }));

                expect(throws([&] {
                    (*it2).m_data;
                }));
                expect(throws([&] {
                    it2->m_data;
                }));
                expect(throws([&] {
                    it2[1].m_data;
                }));
            }
        };

        test t;
        t.test1();
        t.test2();
    };

    "operator-= n"_test = [] {
        class test
        {
            bsl::dynarray<Foo> da1;
            bsl::dynarray<Foo> da2;

        public:
            test() : da2{bsl::make_dynarray<Foo>(1)} {}

            auto
            test1() -> void
            {
                auto it1 = da1.end();
                auto it2 = da2.end();

                expect(throws([&] {
                    (*it1).m_data;
                }));
                expect(throws([&] {
                    it1->m_data;
                }));
                expect(throws([&] {
                    it1[0].m_data;
                }));

                expect(throws([&] {
                    (*it2).m_data;
                }));
                expect(throws([&] {
                    it2->m_data;
                }));
                expect(throws([&] {
                    it2[1].m_data;
                }));

                it1 -= 1;
                it2 -= 1;

                expect(throws([&] {
                    (*it1).m_data;
                }));
                expect(throws([&] {
                    it1->m_data;
                }));
                expect(throws([&] {
                    it1[-1].m_data;
                }));

                expect(nothrow([&] {
                    (*it2).m_data;
                }));
                expect(nothrow([&] {
                    it2->m_data;
                }));
                expect(nothrow([&] {
                    it2[0].m_data;
                }));
            }

            auto
            test2() const -> void
            {
                auto it1 = da1.end();
                auto it2 = da2.end();

                expect(throws([&] {
                    (*it1).m_data;
                }));
                expect(throws([&] {
                    it1->m_data;
                }));
                expect(throws([&] {
                    it1[0].m_data;
                }));

                expect(throws([&] {
                    (*it2).m_data;
                }));
                expect(throws([&] {
                    it2->m_data;
                }));
                expect(throws([&] {
                    it2[1].m_data;
                }));

                it1 -= 1;
                it2 -= 1;

                expect(throws([&] {
                    (*it1).m_data;
                }));
                expect(throws([&] {
                    it1->m_data;
                }));
                expect(throws([&] {
                    it1[-1].m_data;
                }));

                expect(nothrow([&] {
                    (*it2).m_data;
                }));
                expect(nothrow([&] {
                    it2->m_data;
                }));
                expect(nothrow([&] {
                    it2[0].m_data;
                }));
            }
        };

        test t;
        t.test1();
        t.test2();
    };

    "operator- rhs"_test = [] {
        class test
        {
            bsl::dynarray<Foo> da1;
            bsl::dynarray<Foo> da2;

        public:
            test() : da2{bsl::make_dynarray<Foo>(1)} {}

            auto
            test1() -> void
            {
                auto it1 = da1.end();
                auto it2 = da2.end();

                auto it3 = it1 - 1;
                auto it4 = it2 - 1;

                expect(it3 - it1 == -1);
                expect(it4 - it2 == -1);
            }

            auto
            test2() const -> void
            {
                auto it1 = da1.end();
                auto it2 = da2.end();

                auto it3 = it1 - 1;
                auto it4 = it2 - 1;

                expect(it3 - it1 == -1);
                expect(it4 - it2 == -1);
            }
        };

        test t;
        t.test1();
        t.test2();
    };

    "comparison operators"_test = [] {
        auto da = bsl::make_dynarray<int>(42);

        expect(da.begin() == da.begin());
        expect(da.end() == da.end());
        expect(da.begin() != da.end());
        expect(da.end() != da.begin());

        expect(da.end() > da.begin());
        expect(da.begin() < da.end());
        expect(da.end() >= da.begin());
        expect(da.begin() <= da.end());
    };
}
