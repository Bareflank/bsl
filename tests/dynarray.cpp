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

#include <set>
#include <catch2/catch.hpp>

// --------------------------------------------------------------------------
// Mocks
// --------------------------------------------------------------------------

struct Foo
{
    Foo()
    {
        s_con++;
        s_list.insert(this);
    }

    Foo(const Foo &f)
    {
        (void)f;

        s_cop++;
        s_con++;
        s_list.insert(this);
    }

    Foo &
    operator=(const Foo &f)
    {
        (void)f;

        s_cop++;
        s_list.insert(this);
        return *this;
    }

    Foo(Foo &&f) noexcept
    {
        (void)f;

        s_mov++;
        s_con++;
        s_list.insert(this);
    }

    Foo &
    operator=(Foo &&f) noexcept
    {
        (void)f;

        s_mov++;
        s_list.insert(this);
        return *this;
    }

    ~Foo()
    {
        s_des++;
        s_list.erase(this);
    }

    static auto
    dump() -> void
    {
        std::cout << "Foo::check failed\n";
        std::cout << "  - constructed: " << s_con << '\n';
        std::cout << "  - copied: " << s_cop << '\n';
        std::cout << "  - moved: " << s_mov << '\n';
        std::cout << "  - destructed: " << s_des << '\n';
    }

    static auto
    check(int con, int cop, int mov, int des) -> bool
    {
        if (s_con == con && s_cop == cop && s_mov == mov && s_des == des) {
            return s_list.empty();
        }

        dump();
        return false;
    }

    static auto
    reset()
    {
        s_con = 0;
        s_cop = 0;
        s_mov = 0;
        s_des = 0;
    }

    static int s_con;
    static int s_cop;
    static int s_mov;
    static int s_des;

    static std::set<Foo *> s_list;
};

int Foo::s_con{};
int Foo::s_cop{};
int Foo::s_mov{};
int Foo::s_des{};
std::set<Foo *> Foo::s_list{};

#define CHECK_FOO(a, b, c, d) CHECK(Foo::check(a, b, c, d))

struct Deleter
{
    auto
    operator()(Foo *ptr, size_t size) const -> void
    {
        (void)size;
        delete[] ptr;
    };

    Deleter()
    {
        s_con++;
        s_list.insert(this);
    }

    Deleter(const Deleter &d)
    {
        (void)d;

        s_cop++;
        s_con++;
        s_list.insert(this);
    }

    Deleter &
    operator=(const Deleter &d)
    {
        (void)d;

        s_cop++;
        s_list.insert(this);
        return *this;
    }

    Deleter(Deleter &&d) noexcept
    {
        (void)d;

        s_mov++;
        s_con++;
        s_list.insert(this);
    }

    Deleter &
    operator=(Deleter &&d) noexcept
    {
        (void)d;

        s_mov++;
        s_list.insert(this);
        return *this;
    }

    ~Deleter()
    {
        s_des++;
        s_list.erase(this);
    }

    static auto
    dump() -> void
    {
        std::cout << "Deleter::check failed\n";
        std::cout << "  - constructed: " << s_con << '\n';
        std::cout << "  - copied: " << s_cop << '\n';
        std::cout << "  - moved: " << s_mov << '\n';
        std::cout << "  - destructed: " << s_des << '\n';
    }

    static auto
    check(int con, int cop, int mov, int des) -> bool
    {
        if (s_con == con && s_cop == cop && s_mov == mov && s_des == des) {
            return s_list.empty();
        }

        dump();
        return false;
    }

    static auto
    reset()
    {
        s_con = 0;
        s_cop = 0;
        s_mov = 0;
        s_des = 0;
    }

    static int s_con;
    static int s_cop;
    static int s_mov;
    static int s_des;

    static std::set<Deleter *> s_list;
};

int Deleter::s_con{};
int Deleter::s_cop{};
int Deleter::s_mov{};
int Deleter::s_des{};
std::set<Deleter *> Deleter::s_list{};

#define CHECK_DELETER(a, b, c, d) CHECK(Deleter::check(a, b, c, d))

auto
setup_test() -> void
{
    Foo::reset();
    Deleter::reset();
}

using da_t = bsl::dynarray<Foo, Deleter>;

constexpr const auto INT_23 = 23;
constexpr const auto INT_42 = 42;

// --------------------------------------------------------------------------
// Tests
// --------------------------------------------------------------------------

TEST_CASE("check tests")
{
    CHECK_FALSE(Foo::check(1, 1, 1, 1));
    CHECK_FALSE(Deleter::check(1, 1, 1, 1));
}

TEST_CASE("const / non-const")
{
    bsl::dynarray<int> da1;
    bsl::dynarray<const int> da2;
}

TEST_CASE("empty base optimization")
{
    CHECK(sizeof(da_t) == sizeof(void *) * 2);
}

TEST_CASE("nodelete")
{
    auto f = new Foo[1];
    CHECK_NOTHROW(bsl::dynarray<Foo, bsl::nodelete>(f, 1));

    delete[] f;
}

TEST_CASE("constructor")
{
    {
        setup_test();

        da_t da1;
        da_t da2 = {};

        CHECK(da1.empty());
        CHECK(da2.empty());
    }
    CHECK_FOO(0, 0, 0, 0);
    CHECK_DELETER(2, 0, 0, 2);

    {
        setup_test();
        auto f = new Foo[1];

        CHECK_THROWS(da_t(nullptr, 1));
        CHECK_THROWS(da_t(f, 0));
        CHECK_NOTHROW(da_t(new Foo[1], 1));

        delete[] f;
    }
    CHECK_FOO(2, 0, 0, 2);
    CHECK_DELETER(3, 0, 0, 3);

    {
        setup_test();
        auto f = new Foo[1];
        auto d = Deleter();

        CHECK_THROWS(da_t(nullptr, 1, d));
        CHECK_THROWS(da_t(f, 0, d));
        CHECK_NOTHROW(da_t(new Foo[1], 1, d));

        delete[] f;
    }
    CHECK_FOO(2, 0, 0, 2);
    CHECK_DELETER(4, 3, 0, 4);

    {
        setup_test();
        auto f = new Foo[1];

        CHECK_THROWS(da_t(nullptr, 1, Deleter()));
        CHECK_THROWS(da_t(f, 0, Deleter()));
        CHECK_NOTHROW(da_t(new Foo[1], 1, Deleter()));

        delete[] f;
    }
    CHECK_FOO(2, 0, 0, 2);
    CHECK_DELETER(6, 0, 3, 6);

    {
        setup_test();

        auto da1 = da_t(new Foo[1], 1);
        CHECK(da1);

        auto da2 = da_t(std::move(da1));
        CHECK(da2);
    }
    CHECK_FOO(1, 0, 0, 1);
    CHECK_DELETER(2, 0, 1, 2);
}

TEST_CASE("operator=")
{
    {
        setup_test();

        auto da1 = da_t(new Foo[1], 1);
        da1 = std::move(da1);
    }
    CHECK_FOO(1, 0, 0, 1);
    CHECK_DELETER(1, 0, 0, 1);

    {
        setup_test();

        auto da1 = da_t(new Foo[1], 1);
        CHECK(da1);

        auto da2 = da_t();
        CHECK(da2.empty());

        da1 = std::move(da2);
        CHECK(da1.empty());
    }
    CHECK_FOO(1, 0, 0, 1);
    CHECK_DELETER(2, 0, 1, 2);

    {
        setup_test();

        auto da1 = da_t(new Foo[1], 1);
        CHECK(da1);

        auto da2 = da_t(new Foo[1], 1);
        CHECK(da2);

        da1 = std::move(da2);
        CHECK(da1);
    }
    CHECK_FOO(2, 0, 0, 2);
    CHECK_DELETER(2, 0, 1, 2);
}

TEST_CASE("reset and release")
{
    {
        setup_test();

        auto da1 = da_t();
        da1.reset();

        CHECK_FOO(0, 0, 0, 0);
    }
    CHECK_DELETER(1, 0, 0, 1);

    {
        setup_test();

        auto da1 = da_t(new Foo[1], 1);
        da1.reset();

        CHECK_FOO(1, 0, 0, 1);
    }
    CHECK_DELETER(1, 0, 0, 1);

    {
        setup_test();

        auto da1 = da_t(new Foo[1], 1);
        da1.reset(nullptr);

        CHECK_FOO(1, 0, 0, 1);
    }
    CHECK_DELETER(1, 0, 0, 1);

    {
        setup_test();

        auto da1 = da_t(new Foo[1], 1);
        auto da2 = da_t(new Foo[1], 1);
        da1.reset(da2.release());

        CHECK(!da1.empty());
        CHECK(da2.empty());
    }
    CHECK_FOO(2, 0, 0, 2);
    CHECK_DELETER(2, 0, 0, 2);
}

TEST_CASE("swap")
{
    bsl::dynarray<int> da1{new int[1], 1};
    bsl::dynarray<int> da2{new int[2], 2};

    da1.front() = INT_23;
    da2.front() = INT_42;

    CHECK(da1.front() == INT_23);
    CHECK(da1.size() == 1);
    CHECK(da2.front() == INT_42);
    CHECK(da2.size() == 2);

    da1.swap(da2);

    CHECK(da1.front() == INT_42);
    CHECK(da1.size() == 2);
    CHECK(da2.front() == INT_23);
    CHECK(da2.size() == 1);

    da1.swap(da2);

    CHECK(da1.front() == INT_23);
    CHECK(da1.size() == 1);
    CHECK(da2.front() == INT_42);
    CHECK(da2.size() == 2);
}

TEST_CASE("get")
{
    auto f = new int[1];

    bsl::dynarray<int> da1;
    bsl::dynarray<int> da2{f, 1};

    CHECK(da1.get() == nullptr);
    CHECK(da2.get() == f);
}

TEST_CASE("get_deleter")
{
    class test
    {
        bsl::dynarray<int> da;

    public:
        auto
        test1() -> void
        {
            CHECK_NOTHROW(da.get_deleter());
        }

        auto
        test2() const -> void
        {
            CHECK_NOTHROW(da.get_deleter());
        }
    };

    test t;
    t.test1();
    t.test2();
}

TEST_CASE("bool operator")
{
    bsl::dynarray<int> da1;
    bsl::dynarray<int> da2{new int[1], 1};

    CHECK(!da1);
    CHECK(da2);
}

TEST_CASE("operator[]")
{
    class test
    {
        bsl::dynarray<int> da1;
        bsl::dynarray<int> da2{new int[1], 1};

    public:
        auto
        test1() -> void
        {
            da2[0] = INT_23;
            CHECK(da2[0] == INT_23);
            da2[0] = INT_42;
            CHECK(da2[0] == INT_42);
            CHECK_THROWS(da1[0]);
            CHECK_THROWS(da2[42]);
        }

        auto
        test2() const -> void
        {
            CHECK(da2[0] == INT_42);
            CHECK_THROWS(da1[0]);
            CHECK_THROWS(da2[42]);
        }
    };

    test t;
    t.test1();
    t.test2();
}

TEST_CASE("at")
{
    class test
    {
        bsl::dynarray<int> da1;
        bsl::dynarray<int> da2{new int[1], 1};

    public:
        auto
        test1() -> void
        {
            da2.at(0) = INT_23;
            CHECK(da2.at(0) == INT_23);
            da2.at(0) = INT_42;
            CHECK(da2.at(0) == INT_42);
            CHECK_THROWS(da1.at(0));
            CHECK_THROWS(da2.at(42));
        }

        auto
        test2() const -> void
        {
            CHECK(da2.at(0) == INT_42);
            CHECK_THROWS(da1.at(0));
            CHECK_THROWS(da2.at(42));
        }
    };

    test t;
    t.test1();
    t.test2();
}

TEST_CASE("front")
{
    class test
    {
        bsl::dynarray<int> da1;
        bsl::dynarray<int> da2{new int[1], 1};

    public:
        auto
        test1() -> void
        {
            da2.front() = INT_23;
            CHECK(da2.front() == INT_23);
            da2.front() = INT_42;
            CHECK(da2.front() == INT_42);
            CHECK_THROWS(da1.front());
            CHECK_NOTHROW(da2.front());
        }

        auto
        test2() const -> void
        {
            CHECK(da2.front() == INT_42);
            CHECK_THROWS(da1.front());
            CHECK_NOTHROW(da2.front());
        }
    };

    test t;
    t.test1();
    t.test2();
}

TEST_CASE("back")
{
    class test
    {
        bsl::dynarray<int> da1;
        bsl::dynarray<int> da2{new int[1], 1};

    public:
        auto
        test1() -> void
        {
            da2.back() = INT_23;
            CHECK(da2.back() == INT_23);
            da2.back() = INT_42;
            CHECK(da2.back() == INT_42);
            CHECK_THROWS(da1.back());
            CHECK_NOTHROW(da2.back());
        }

        auto
        test2() const -> void
        {
            CHECK(da2.back() == INT_42);
            CHECK_THROWS(da1.back());
            CHECK_NOTHROW(da2.back());
        }
    };

    test t;
    t.test1();
    t.test2();
}

TEST_CASE("data")
{
    class test
    {
        bsl::dynarray<int> da1;
        bsl::dynarray<int> da2{new int[1], 1};

    public:
        auto
        test1() -> void
        {
            da2.data()[0] = INT_23;
            CHECK(da2.data()[0] == INT_23);
            da2.data()[0] = INT_42;
            CHECK(da2.data()[0] == INT_42);
        }

        auto
        test2() const -> void
        {
            CHECK(da2.data()[0] == INT_42);
        }
    };

    test t;
    t.test1();
    t.test2();
}

TEST_CASE("begin / end")
{
    class test
    {
        bsl::dynarray<int> da{new int[1], 1};

    public:
        auto
        test1() -> void
        {
            for (auto it = da.begin(); it != da.end(); ++it) {
                *it = INT_42;
            }
        }

        auto
        test2() const -> void
        {
            for (auto it = da.begin(); it != da.end(); ++it) {
                CHECK(*it == INT_42);
            }

            for (auto it = da.cbegin(); it != da.cend(); ++it) {
                CHECK(*it == INT_42);
            }
        }
    };

    test t;
    t.test1();
    t.test2();
}

TEST_CASE("rbegin / rend")
{
    class test
    {
        bsl::dynarray<int> da{new int[1], 1};

    public:
        auto
        test1() -> void
        {
            for (auto it = da.rbegin(); it != da.rend(); ++it) {
                *it = INT_42;
            }
        }

        auto
        test2() const -> void
        {
            for (auto it = da.rbegin(); it != da.rend(); ++it) {
                CHECK(*it == INT_42);
            }

            for (auto it = da.crbegin(); it != da.crend(); ++it) {
                CHECK(*it == INT_42);
            }
        }
    };

    test t;
    t.test1();
    t.test2();
}

TEST_CASE("empty")
{
    bsl::dynarray<int> da1;
    bsl::dynarray<int> da2{new int[1], 1};

    CHECK(da1.empty());
    CHECK(!da2.empty());
}

TEST_CASE("size")
{
    bsl::dynarray<int> da1;
    bsl::dynarray<int> da2{new int[1], 1};

    CHECK(da1.size() == 0);    // NOLINT
    CHECK(da2.size() == 1);
}

TEST_CASE("ssize")
{
    bsl::dynarray<int> da1;
    bsl::dynarray<int> da2{new int[1], 1};

    CHECK(da1.ssize() == 0);
    CHECK(da2.ssize() == 1);
}

TEST_CASE("size_bytes")
{
    bsl::dynarray<int> da1;
    bsl::dynarray<int> da2{new int[1], 1};

    CHECK(da1.size_bytes() == 0);
    CHECK(da2.size_bytes() == sizeof(int));
}

TEST_CASE("max_size")
{
    bsl::dynarray<int> da1;
    bsl::dynarray<int> da2{new int[1], 1};

    CHECK(
        da1.max_size() == std::numeric_limits<ptrdiff_t>::max() / sizeof(int));
    CHECK(
        da2.max_size() == std::numeric_limits<ptrdiff_t>::max() / sizeof(int));
}

TEST_CASE("fill")
{
    bsl::dynarray<int> da{new int[1], 1};

    da.fill(INT_23);
    CHECK(da.front() == INT_23);

    da.fill(INT_42);
    CHECK(da.front() == INT_42);
}

TEST_CASE("comparison operators")
{
    bsl::dynarray<int> da1{new int[1], 1};
    bsl::dynarray<int> da2{new int[1], 1};
    bsl::dynarray<int> da3{new int[1], 1};
    bsl::dynarray<int> da4{new int[2], 2};
    bsl::dynarray<int> da5{new int[2], 2};

    da1.at(0) = INT_23;
    da2.at(0) = INT_23;
    da3.at(0) = INT_42;
    da4.at(0) = INT_42;
    da4.at(1) = INT_42;
    da5.at(0) = INT_42;
    da5.at(1) = INT_42;

    CHECK((da1 == da2));
    CHECK((da2 != da3));
    CHECK((da3 != da4));
    CHECK((da4 == da5));
}

TEST_CASE("ostream")
{
    bsl::dynarray<Foo, Deleter> da2;
    bsl::dynarray<int> da1{new int[1], 1};

    std::cout << "testing os: " << da1 << '\n';
    std::cout << "testing os: " << da2 << '\n';
}

TEST_CASE("make_dynarray")
{
    {
        CHECK_THROWS(bsl::make_dynarray<Foo>(0));
        CHECK_THROWS(bsl::make_dynarray_default_init<Foo>(0));
    }

    {
        setup_test();

        auto da = bsl::make_dynarray<Foo>(1);
        CHECK(da.size() == 1);
    }
    CHECK_FOO(1, 0, 0, 1);

    {
        setup_test();

        auto da = bsl::make_dynarray_default_init<Foo>(1);
        CHECK(da.size() == 1);
    }
    CHECK_FOO(1, 0, 0, 1);
}
