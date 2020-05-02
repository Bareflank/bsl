/// @copyright
/// Copyright (C) 2020 Assured Information Security, Inc.
///
/// @copyright
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files (the "Software"), to deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions:
///
/// @copyright
/// The above copyright notice and this permission notice shall be included in
/// all copies or substantial portions of the Software.
///
/// @copyright
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
/// SOFTWARE.

#include <bsl/span.hpp>
#include <bsl/array.hpp>
#include <bsl/npos.hpp>
#include <bsl/ut.hpp>

namespace
{
    struct aggregate final
    {
        bsl::safe_int32 m_data;
    };

    constexpr bool
    operator==(aggregate const &lhs, aggregate const &rhs) noexcept
    {
        return lhs.m_data == rhs.m_data;
    }

    constexpr bsl::array<bsl::safe_int32, 6> test_arr{
        bsl::to_i32(4),
        bsl::to_i32(8),
        bsl::to_i32(15),
        bsl::to_i32(16),
        bsl::to_i32(23),
        bsl::to_i32(42)};

    constexpr bsl::array<bsl::safe_int32, 6> test_arr2{
        bsl::to_i32(4),
        bsl::to_i32(8),
        bsl::to_i32(15),
        bsl::to_i32(16),
        bsl::to_i32(0),
        bsl::to_i32(42)};

    constexpr bsl::array<aggregate, 6> test_aggregate_arr{
        bsl::to_i32(4),
        bsl::to_i32(8),
        bsl::to_i32(15),
        bsl::to_i32(16),
        bsl::to_i32(23),
        bsl::to_i32(42)};

    constexpr bsl::array<aggregate, 6> test_aggregate_arr2{
        bsl::to_i32(4),
        bsl::to_i32(8),
        bsl::to_i32(15),
        bsl::to_i32(16),
        bsl::to_i32(0),
        bsl::to_i32(42)};
}

/// <!-- description -->
///   @brief Used to execute the actual checks. We put the checks in this
///     function so that we can validate the tests both at compile-time
///     and at run-time. If a bsl::ut_check fails, the tests will either
///     fail fast at run-time, or will produce a compile-time error.
///
/// <!-- inputs/outputs -->
///   @return Always returns bsl::exit_success.
///
constexpr bsl::exit_code
tests() noexcept
{
    using namespace bsl;

    bsl::ut_scenario{"at_if"} = []() {
        bsl::ut_given{} = []() {
            span<bool> spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.at_if(to_umax(0)) == nullptr);
                bsl::ut_check(spn.at_if(npos) == nullptr);
                bsl::ut_check(spn.at_if(safe_uintmax::zero(true)) == nullptr);
            };
        };

        bsl::ut_given{} = []() {
            span<bool> const spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.at_if(to_umax(0)) == nullptr);
                bsl::ut_check(spn.at_if(npos) == nullptr);
                bsl::ut_check(spn.at_if(safe_uintmax::zero(true)) == nullptr);
            };
        };

        bsl::ut_given{} = []() {
            span<bool> spn{nullptr, to_umax(5)};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.at_if(to_umax(0)) == nullptr);
                bsl::ut_check(spn.at_if(npos) == nullptr);
                bsl::ut_check(spn.at_if(safe_uintmax::zero(true)) == nullptr);
            };
        };

        bsl::ut_given{} = []() {
            span<bool> const spn{nullptr, to_umax(5)};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.at_if(to_umax(0)) == nullptr);
                bsl::ut_check(spn.at_if(npos) == nullptr);
                bsl::ut_check(spn.at_if(safe_uintmax::zero(true)) == nullptr);
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> arr = test_arr;
            span spn{arr.data(), to_umax(0)};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.at_if(to_umax(0)) == nullptr);
                bsl::ut_check(spn.at_if(npos) == nullptr);
                bsl::ut_check(spn.at_if(safe_uintmax::zero(true)) == nullptr);
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> arr = test_arr;
            span const spn{arr.data(), to_umax(0)};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.at_if(to_umax(0)) == nullptr);
                bsl::ut_check(spn.at_if(npos) == nullptr);
                bsl::ut_check(spn.at_if(safe_uintmax::zero(true)) == nullptr);
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> arr = test_arr;
            span spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(*spn.at_if(to_umax(0)) == to_i32(4));
                bsl::ut_check(*spn.at_if(to_umax(1)) == to_i32(8));
                bsl::ut_check(*spn.at_if(to_umax(2)) == to_i32(15));
                bsl::ut_check(*spn.at_if(to_umax(3)) == to_i32(16));
                bsl::ut_check(*spn.at_if(to_umax(4)) == to_i32(23));
                bsl::ut_check(*spn.at_if(to_umax(5)) == to_i32(42));
                bsl::ut_check(spn.at_if(to_umax(6)) == nullptr);
                bsl::ut_check(spn.at_if(npos) == nullptr);
                bsl::ut_check(spn.at_if(safe_uintmax::zero(true)) == nullptr);
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> const arr = test_arr;
            span const spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(*spn.at_if(to_umax(0)) == to_i32(4));
                bsl::ut_check(*spn.at_if(to_umax(1)) == to_i32(8));
                bsl::ut_check(*spn.at_if(to_umax(2)) == to_i32(15));
                bsl::ut_check(*spn.at_if(to_umax(3)) == to_i32(16));
                bsl::ut_check(*spn.at_if(to_umax(4)) == to_i32(23));
                bsl::ut_check(*spn.at_if(to_umax(5)) == to_i32(42));
                bsl::ut_check(spn.at_if(to_umax(6)) == nullptr);
                bsl::ut_check(spn.at_if(npos) == nullptr);
                bsl::ut_check(spn.at_if(safe_uintmax::zero(true)) == nullptr);
            };
        };
    };

    bsl::ut_scenario{"front_if"} = []() {
        bsl::ut_given{} = []() {
            span<bool> spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.front_if() == nullptr);
            };
        };

        bsl::ut_given{} = []() {
            span<bool> const spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.front_if() == nullptr);
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> arr = test_arr;
            span spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(*spn.front_if() == to_i32(4));
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> const arr = test_arr;
            span const spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(*spn.front_if() == to_i32(4));
            };
        };
    };

    bsl::ut_scenario{"back_if"} = []() {
        bsl::ut_given{} = []() {
            span<bool> spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.back_if() == nullptr);
            };
        };

        bsl::ut_given{} = []() {
            span<bool> const spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.back_if() == nullptr);
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> arr = test_arr;
            span spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(*spn.back_if() == to_i32(42));
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> const arr = test_arr;
            span const spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(*spn.back_if() == to_i32(42));
            };
        };
    };

    bsl::ut_scenario{"data"} = []() {
        bsl::ut_given{} = []() {
            span<bool> spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.data() == nullptr);
            };
        };

        bsl::ut_given{} = []() {
            span<bool> const spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.data() == nullptr);
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> arr = test_arr;
            span spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.data() != nullptr);
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> const arr = test_arr;
            span const spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.data() != nullptr);
            };
        };
    };

    bsl::ut_scenario{"begin"} = []() {
        bsl::ut_given{} = []() {
            span<bool> spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.begin().get_if() == nullptr);
                bsl::ut_check(spn.begin().index() == spn.size());
            };
        };

        bsl::ut_given{} = []() {
            span<bool> const spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.begin().get_if() == nullptr);
                bsl::ut_check(spn.begin().index() == spn.size());
            };
        };

        bsl::ut_given{} = []() {
            span<bool> const spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.begin().get_if() == nullptr);
                bsl::ut_check(spn.cbegin().index() == spn.size());
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> arr = test_arr;
            span spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(*(spn.begin().get_if()) == to_i32(4));
                bsl::ut_check(spn.begin().index() == to_umax(0));
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> const arr = test_arr;
            span const spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(*(spn.begin().get_if()) == to_i32(4));
                bsl::ut_check(spn.begin().index() == to_umax(0));
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> const arr = test_arr;
            span const spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(*(spn.cbegin().get_if()) == to_i32(4));
                bsl::ut_check(spn.cbegin().index() == to_umax(0));
            };
        };
    };

    bsl::ut_scenario{"end"} = []() {
        bsl::ut_given{} = []() {
            span<bool> spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.end().get_if() == nullptr);
                bsl::ut_check(spn.end().index() == spn.size());
            };
        };

        bsl::ut_given{} = []() {
            span<bool> const spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.end().get_if() == nullptr);
                bsl::ut_check(spn.end().index() == spn.size());
            };
        };

        bsl::ut_given{} = []() {
            span<bool> const spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.end().get_if() == nullptr);
                bsl::ut_check(spn.cend().index() == spn.size());
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> arr = test_arr;
            span spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.end().get_if() == nullptr);
                bsl::ut_check(spn.end().index() == spn.size());
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> const arr = test_arr;
            span const spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.end().get_if() == nullptr);
                bsl::ut_check(spn.end().index() == spn.size());
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> const arr = test_arr;
            span const spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.cend().get_if() == nullptr);
                bsl::ut_check(spn.cend().index() == spn.size());
            };
        };
    };

    bsl::ut_scenario{"iter"} = []() {
        bsl::ut_given{} = []() {
            span<bool> spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.iter(to_umax(0)).get_if() == nullptr);
                bsl::ut_check(spn.iter(to_umax(0)).index() == spn.size());
            };
        };

        bsl::ut_given{} = []() {
            span<bool> const spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.iter(to_umax(0)).get_if() == nullptr);
                bsl::ut_check(spn.iter(to_umax(0)).index() == spn.size());
            };
        };

        bsl::ut_given{} = []() {
            span<bool> const spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.iter(to_umax(0)).get_if() == nullptr);
                bsl::ut_check(spn.citer(to_umax(0)).index() == spn.size());
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> arr = test_arr;
            span spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(*(spn.iter(to_umax(1)).get_if()) == to_i32(8));
                bsl::ut_check(spn.iter(to_umax(1)).index() == to_umax(1));
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> const arr = test_arr;
            span const spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(*(spn.iter(to_umax(1)).get_if()) == to_i32(8));
                bsl::ut_check(spn.iter(to_umax(1)).index() == to_umax(1));
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> const arr = test_arr;
            span const spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(*(spn.citer(to_umax(1)).get_if()) == to_i32(8));
                bsl::ut_check(spn.citer(to_umax(1)).index() == to_umax(1));
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> arr = test_arr;
            span spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.iter(npos).get_if() == nullptr);
                bsl::ut_check(spn.iter(npos).index() == spn.size());
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> const arr = test_arr;
            span const spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.iter(npos).get_if() == nullptr);
                bsl::ut_check(spn.iter(npos).index() == spn.size());
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> const arr = test_arr;
            span const spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.citer(npos).get_if() == nullptr);
                bsl::ut_check(spn.citer(npos).index() == spn.size());
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> arr = test_arr;
            span spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.iter(safe_uintmax::zero(true)).get_if() == nullptr);
                bsl::ut_check(spn.iter(safe_uintmax::zero(true)).index() == spn.size());
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> const arr = test_arr;
            span const spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.iter(safe_uintmax::zero(true)).get_if() == nullptr);
                bsl::ut_check(spn.iter(safe_uintmax::zero(true)).index() == spn.size());
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> const arr = test_arr;
            span const spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.citer(safe_uintmax::zero(true)).get_if() == nullptr);
                bsl::ut_check(spn.citer(safe_uintmax::zero(true)).index() == spn.size());
            };
        };
    };

    bsl::ut_scenario{"rbegin"} = []() {
        bsl::ut_given{} = []() {
            span<bool> spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.rbegin().get_if() == nullptr);
                bsl::ut_check(spn.rbegin().index() == spn.size());
            };
        };

        bsl::ut_given{} = []() {
            span<bool> const spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.rbegin().get_if() == nullptr);
                bsl::ut_check(spn.rbegin().index() == spn.size());
            };
        };

        bsl::ut_given{} = []() {
            span<bool> const spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.rbegin().get_if() == nullptr);
                bsl::ut_check(spn.crbegin().index() == spn.size());
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> arr = test_arr;
            span spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(*(spn.rbegin().get_if()) == to_i32(42));
                bsl::ut_check(spn.rbegin().index() == to_umax(5));
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> const arr = test_arr;
            span const spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(*(spn.rbegin().get_if()) == to_i32(42));
                bsl::ut_check(spn.rbegin().index() == to_umax(5));
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> const arr = test_arr;
            span const spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(*(spn.crbegin().get_if()) == to_i32(42));
                bsl::ut_check(spn.crbegin().index() == to_umax(5));
            };
        };
    };

    bsl::ut_scenario{"rend"} = []() {
        bsl::ut_given{} = []() {
            span<bool> spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.rend().get_if() == nullptr);
                bsl::ut_check(spn.rend().index() == spn.size());
            };
        };

        bsl::ut_given{} = []() {
            span<bool> const spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.rend().get_if() == nullptr);
                bsl::ut_check(spn.rend().index() == spn.size());
            };
        };

        bsl::ut_given{} = []() {
            span<bool> const spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.rend().get_if() == nullptr);
                bsl::ut_check(spn.crend().index() == spn.size());
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> arr = test_arr;
            span spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.rend().get_if() == nullptr);
                bsl::ut_check(spn.rend().index() == spn.size());
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> const arr = test_arr;
            span const spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.rend().get_if() == nullptr);
                bsl::ut_check(spn.rend().index() == spn.size());
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> const arr = test_arr;
            span const spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.crend().get_if() == nullptr);
                bsl::ut_check(spn.crend().index() == spn.size());
            };
        };
    };

    bsl::ut_scenario{"riter"} = []() {
        bsl::ut_given{} = []() {
            span<bool> spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.riter(to_umax(0)).get_if() == nullptr);
                bsl::ut_check(spn.riter(to_umax(0)).index() == spn.size());
            };
        };

        bsl::ut_given{} = []() {
            span<bool> const spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.riter(to_umax(0)).get_if() == nullptr);
                bsl::ut_check(spn.riter(to_umax(0)).index() == spn.size());
            };
        };

        bsl::ut_given{} = []() {
            span<bool> const spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.riter(to_umax(0)).get_if() == nullptr);
                bsl::ut_check(spn.criter(to_umax(0)).index() == spn.size());
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> arr = test_arr;
            span spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(*(spn.riter(to_umax(1)).get_if()) == to_i32(8));
                bsl::ut_check(spn.riter(to_umax(1)).index() == to_umax(1));
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> const arr = test_arr;
            span const spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(*(spn.riter(to_umax(1)).get_if()) == to_i32(8));
                bsl::ut_check(spn.riter(to_umax(1)).index() == to_umax(1));
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> const arr = test_arr;
            span const spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(*(spn.criter(to_umax(1)).get_if()) == to_i32(8));
                bsl::ut_check(spn.criter(to_umax(1)).index() == to_umax(1));
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> arr = test_arr;
            span spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(*(spn.riter(npos).get_if()) == to_i32(42));
                bsl::ut_check(spn.riter(npos).index() == to_umax(5));
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> const arr = test_arr;
            span const spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(*(spn.riter(npos).get_if()) == to_i32(42));
                bsl::ut_check(spn.riter(npos).index() == to_umax(5));
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> const arr = test_arr;
            span const spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(*(spn.criter(npos).get_if()) == to_i32(42));
                bsl::ut_check(spn.criter(npos).index() == to_umax(5));
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> arr = test_arr;
            span spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(*(spn.riter(safe_uintmax::zero(true)).get_if()) == to_i32(42));
                bsl::ut_check(spn.riter(safe_uintmax::zero(true)).index() == to_umax(5));
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> const arr = test_arr;
            span const spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(*(spn.riter(safe_uintmax::zero(true)).get_if()) == to_i32(42));
                bsl::ut_check(spn.riter(safe_uintmax::zero(true)).index() == to_umax(5));
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> const arr = test_arr;
            span const spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(*(spn.criter(safe_uintmax::zero(true)).get_if()) == to_i32(42));
                bsl::ut_check(spn.criter(safe_uintmax::zero(true)).index() == to_umax(5));
            };
        };
    };

    bsl::ut_scenario{"empty"} = []() {
        bsl::ut_given{} = []() {
            span<bool> const spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.empty());
            };
        };

        bsl::ut_given{} = []() {
            span<bool> const spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.empty());
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> arr = test_arr;
            span spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(!spn.empty());
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> const arr = test_arr;
            span const spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(!spn.empty());
            };
        };
    };

    bsl::ut_scenario{"operator bool"} = []() {
        bsl::ut_given{} = []() {
            span<bool> const spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(!spn);
            };
        };

        bsl::ut_given{} = []() {
            span<bool> const spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(!spn);
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> arr = test_arr;
            span spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(!!spn);
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> const arr = test_arr;
            span const spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(!!spn);
            };
        };
    };

    bsl::ut_scenario{"size"} = []() {
        bsl::ut_given{} = []() {
            span<bool> const spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.size() == to_umax(0));    // NOLINT
            };
        };

        bsl::ut_given{} = []() {
            span<bool> const spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.size() == to_umax(0));    // NOLINT
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> arr = test_arr;
            span spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.size() == to_umax(6));
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> const arr = test_arr;
            span const spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.size() == to_umax(6));
            };
        };
    };

    bsl::ut_scenario{"max_size"} = []() {
        bsl::ut_given{} = []() {
            span<bool> const spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.max_size() == safe_uintmax::max() / sizeof(bool));
            };
        };

        bsl::ut_given{} = []() {
            span<bool> const spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.max_size() == safe_uintmax::max() / sizeof(bool));
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> arr = test_arr;
            span spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.max_size() == safe_uintmax::max() / sizeof(safe_int32));
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> const arr = test_arr;
            span const spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.max_size() == safe_uintmax::max() / sizeof(safe_int32));
            };
        };
    };

    bsl::ut_scenario{"size_bytes"} = []() {
        bsl::ut_given{} = []() {
            span<bool> const spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.size_bytes() == to_umax(0));
            };
        };

        bsl::ut_given{} = []() {
            span<bool> const spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.size_bytes() == to_umax(0));
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> arr = test_arr;
            span spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.size_bytes() == 6 * sizeof(safe_int32));
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> const arr = test_arr;
            span const spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.size_bytes() == 6 * sizeof(safe_int32));
            };
        };
    };

    bsl::ut_scenario{"first"} = []() {
        bsl::ut_given{} = []() {
            span<bool> spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.first() == spn);
            };
        };

        bsl::ut_given{} = []() {
            span<bool> const spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.first() == spn);
            };
        };

        bsl::ut_given{} = []() {
            span<bool> spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.first(to_umax(3)) == spn);
            };
        };

        bsl::ut_given{} = []() {
            span<bool> const spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.first(to_umax(3)) == spn);
            };
        };

        bsl::ut_given{} = []() {
            span<bool> spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.first(to_umax(0)) == spn);
            };
        };

        bsl::ut_given{} = []() {
            span<bool> const spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.first(to_umax(0)) == spn);
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> arr = test_arr;
            span spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.first() == spn);
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> const arr = test_arr;
            span const spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.first() == spn);
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> arr1 = test_arr;
            array<safe_int32, 3> arr2 = {to_i32(4), to_i32(8), to_i32(15)};
            span spn1{arr1.data(), arr1.size()};
            span spn2{arr2.data(), arr2.size()};
            bsl::ut_then{} = [&spn1, &spn2]() {
                bsl::ut_check(spn1.first(to_umax(3)) == spn2);
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> const arr1 = test_arr;
            array<safe_int32, 3> const arr2 = {to_i32(4), to_i32(8), to_i32(15)};
            span const spn1{arr1.data(), arr1.size()};
            span const spn2{arr2.data(), arr2.size()};
            bsl::ut_then{} = [&spn1, &spn2]() {
                bsl::ut_check(spn1.first(to_umax(3)) == spn2);
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> arr = test_arr;
            span spn1{arr.data(), arr.size()};
            span<safe_int32> spn2{};
            bsl::ut_then{} = [&spn1, &spn2]() {
                bsl::ut_check(spn1.first(to_umax(0)) == spn2);
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> const arr = test_arr;
            span const spn1{arr.data(), arr.size()};
            span<safe_int32 const> const spn2{};
            bsl::ut_then{} = [&spn1, &spn2]() {
                bsl::ut_check(spn1.first(to_umax(0)) == spn2);
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> arr = test_arr;
            span spn1{arr.data(), arr.size()};
            span<safe_int32> spn2{};
            bsl::ut_then{} = [&spn1, &spn2]() {
                bsl::ut_check(spn1.first(safe_uintmax::zero(true)) == spn2);
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> const arr = test_arr;
            span const spn1{arr.data(), arr.size()};
            span<safe_int32 const> const spn2{};
            bsl::ut_then{} = [&spn1, &spn2]() {
                bsl::ut_check(spn1.first(safe_uintmax::zero(true)) == spn2);
            };
        };
    };

    bsl::ut_scenario{"last"} = []() {
        bsl::ut_given{} = []() {
            span<bool> spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.last() == spn);
            };
        };

        bsl::ut_given{} = []() {
            span<bool> const spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.last() == spn);
            };
        };

        bsl::ut_given{} = []() {
            span<bool> spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.last(to_umax(3)) == spn);
            };
        };

        bsl::ut_given{} = []() {
            span<bool> const spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.last(to_umax(3)) == spn);
            };
        };

        bsl::ut_given{} = []() {
            span<bool> spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.last(to_umax(0)) == spn);
            };
        };

        bsl::ut_given{} = []() {
            span<bool> const spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.last(to_umax(0)) == spn);
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> arr = test_arr;
            span spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.last() == spn);
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> const arr = test_arr;
            span const spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.last() == spn);
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> arr1 = test_arr;
            array<safe_int32, 3> arr2 = {to_i32(16), to_i32(23), to_i32(42)};
            span spn1{arr1.data(), arr1.size()};
            span spn2{arr2.data(), arr2.size()};
            bsl::ut_then{} = [&spn1, &spn2]() {
                bsl::ut_check(spn1.last(to_umax(3)) == spn2);
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> const arr1 = test_arr;
            array<safe_int32, 3> const arr2 = {to_i32(16), to_i32(23), to_i32(42)};
            span const spn1{arr1.data(), arr1.size()};
            span const spn2{arr2.data(), arr2.size()};
            bsl::ut_then{} = [&spn1, &spn2]() {
                bsl::ut_check(spn1.last(to_umax(3)) == spn2);
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> arr = test_arr;
            span spn1{arr.data(), arr.size()};
            span<safe_int32> spn2{};
            bsl::ut_then{} = [&spn1, &spn2]() {
                bsl::ut_check(spn1.last(to_umax(0)) == spn2);
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> const arr = test_arr;
            span const spn1{arr.data(), arr.size()};
            span<safe_int32 const> const spn2{};
            bsl::ut_then{} = [&spn1, &spn2]() {
                bsl::ut_check(spn1.last(to_umax(0)) == spn2);
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> arr = test_arr;
            span spn1{arr.data(), arr.size()};
            span<safe_int32> spn2{};
            bsl::ut_then{} = [&spn1, &spn2]() {
                bsl::ut_check(spn1.last(safe_uintmax::zero(true)) == spn2);
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> const arr = test_arr;
            span const spn1{arr.data(), arr.size()};
            span<safe_int32 const> const spn2{};
            bsl::ut_then{} = [&spn1, &spn2]() {
                bsl::ut_check(spn1.last(safe_uintmax::zero(true)) == spn2);
            };
        };
    };

    bsl::ut_scenario{"subspan"} = []() {
        bsl::ut_given{} = []() {
            span<bool> spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.subspan(to_umax(0)) == spn);
            };
        };

        bsl::ut_given{} = []() {
            span<bool> const spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.subspan(to_umax(0)) == spn);
            };
        };

        bsl::ut_given{} = []() {
            span<bool> spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.subspan(to_umax(3)) == spn);
            };
        };

        bsl::ut_given{} = []() {
            span<bool> const spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.subspan(to_umax(3)) == spn);
            };
        };

        bsl::ut_given{} = []() {
            span<bool> spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.subspan(to_umax(0), to_umax(3)) == spn);
            };
        };

        bsl::ut_given{} = []() {
            span<bool> const spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.subspan(to_umax(0), to_umax(3)) == spn);
            };
        };

        bsl::ut_given{} = []() {
            span<bool> spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.subspan(to_umax(1), to_umax(3)) == spn);
            };
        };

        bsl::ut_given{} = []() {
            span<bool> const spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.subspan(to_umax(1), to_umax(3)) == spn);
            };
        };

        bsl::ut_given{} = []() {
            span<bool> spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.subspan(npos) == spn);
            };
        };

        bsl::ut_given{} = []() {
            span<bool> const spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.subspan(npos) == spn);
            };
        };

        bsl::ut_given{} = []() {
            span<bool> spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.subspan(safe_uintmax::zero(true)) == spn);
            };
        };

        bsl::ut_given{} = []() {
            span<bool> const spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.subspan(safe_uintmax::zero(true)) == spn);
            };
        };

        bsl::ut_given{} = []() {
            span<bool> spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.subspan(npos, to_umax(3)) == spn);
            };
        };

        bsl::ut_given{} = []() {
            span<bool> const spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.subspan(npos, to_umax(3)) == spn);
            };
        };

        bsl::ut_given{} = []() {
            span<bool> spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.subspan(npos, npos) == spn);
            };
        };

        bsl::ut_given{} = []() {
            span<bool> const spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.subspan(npos, npos) == spn);
            };
        };

        bsl::ut_given{} = []() {
            span<bool> spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.subspan(to_umax(0), safe_uintmax::zero(true)) == spn);
            };
        };

        bsl::ut_given{} = []() {
            span<bool> const spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.subspan(to_umax(0), safe_uintmax::zero(true)) == spn);
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> arr = test_arr;
            span spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.subspan(to_umax(0)) == spn);
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> const arr = test_arr;
            span const spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.subspan(to_umax(0)) == spn);
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> arr1 = test_arr;
            array<safe_int32, 3> arr2 = {to_i32(16), to_i32(23), to_i32(42)};
            span spn1{arr1.data(), arr1.size()};
            span spn2{arr2.data(), arr2.size()};
            bsl::ut_then{} = [&spn1, &spn2]() {
                bsl::ut_check(spn1.subspan(to_umax(3)) == spn2);
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> const arr1 = test_arr;
            array<safe_int32, 3> const arr2 = {to_i32(16), to_i32(23), to_i32(42)};
            span const spn1{arr1.data(), arr1.size()};
            span const spn2{arr2.data(), arr2.size()};
            bsl::ut_then{} = [&spn1, &spn2]() {
                bsl::ut_check(spn1.subspan(to_umax(3)) == spn2);
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> arr1 = test_arr;
            array<safe_int32, 3> arr2 = {to_i32(4), to_i32(8), to_i32(15)};
            span spn1{arr1.data(), arr1.size()};
            span spn2{arr2.data(), arr2.size()};
            bsl::ut_then{} = [&spn1, &spn2]() {
                bsl::ut_check(spn1.subspan(to_umax(0), to_umax(3)) == spn2);
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> const arr1 = test_arr;
            array<safe_int32, 3> const arr2 = {to_i32(4), to_i32(8), to_i32(15)};
            span const spn1{arr1.data(), arr1.size()};
            span const spn2{arr2.data(), arr2.size()};
            bsl::ut_then{} = [&spn1, &spn2]() {
                bsl::ut_check(spn1.subspan(to_umax(0), to_umax(3)) == spn2);
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> arr1 = test_arr;
            array<safe_int32, 3> arr2 = {to_i32(8), to_i32(15), to_i32(16)};
            span spn1{arr1.data(), arr1.size()};
            span spn2{arr2.data(), arr2.size()};
            bsl::ut_then{} = [&spn1, &spn2]() {
                bsl::ut_check(spn1.subspan(to_umax(1), to_umax(3)) == spn2);
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> const arr1 = test_arr;
            array<safe_int32, 3> const arr2 = {to_i32(8), to_i32(15), to_i32(16)};
            span const spn1{arr1.data(), arr1.size()};
            span const spn2{arr2.data(), arr2.size()};
            bsl::ut_then{} = [&spn1, &spn2]() {
                bsl::ut_check(spn1.subspan(to_umax(1), to_umax(3)) == spn2);
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> arr = test_arr;
            span spn1{arr.data(), arr.size()};
            span<safe_int32> spn2{};
            bsl::ut_then{} = [&spn1, &spn2]() {
                bsl::ut_check(spn1.subspan(npos) == spn2);
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> const arr = test_arr;
            span const spn1{arr.data(), arr.size()};
            span<safe_int32 const> const spn2{};
            bsl::ut_then{} = [&spn1, &spn2]() {
                bsl::ut_check(spn1.subspan(npos) == spn2);
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> arr = test_arr;
            span spn1{arr.data(), arr.size()};
            span<safe_int32> spn2{};
            bsl::ut_then{} = [&spn1, &spn2]() {
                bsl::ut_check(spn1.subspan(npos, to_umax(3)) == spn2);
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> const arr = test_arr;
            span const spn1{arr.data(), arr.size()};
            span<safe_int32 const> const spn2{};
            bsl::ut_then{} = [&spn1, &spn2]() {
                bsl::ut_check(spn1.subspan(npos, to_umax(3)) == spn2);
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> arr = test_arr;
            span spn1{arr.data(), arr.size()};
            span<safe_int32> spn2{};
            bsl::ut_then{} = [&spn1, &spn2]() {
                bsl::ut_check(spn1.subspan(npos, npos) == spn2);
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> const arr = test_arr;
            span const spn1{arr.data(), arr.size()};
            span<safe_int32 const> const spn2{};
            bsl::ut_then{} = [&spn1, &spn2]() {
                bsl::ut_check(spn1.subspan(npos, npos) == spn2);
            };
        };
    };

    bsl::ut_scenario{"as_bytes"} = []() {
        bsl::ut_given_at_runtime{} = []() {
            array<safe_int32, 6> arr = test_arr;
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(!as_bytes(nullptr, arr.size_bytes()));
                bsl::ut_check(!as_bytes(arr.data(), to_umax(0)));
                bsl::ut_check(!as_bytes(span{arr.data(), to_umax(0)}));
            };
        };

        bsl::ut_given_at_runtime{} = []() {
            array<safe_int32, 6> arr = test_arr;
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(!!as_bytes(arr.data(), arr.size_bytes()));
                bsl::ut_check(as_bytes(arr.data(), arr.size_bytes()).size() == arr.size_bytes());
                bsl::ut_check(as_bytes(span{arr.data(), arr.size()}).size() == arr.size_bytes());
            };
        };
    };

    bsl::ut_scenario{"as_writable_bytes"} = []() {
        bsl::ut_given_at_runtime{} = []() {
            array<safe_int32, 6> arr = test_arr;
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(!as_writable_bytes(nullptr, arr.size_bytes()));
                bsl::ut_check(!as_writable_bytes(arr.data(), to_umax(0)));
                bsl::ut_check(!as_writable_bytes(span{arr.data(), to_umax(0)}));
            };
        };

        bsl::ut_given_at_runtime{} = []() {
            array<safe_int32, 6> arr = test_arr;
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(!!as_writable_bytes(arr.data(), arr.size_bytes()));
                bsl::ut_check(
                    as_writable_bytes(arr.data(), arr.size_bytes()).size() == arr.size_bytes());
                bsl::ut_check(
                    as_writable_bytes(span{arr.data(), arr.size()}).size() == arr.size_bytes());
            };
        };
    };

    bsl::ut_scenario{"equals"} = []() {
        bsl::ut_given{} = []() {
            array<safe_int32, 6> arr1 = test_arr;
            array<safe_int32, 6> arr2 = test_arr;
            span spn1{arr1.data(), arr1.size()};
            span spn2{arr2.data(), arr2.size()};
            bsl::ut_then{} = [&spn1, &spn2]() {
                bsl::ut_check(spn1 == spn2);
            };
        };

        bsl::ut_given{} = []() {
            array<aggregate, 6> const arr1 = test_aggregate_arr;
            array<aggregate, 6> const arr2 = test_aggregate_arr;
            span spn1{arr1.data(), arr1.size()};
            span spn2{arr2.data(), arr2.size()};
            bsl::ut_then{} = [&spn1, &spn2]() {
                bsl::ut_check(spn1 == spn2);
            };
        };
    };

    bsl::ut_scenario{"not equals"} = []() {
        bsl::ut_given{} = []() {
            array<safe_int32, 6> arr1 = test_arr;
            span spn1{arr1.data(), arr1.size()};
            span<safe_int32> spn2{};
            bsl::ut_then{} = [&spn1, &spn2]() {
                bsl::ut_check(spn1 != spn2);
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> arr1 = test_arr;
            span spn1{arr1.data(), arr1.size()};
            span<safe_int32> spn2{};
            bsl::ut_then{} = [&spn1, &spn2]() {
                bsl::ut_check(spn2 != spn1);
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> arr1 = test_arr;
            array<safe_int32, 3> arr2 = {to_i32(4), to_i32(8), to_i32(15)};
            span spn1{arr1.data(), arr1.size()};
            span spn2{arr2.data(), arr2.size()};
            bsl::ut_then{} = [&spn1, &spn2]() {
                bsl::ut_check(spn1 != spn2);
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> arr1 = test_arr;
            array<safe_int32, 3> arr2 = {to_i32(4), to_i32(8), to_i32(15)};
            span spn1{arr1.data(), arr1.size()};
            span spn2{arr2.data(), arr2.size()};
            bsl::ut_then{} = [&spn1, &spn2]() {
                bsl::ut_check(spn2 != spn1);
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> arr1 = test_arr;
            array<safe_int32, 6> arr2 = test_arr2;
            span spn1{arr1.data(), arr1.size()};
            span spn2{arr2.data(), arr2.size()};
            bsl::ut_then{} = [&spn1, &spn2]() {
                bsl::ut_check(spn1 != spn2);
            };
        };

        bsl::ut_given{} = []() {
            array<aggregate, 6> const arr1 = test_aggregate_arr;
            array<aggregate, 6> const arr2 = test_aggregate_arr2;
            span spn1{arr1.data(), arr1.size()};
            span spn2{arr2.data(), arr2.size()};
            bsl::ut_then{} = [&spn1, &spn2]() {
                bsl::ut_check(spn1 != spn2);
            };
        };
    };

    bsl::ut_scenario{"output doesn't crash"} = []() {
        bsl::ut_given{} = []() {
            span<bool> spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::debug() << spn << '\n';
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> const arr = test_arr;
            span spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::debug() << spn << '\n';
            };
        };
    };

    return bsl::ut_success();
}

/// <!-- description -->
///   @brief Main function for this unit test. If a call to ut_check() fails
///     the application will fast fail. If all calls to ut_check() pass, this
///     function will successfully return with bsl::exit_success.
///
/// <!-- inputs/outputs -->
///   @return Always returns bsl::exit_success.
///
bsl::exit_code
main() noexcept
{
    static_assert(tests() == bsl::ut_success());
    return tests();
}
