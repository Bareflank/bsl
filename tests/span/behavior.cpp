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
#include <bsl/for_each.hpp>
#include <bsl/numeric_limits.hpp>
#include <bsl/ut.hpp>

namespace
{
    struct aggregate final
    {
        bsl::uintmax m_data;
    };

    constexpr bool
    operator==(aggregate const &lhs, aggregate const &rhs) noexcept
    {
        return lhs.m_data == rhs.m_data;
    }
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
    constexpr bsl::uintmax max_size{bsl::numeric_limits<bsl::uintmax>::max()};

    bsl::ut_scenario{"at_if"} = []() {
        bsl::ut_given{} = []() {
            bsl::span<bool> spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.at_if(0) == nullptr);
                bsl::ut_check(spn.at_if(max_size) == nullptr);
            };
        };

        bsl::ut_given{} = []() {
            bsl::span<bool> const spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.at_if(0) == nullptr);
                bsl::ut_check(spn.at_if(max_size) == nullptr);
            };
        };

        bsl::ut_given{} = []() {
            bsl::span<bool> spn{nullptr, 5};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.at_if(0) == nullptr);
                bsl::ut_check(spn.at_if(max_size) == nullptr);
            };
        };

        bsl::ut_given{} = []() {
            bsl::span<bool> const spn{nullptr, 5};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.at_if(0) == nullptr);
                bsl::ut_check(spn.at_if(max_size) == nullptr);
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> arr = {4, 8, 15, 16, 23, 42};
            bsl::span spn{arr.data(), 0};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.at_if(0) == nullptr);
                bsl::ut_check(spn.at_if(max_size) == nullptr);
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> arr = {4, 8, 15, 16, 23, 42};
            bsl::span const spn{arr.data(), 0};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.at_if(0) == nullptr);
                bsl::ut_check(spn.at_if(max_size) == nullptr);
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> arr = {4, 8, 15, 16, 23, 42};
            bsl::span spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(*spn.at_if(0) == 4);
                bsl::ut_check(*spn.at_if(1) == 8);
                bsl::ut_check(*spn.at_if(2) == 15);
                bsl::ut_check(*spn.at_if(3) == 16);
                bsl::ut_check(*spn.at_if(4) == 23);
                bsl::ut_check(*spn.at_if(5) == 42);
                bsl::ut_check(spn.at_if(6) == nullptr);
                bsl::ut_check(spn.at_if(max_size) == nullptr);
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> const arr = {4, 8, 15, 16, 23, 42};
            bsl::span const spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(*spn.at_if(0) == 4);
                bsl::ut_check(*spn.at_if(1) == 8);
                bsl::ut_check(*spn.at_if(2) == 15);
                bsl::ut_check(*spn.at_if(3) == 16);
                bsl::ut_check(*spn.at_if(4) == 23);
                bsl::ut_check(*spn.at_if(5) == 42);
                bsl::ut_check(spn.at_if(6) == nullptr);
                bsl::ut_check(spn.at_if(max_size) == nullptr);
            };
        };
    };

    bsl::ut_scenario{"front_if"} = []() {
        bsl::ut_given{} = []() {
            bsl::span<bool> spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.front_if() == nullptr);
            };
        };

        bsl::ut_given{} = []() {
            bsl::span<bool> const spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.front_if() == nullptr);
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> arr = {4, 8, 15, 16, 23, 42};
            bsl::span spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(*spn.front_if() == 4);
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> const arr = {4, 8, 15, 16, 23, 42};
            bsl::span const spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(*spn.front_if() == 4);
            };
        };
    };

    bsl::ut_scenario{"back_if"} = []() {
        bsl::ut_given{} = []() {
            bsl::span<bool> spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.back_if() == nullptr);
            };
        };

        bsl::ut_given{} = []() {
            bsl::span<bool> const spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.back_if() == nullptr);
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> arr = {4, 8, 15, 16, 23, 42};
            bsl::span spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(*spn.back_if() == 42);
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> const arr = {4, 8, 15, 16, 23, 42};
            bsl::span const spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(*spn.back_if() == 42);
            };
        };
    };

    bsl::ut_scenario{"data"} = []() {
        bsl::ut_given{} = []() {
            bsl::span<bool> spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.data() == nullptr);
            };
        };

        bsl::ut_given{} = []() {
            bsl::span<bool> const spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.data() == nullptr);
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> arr = {4, 8, 15, 16, 23, 42};
            bsl::span spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.data() != nullptr);
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> const arr = {4, 8, 15, 16, 23, 42};
            bsl::span const spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.data() != nullptr);
            };
        };
    };

    bsl::ut_scenario{"begin"} = []() {
        bsl::ut_given{} = []() {
            bsl::span<bool> spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.begin().get_if() == nullptr);
                bsl::ut_check(spn.begin().index() == spn.size());
            };
        };

        bsl::ut_given{} = []() {
            bsl::span<bool> const spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.begin().get_if() == nullptr);
                bsl::ut_check(spn.begin().index() == spn.size());
            };
        };

        bsl::ut_given{} = []() {
            bsl::span<bool> const spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.begin().get_if() == nullptr);
                bsl::ut_check(spn.cbegin().index() == spn.size());
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> arr = {4, 8, 15, 16, 23, 42};
            bsl::span spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(*(spn.begin().get_if()) == 4);
                bsl::ut_check(spn.begin().index() == 0);
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> const arr = {4, 8, 15, 16, 23, 42};
            bsl::span const spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(*(spn.begin().get_if()) == 4);
                bsl::ut_check(spn.begin().index() == 0);
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> const arr = {4, 8, 15, 16, 23, 42};
            bsl::span const spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(*(spn.cbegin().get_if()) == 4);
                bsl::ut_check(spn.cbegin().index() == 0);
            };
        };
    };

    bsl::ut_scenario{"end"} = []() {
        bsl::ut_given{} = []() {
            bsl::span<bool> spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.end().get_if() == nullptr);
                bsl::ut_check(spn.end().index() == spn.size());
            };
        };

        bsl::ut_given{} = []() {
            bsl::span<bool> const spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.end().get_if() == nullptr);
                bsl::ut_check(spn.end().index() == spn.size());
            };
        };

        bsl::ut_given{} = []() {
            bsl::span<bool> const spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.end().get_if() == nullptr);
                bsl::ut_check(spn.cend().index() == spn.size());
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> arr = {4, 8, 15, 16, 23, 42};
            bsl::span spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.end().get_if() == nullptr);
                bsl::ut_check(spn.end().index() == spn.size());
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> const arr = {4, 8, 15, 16, 23, 42};
            bsl::span const spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.end().get_if() == nullptr);
                bsl::ut_check(spn.end().index() == spn.size());
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> const arr = {4, 8, 15, 16, 23, 42};
            bsl::span const spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.cend().get_if() == nullptr);
                bsl::ut_check(spn.cend().index() == spn.size());
            };
        };
    };

    bsl::ut_scenario{"iter"} = []() {
        bsl::ut_given{} = []() {
            bsl::span<bool> spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.iter(0).get_if() == nullptr);
                bsl::ut_check(spn.iter(0).index() == spn.size());
            };
        };

        bsl::ut_given{} = []() {
            bsl::span<bool> const spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.iter(0).get_if() == nullptr);
                bsl::ut_check(spn.iter(0).index() == spn.size());
            };
        };

        bsl::ut_given{} = []() {
            bsl::span<bool> const spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.iter(0).get_if() == nullptr);
                bsl::ut_check(spn.citer(0).index() == spn.size());
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> arr = {4, 8, 15, 16, 23, 42};
            bsl::span spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(*(spn.iter(1).get_if()) == 8);
                bsl::ut_check(spn.iter(1).index() == 1);
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> const arr = {4, 8, 15, 16, 23, 42};
            bsl::span const spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(*(spn.iter(1).get_if()) == 8);
                bsl::ut_check(spn.iter(1).index() == 1);
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> const arr = {4, 8, 15, 16, 23, 42};
            bsl::span const spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(*(spn.citer(1).get_if()) == 8);
                bsl::ut_check(spn.citer(1).index() == 1);
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> arr = {4, 8, 15, 16, 23, 42};
            bsl::span spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.iter(bsl::npos).get_if() == nullptr);
                bsl::ut_check(spn.iter(bsl::npos).index() == spn.size());
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> const arr = {4, 8, 15, 16, 23, 42};
            bsl::span const spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.iter(bsl::npos).get_if() == nullptr);
                bsl::ut_check(spn.iter(bsl::npos).index() == spn.size());
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> const arr = {4, 8, 15, 16, 23, 42};
            bsl::span const spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.citer(bsl::npos).get_if() == nullptr);
                bsl::ut_check(spn.citer(bsl::npos).index() == spn.size());
            };
        };
    };

    bsl::ut_scenario{"rbegin"} = []() {
        bsl::ut_given{} = []() {
            bsl::span<bool> spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.rbegin().get_if() == nullptr);
                bsl::ut_check(spn.rbegin().index() == spn.size());
            };
        };

        bsl::ut_given{} = []() {
            bsl::span<bool> const spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.rbegin().get_if() == nullptr);
                bsl::ut_check(spn.rbegin().index() == spn.size());
            };
        };

        bsl::ut_given{} = []() {
            bsl::span<bool> const spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.rbegin().get_if() == nullptr);
                bsl::ut_check(spn.crbegin().index() == spn.size());
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> arr = {4, 8, 15, 16, 23, 42};
            bsl::span spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(*(spn.rbegin().get_if()) == 42);
                bsl::ut_check(spn.rbegin().index() == 5);
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> const arr = {4, 8, 15, 16, 23, 42};
            bsl::span const spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(*(spn.rbegin().get_if()) == 42);
                bsl::ut_check(spn.rbegin().index() == 5);
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> const arr = {4, 8, 15, 16, 23, 42};
            bsl::span const spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(*(spn.crbegin().get_if()) == 42);
                bsl::ut_check(spn.crbegin().index() == 5);
            };
        };
    };

    bsl::ut_scenario{"rend"} = []() {
        bsl::ut_given{} = []() {
            bsl::span<bool> spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.rend().get_if() == nullptr);
                bsl::ut_check(spn.rend().index() == spn.size());
            };
        };

        bsl::ut_given{} = []() {
            bsl::span<bool> const spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.rend().get_if() == nullptr);
                bsl::ut_check(spn.rend().index() == spn.size());
            };
        };

        bsl::ut_given{} = []() {
            bsl::span<bool> const spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.rend().get_if() == nullptr);
                bsl::ut_check(spn.crend().index() == spn.size());
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> arr = {4, 8, 15, 16, 23, 42};
            bsl::span spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.rend().get_if() == nullptr);
                bsl::ut_check(spn.rend().index() == spn.size());
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> const arr = {4, 8, 15, 16, 23, 42};
            bsl::span const spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.rend().get_if() == nullptr);
                bsl::ut_check(spn.rend().index() == spn.size());
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> const arr = {4, 8, 15, 16, 23, 42};
            bsl::span const spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.crend().get_if() == nullptr);
                bsl::ut_check(spn.crend().index() == spn.size());
            };
        };
    };

    bsl::ut_scenario{"riter"} = []() {
        bsl::ut_given{} = []() {
            bsl::span<bool> spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.riter(0).get_if() == nullptr);
                bsl::ut_check(spn.riter(0).index() == spn.size());
            };
        };

        bsl::ut_given{} = []() {
            bsl::span<bool> const spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.riter(0).get_if() == nullptr);
                bsl::ut_check(spn.riter(0).index() == spn.size());
            };
        };

        bsl::ut_given{} = []() {
            bsl::span<bool> const spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.riter(0).get_if() == nullptr);
                bsl::ut_check(spn.criter(0).index() == spn.size());
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> arr = {4, 8, 15, 16, 23, 42};
            bsl::span spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(*(spn.riter(1).get_if()) == 8);
                bsl::ut_check(spn.riter(1).index() == 1);
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> const arr = {4, 8, 15, 16, 23, 42};
            bsl::span const spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(*(spn.riter(1).get_if()) == 8);
                bsl::ut_check(spn.riter(1).index() == 1);
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> const arr = {4, 8, 15, 16, 23, 42};
            bsl::span const spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(*(spn.criter(1).get_if()) == 8);
                bsl::ut_check(spn.criter(1).index() == 1);
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> arr = {4, 8, 15, 16, 23, 42};
            bsl::span spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(*(spn.riter(bsl::npos).get_if()) == 42);
                bsl::ut_check(spn.riter(bsl::npos).index() == 5);
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> const arr = {4, 8, 15, 16, 23, 42};
            bsl::span const spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(*(spn.riter(bsl::npos).get_if()) == 42);
                bsl::ut_check(spn.riter(bsl::npos).index() == 5);
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> const arr = {4, 8, 15, 16, 23, 42};
            bsl::span const spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(*(spn.criter(bsl::npos).get_if()) == 42);
                bsl::ut_check(spn.criter(bsl::npos).index() == 5);
            };
        };
    };

    bsl::ut_scenario{"empty"} = []() {
        bsl::ut_given{} = []() {
            bsl::span<bool> const spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.empty());
            };
        };

        bsl::ut_given{} = []() {
            bsl::span<bool> const spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.empty());
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> arr = {4, 8, 15, 16, 23, 42};
            bsl::span spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(!spn.empty());
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> const arr = {4, 8, 15, 16, 23, 42};
            bsl::span const spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(!spn.empty());
            };
        };
    };

    bsl::ut_scenario{"size"} = []() {
        bsl::ut_given{} = []() {
            bsl::span<bool> const spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.size() == 0);    // NOLINT
            };
        };

        bsl::ut_given{} = []() {
            bsl::span<bool> const spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.size() == 0);    // NOLINT
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> arr = {4, 8, 15, 16, 23, 42};
            bsl::span spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.size() == 6);
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> const arr = {4, 8, 15, 16, 23, 42};
            bsl::span const spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.size() == 6);
            };
        };
    };

    bsl::ut_scenario{"max_size"} = []() {
        bsl::ut_given{} = []() {
            bsl::span<bool> const spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.max_size() == max_size / sizeof(bool));
            };
        };

        bsl::ut_given{} = []() {
            bsl::span<bool> const spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.max_size() == max_size / sizeof(bool));
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> arr = {4, 8, 15, 16, 23, 42};
            bsl::span spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.max_size() == max_size / sizeof(bsl::uintmax));
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> const arr = {4, 8, 15, 16, 23, 42};
            bsl::span const spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.max_size() == max_size / sizeof(bsl::uintmax));
            };
        };
    };

    bsl::ut_scenario{"size_bytes"} = []() {
        bsl::ut_given{} = []() {
            bsl::span<bool> const spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.size_bytes() == 0);
            };
        };

        bsl::ut_given{} = []() {
            bsl::span<bool> const spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.size_bytes() == 0);
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> arr = {4, 8, 15, 16, 23, 42};
            bsl::span spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.size_bytes() == 6 * sizeof(bsl::uintmax));
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> const arr = {4, 8, 15, 16, 23, 42};
            bsl::span const spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.size_bytes() == 6 * sizeof(bsl::uintmax));
            };
        };
    };

    bsl::ut_scenario{"first"} = []() {
        bsl::ut_given{} = []() {
            bsl::span<bool> spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.first() == spn);
            };
        };

        bsl::ut_given{} = []() {
            bsl::span<bool> const spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.first() == spn);
            };
        };

        bsl::ut_given{} = []() {
            bsl::span<bool> spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.first(3) == spn);
            };
        };

        bsl::ut_given{} = []() {
            bsl::span<bool> const spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.first(3) == spn);
            };
        };

        bsl::ut_given{} = []() {
            bsl::span<bool> spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.first(0) == spn);
            };
        };

        bsl::ut_given{} = []() {
            bsl::span<bool> const spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.first(0) == spn);
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> arr = {4, 8, 15, 16, 23, 42};
            bsl::span spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.first() == spn);
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> const arr = {4, 8, 15, 16, 23, 42};
            bsl::span const spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.first() == spn);
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> arr1 = {4, 8, 15, 16, 23, 42};
            bsl::array<bsl::uintmax, 3> arr2 = {4, 8, 15};
            bsl::span spn1{arr1.data(), arr1.size()};
            bsl::span spn2{arr2.data(), arr2.size()};
            bsl::ut_then{} = [&spn1, &spn2]() {
                bsl::ut_check(spn1.first(3) == spn2);
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> const arr1 = {4, 8, 15, 16, 23, 42};
            bsl::array<bsl::uintmax, 3> const arr2 = {4, 8, 15};
            bsl::span const spn1{arr1.data(), arr1.size()};
            bsl::span const spn2{arr2.data(), arr2.size()};
            bsl::ut_then{} = [&spn1, &spn2]() {
                bsl::ut_check(spn1.first(3) == spn2);
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> arr = {4, 8, 15, 16, 23, 42};
            bsl::span spn1{arr.data(), arr.size()};
            bsl::span<bsl::uintmax> spn2{};
            bsl::ut_then{} = [&spn1, &spn2]() {
                bsl::ut_check(spn1.first(0) == spn2);
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> const arr = {4, 8, 15, 16, 23, 42};
            bsl::span const spn1{arr.data(), arr.size()};
            bsl::span<bsl::uintmax const> const spn2{};
            bsl::ut_then{} = [&spn1, &spn2]() {
                bsl::ut_check(spn1.first(0) == spn2);
            };
        };
    };

    bsl::ut_scenario{"last"} = []() {
        bsl::ut_given{} = []() {
            bsl::span<bool> spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.last() == spn);
            };
        };

        bsl::ut_given{} = []() {
            bsl::span<bool> const spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.last() == spn);
            };
        };

        bsl::ut_given{} = []() {
            bsl::span<bool> spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.last(3) == spn);
            };
        };

        bsl::ut_given{} = []() {
            bsl::span<bool> const spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.last(3) == spn);
            };
        };

        bsl::ut_given{} = []() {
            bsl::span<bool> spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.last(0) == spn);
            };
        };

        bsl::ut_given{} = []() {
            bsl::span<bool> const spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.last(0) == spn);
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> arr = {4, 8, 15, 16, 23, 42};
            bsl::span spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.last() == spn);
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> const arr = {4, 8, 15, 16, 23, 42};
            bsl::span const spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.last() == spn);
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> arr1 = {4, 8, 15, 16, 23, 42};
            bsl::array<bsl::uintmax, 3> arr2 = {16, 23, 42};
            bsl::span spn1{arr1.data(), arr1.size()};
            bsl::span spn2{arr2.data(), arr2.size()};
            bsl::ut_then{} = [&spn1, &spn2]() {
                bsl::ut_check(spn1.last(3) == spn2);
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> const arr1 = {4, 8, 15, 16, 23, 42};
            bsl::array<bsl::uintmax, 3> const arr2 = {16, 23, 42};
            bsl::span const spn1{arr1.data(), arr1.size()};
            bsl::span const spn2{arr2.data(), arr2.size()};
            bsl::ut_then{} = [&spn1, &spn2]() {
                bsl::ut_check(spn1.last(3) == spn2);
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> arr = {4, 8, 15, 16, 23, 42};
            bsl::span spn1{arr.data(), arr.size()};
            bsl::span<bsl::uintmax> spn2{};
            bsl::ut_then{} = [&spn1, &spn2]() {
                bsl::ut_check(spn1.last(0) == spn2);
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> const arr = {4, 8, 15, 16, 23, 42};
            bsl::span const spn1{arr.data(), arr.size()};
            bsl::span<bsl::uintmax const> const spn2{};
            bsl::ut_then{} = [&spn1, &spn2]() {
                bsl::ut_check(spn1.last(0) == spn2);
            };
        };
    };

    bsl::ut_scenario{"subspan"} = []() {
        bsl::ut_given{} = []() {
            bsl::span<bool> spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.subspan(0) == spn);
            };
        };

        bsl::ut_given{} = []() {
            bsl::span<bool> const spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.subspan(0) == spn);
            };
        };

        bsl::ut_given{} = []() {
            bsl::span<bool> spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.subspan(3) == spn);
            };
        };

        bsl::ut_given{} = []() {
            bsl::span<bool> const spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.subspan(3) == spn);
            };
        };

        bsl::ut_given{} = []() {
            bsl::span<bool> spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.subspan(0, 3) == spn);
            };
        };

        bsl::ut_given{} = []() {
            bsl::span<bool> const spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.subspan(0, 3) == spn);
            };
        };

        bsl::ut_given{} = []() {
            bsl::span<bool> spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.subspan(1, 3) == spn);
            };
        };

        bsl::ut_given{} = []() {
            bsl::span<bool> const spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.subspan(1, 3) == spn);
            };
        };

        bsl::ut_given{} = []() {
            bsl::span<bool> spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.subspan(bsl::npos) == spn);
            };
        };

        bsl::ut_given{} = []() {
            bsl::span<bool> const spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.subspan(bsl::npos) == spn);
            };
        };

        bsl::ut_given{} = []() {
            bsl::span<bool> spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.subspan(bsl::npos, 3) == spn);
            };
        };

        bsl::ut_given{} = []() {
            bsl::span<bool> const spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.subspan(bsl::npos, 3) == spn);
            };
        };

        bsl::ut_given{} = []() {
            bsl::span<bool> spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.subspan(bsl::npos, bsl::npos) == spn);
            };
        };

        bsl::ut_given{} = []() {
            bsl::span<bool> const spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.subspan(bsl::npos, bsl::npos) == spn);
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> arr = {4, 8, 15, 16, 23, 42};
            bsl::span spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.subspan(0) == spn);
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> const arr = {4, 8, 15, 16, 23, 42};
            bsl::span const spn{arr.data(), arr.size()};
            bsl::ut_then{} = [&spn]() {
                bsl::ut_check(spn.subspan(0) == spn);
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> arr1 = {4, 8, 15, 16, 23, 42};
            bsl::array<bsl::uintmax, 3> arr2 = {16, 23, 42};
            bsl::span spn1{arr1.data(), arr1.size()};
            bsl::span spn2{arr2.data(), arr2.size()};
            bsl::ut_then{} = [&spn1, &spn2]() {
                bsl::ut_check(spn1.subspan(3) == spn2);
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> const arr1 = {4, 8, 15, 16, 23, 42};
            bsl::array<bsl::uintmax, 3> const arr2 = {16, 23, 42};
            bsl::span const spn1{arr1.data(), arr1.size()};
            bsl::span const spn2{arr2.data(), arr2.size()};
            bsl::ut_then{} = [&spn1, &spn2]() {
                bsl::ut_check(spn1.subspan(3) == spn2);
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> arr1 = {4, 8, 15, 16, 23, 42};
            bsl::array<bsl::uintmax, 3> arr2 = {4, 8, 15};
            bsl::span spn1{arr1.data(), arr1.size()};
            bsl::span spn2{arr2.data(), arr2.size()};
            bsl::ut_then{} = [&spn1, &spn2]() {
                bsl::ut_check(spn1.subspan(0, 3) == spn2);
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> const arr1 = {4, 8, 15, 16, 23, 42};
            bsl::array<bsl::uintmax, 3> const arr2 = {4, 8, 15};
            bsl::span const spn1{arr1.data(), arr1.size()};
            bsl::span const spn2{arr2.data(), arr2.size()};
            bsl::ut_then{} = [&spn1, &spn2]() {
                bsl::ut_check(spn1.subspan(0, 3) == spn2);
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> arr1 = {4, 8, 15, 16, 23, 42};
            bsl::array<bsl::uintmax, 3> arr2 = {8, 15, 16};
            bsl::span spn1{arr1.data(), arr1.size()};
            bsl::span spn2{arr2.data(), arr2.size()};
            bsl::ut_then{} = [&spn1, &spn2]() {
                bsl::ut_check(spn1.subspan(1, 3) == spn2);
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> const arr1 = {4, 8, 15, 16, 23, 42};
            bsl::array<bsl::uintmax, 3> const arr2 = {8, 15, 16};
            bsl::span const spn1{arr1.data(), arr1.size()};
            bsl::span const spn2{arr2.data(), arr2.size()};
            bsl::ut_then{} = [&spn1, &spn2]() {
                bsl::ut_check(spn1.subspan(1, 3) == spn2);
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> arr = {4, 8, 15, 16, 23, 42};
            bsl::span spn1{arr.data(), arr.size()};
            bsl::span<bsl::uintmax> spn2{};
            bsl::ut_then{} = [&spn1, &spn2]() {
                bsl::ut_check(spn1.subspan(bsl::npos) == spn2);
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> const arr = {4, 8, 15, 16, 23, 42};
            bsl::span const spn1{arr.data(), arr.size()};
            bsl::span<bsl::uintmax const> const spn2{};
            bsl::ut_then{} = [&spn1, &spn2]() {
                bsl::ut_check(spn1.subspan(bsl::npos) == spn2);
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> arr = {4, 8, 15, 16, 23, 42};
            bsl::span spn1{arr.data(), arr.size()};
            bsl::span<bsl::uintmax> spn2{};
            bsl::ut_then{} = [&spn1, &spn2]() {
                bsl::ut_check(spn1.subspan(bsl::npos, 3) == spn2);
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> const arr = {4, 8, 15, 16, 23, 42};
            bsl::span const spn1{arr.data(), arr.size()};
            bsl::span<bsl::uintmax const> const spn2{};
            bsl::ut_then{} = [&spn1, &spn2]() {
                bsl::ut_check(spn1.subspan(bsl::npos, 3) == spn2);
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> arr = {4, 8, 15, 16, 23, 42};
            bsl::span spn1{arr.data(), arr.size()};
            bsl::span<bsl::uintmax> spn2{};
            bsl::ut_then{} = [&spn1, &spn2]() {
                bsl::ut_check(spn1.subspan(bsl::npos, bsl::npos) == spn2);
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> const arr = {4, 8, 15, 16, 23, 42};
            bsl::span const spn1{arr.data(), arr.size()};
            bsl::span<bsl::uintmax const> const spn2{};
            bsl::ut_then{} = [&spn1, &spn2]() {
                bsl::ut_check(spn1.subspan(bsl::npos, bsl::npos) == spn2);
            };
        };
    };

    bsl::ut_scenario{"equals"} = []() {
        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> arr1 = {4, 8, 15, 16, 23, 42};
            bsl::array<bsl::uintmax, 6> arr2 = {4, 8, 15, 16, 23, 42};
            bsl::span spn1{arr1.data(), arr1.size()};
            bsl::span spn2{arr2.data(), arr2.size()};
            bsl::ut_then{} = [&spn1, &spn2]() {
                bsl::ut_check(spn1 == spn2);
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<aggregate, 6> const arr1 = {4, 8, 15, 16, 23, 42};
            bsl::array<aggregate, 6> const arr2 = {4, 8, 15, 16, 23, 42};
            bsl::span spn1{arr1.data(), arr1.size()};
            bsl::span spn2{arr2.data(), arr2.size()};
            bsl::ut_then{} = [&spn1, &spn2]() {
                bsl::ut_check(spn1 == spn2);
            };
        };
    };

    bsl::ut_scenario{"not equals"} = []() {
        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> arr1 = {4, 8, 15, 16, 23, 42};
            bsl::span spn1{arr1.data(), arr1.size()};
            bsl::span<bsl::uintmax> spn2{};
            bsl::ut_then{} = [&spn1, &spn2]() {
                bsl::ut_check(spn1 != spn2);
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> arr1 = {4, 8, 15, 16, 23, 42};
            bsl::span spn1{arr1.data(), arr1.size()};
            bsl::span<bsl::uintmax> spn2{};
            bsl::ut_then{} = [&spn1, &spn2]() {
                bsl::ut_check(spn2 != spn1);
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> arr1 = {4, 8, 15, 16, 23, 42};
            bsl::array<bsl::uintmax, 3> arr2 = {4, 8, 15};
            bsl::span spn1{arr1.data(), arr1.size()};
            bsl::span spn2{arr2.data(), arr2.size()};
            bsl::ut_then{} = [&spn1, &spn2]() {
                bsl::ut_check(spn1 != spn2);
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> arr1 = {4, 8, 15, 16, 23, 42};
            bsl::array<bsl::uintmax, 3> arr2 = {4, 8, 15};
            bsl::span spn1{arr1.data(), arr1.size()};
            bsl::span spn2{arr2.data(), arr2.size()};
            bsl::ut_then{} = [&spn1, &spn2]() {
                bsl::ut_check(spn2 != spn1);
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> arr1 = {4, 8, 15, 16, 23, 42};
            bsl::array<bsl::uintmax, 6> arr2 = {4, 8, 15, 16, 0, 42};
            bsl::span spn1{arr1.data(), arr1.size()};
            bsl::span spn2{arr2.data(), arr2.size()};
            bsl::ut_then{} = [&spn1, &spn2]() {
                bsl::ut_check(spn1 != spn2);
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<aggregate, 6> const arr1 = {4, 8, 15, 16, 23, 42};
            bsl::array<aggregate, 6> const arr2 = {4, 8, 15, 16, 0, 42};
            bsl::span spn1{arr1.data(), arr1.size()};
            bsl::span spn2{arr2.data(), arr2.size()};
            bsl::ut_then{} = [&spn1, &spn2]() {
                bsl::ut_check(spn1 != spn2);
            };
        };
    };

    bsl::ut_scenario{"output doesn't crash"} = []() {
        bsl::ut_given{} = []() {
            bsl::span<bool> spn{};
            bsl::ut_then{} = [&spn]() {
                bsl::debug() << spn << '\n';
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> const arr = {4, 8, 15, 16, 23, 42};
            bsl::span spn{arr.data(), arr.size()};
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
