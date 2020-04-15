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

#include <bsl/array.hpp>
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
            bsl::array<bsl::uintmax, 6> arr = {4, 8, 15, 16, 23, 42};
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(*arr.at_if(0) == 4);
                bsl::ut_check(*arr.at_if(1) == 8);
                bsl::ut_check(*arr.at_if(2) == 15);
                bsl::ut_check(*arr.at_if(3) == 16);
                bsl::ut_check(*arr.at_if(4) == 23);
                bsl::ut_check(*arr.at_if(5) == 42);
                bsl::ut_check(arr.at_if(6) == nullptr);
                bsl::ut_check(arr.at_if(max_size) == nullptr);
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> const arr = {4, 8, 15, 16, 23, 42};
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(*arr.at_if(0) == 4);
                bsl::ut_check(*arr.at_if(1) == 8);
                bsl::ut_check(*arr.at_if(2) == 15);
                bsl::ut_check(*arr.at_if(3) == 16);
                bsl::ut_check(*arr.at_if(4) == 23);
                bsl::ut_check(*arr.at_if(5) == 42);
                bsl::ut_check(arr.at_if(6) == nullptr);
                bsl::ut_check(arr.at_if(max_size) == nullptr);
            };
        };
    };

    bsl::ut_scenario{"front"} = []() {
        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> arr = {4, 8, 15, 16, 23, 42};
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(arr.front() == 4);
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> const arr = {4, 8, 15, 16, 23, 42};
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(arr.front() == 4);
            };
        };
    };

    bsl::ut_scenario{"front_if"} = []() {
        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> arr = {4, 8, 15, 16, 23, 42};
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(*arr.front_if() == 4);
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> const arr = {4, 8, 15, 16, 23, 42};
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(*arr.front_if() == 4);
            };
        };
    };

    bsl::ut_scenario{"back"} = []() {
        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> arr = {4, 8, 15, 16, 23, 42};
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(arr.back() == 42);
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> const arr = {4, 8, 15, 16, 23, 42};
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(arr.back() == 42);
            };
        };
    };

    bsl::ut_scenario{"back_if"} = []() {
        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> arr = {4, 8, 15, 16, 23, 42};
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(*arr.back_if() == 42);
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> const arr = {4, 8, 15, 16, 23, 42};
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(*arr.back_if() == 42);
            };
        };
    };

    bsl::ut_scenario{"data"} = []() {
        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> arr = {4, 8, 15, 16, 23, 42};
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(arr.data() != nullptr);
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> const arr = {4, 8, 15, 16, 23, 42};
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(arr.data() != nullptr);
            };
        };
    };

    bsl::ut_scenario{"begin"} = []() {
        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> arr = {4, 8, 15, 16, 23, 42};
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(*(arr.begin().get_if()) == 4);
                bsl::ut_check(arr.begin().index() == 0);
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> const arr = {4, 8, 15, 16, 23, 42};
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(*(arr.begin().get_if()) == 4);
                bsl::ut_check(arr.begin().index() == 0);
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> const arr = {4, 8, 15, 16, 23, 42};
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(*(arr.cbegin().get_if()) == 4);
                bsl::ut_check(arr.cbegin().index() == 0);
            };
        };
    };

    bsl::ut_scenario{"end"} = []() {
        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> arr = {4, 8, 15, 16, 23, 42};
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(arr.end().get_if() == nullptr);
                bsl::ut_check(arr.end().index() == arr.size());
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> const arr = {4, 8, 15, 16, 23, 42};
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(arr.end().get_if() == nullptr);
                bsl::ut_check(arr.end().index() == arr.size());
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> const arr = {4, 8, 15, 16, 23, 42};
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(arr.cend().get_if() == nullptr);
                bsl::ut_check(arr.cend().index() == arr.size());
            };
        };
    };

    bsl::ut_scenario{"iter"} = []() {
        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> arr = {4, 8, 15, 16, 23, 42};
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(*(arr.iter(1).get_if()) == 8);
                bsl::ut_check(arr.iter(1).index() == 1);
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> const arr = {4, 8, 15, 16, 23, 42};
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(*(arr.iter(1).get_if()) == 8);
                bsl::ut_check(arr.iter(1).index() == 1);
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> const arr = {4, 8, 15, 16, 23, 42};
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(*(arr.citer(1).get_if()) == 8);
                bsl::ut_check(arr.citer(1).index() == 1);
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> arr = {4, 8, 15, 16, 23, 42};
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(arr.iter(bsl::npos).get_if() == nullptr);
                bsl::ut_check(arr.iter(bsl::npos).index() == arr.size());
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> const arr = {4, 8, 15, 16, 23, 42};
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(arr.iter(bsl::npos).get_if() == nullptr);
                bsl::ut_check(arr.iter(bsl::npos).index() == arr.size());
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> const arr = {4, 8, 15, 16, 23, 42};
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(arr.citer(bsl::npos).get_if() == nullptr);
                bsl::ut_check(arr.citer(bsl::npos).index() == arr.size());
            };
        };
    };

    bsl::ut_scenario{"rbegin"} = []() {
        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> arr = {4, 8, 15, 16, 23, 42};
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(*(arr.rbegin().get_if()) == 42);
                bsl::ut_check(arr.rbegin().index() == 5);
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> const arr = {4, 8, 15, 16, 23, 42};
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(*(arr.rbegin().get_if()) == 42);
                bsl::ut_check(arr.rbegin().index() == 5);
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> const arr = {4, 8, 15, 16, 23, 42};
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(*(arr.crbegin().get_if()) == 42);
                bsl::ut_check(arr.crbegin().index() == 5);
            };
        };
    };

    bsl::ut_scenario{"rend"} = []() {
        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> arr = {4, 8, 15, 16, 23, 42};
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(arr.rend().get_if() == nullptr);
                bsl::ut_check(arr.rend().index() == arr.size());
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> const arr = {4, 8, 15, 16, 23, 42};
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(arr.rend().get_if() == nullptr);
                bsl::ut_check(arr.rend().index() == arr.size());
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> const arr = {4, 8, 15, 16, 23, 42};
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(arr.crend().get_if() == nullptr);
                bsl::ut_check(arr.crend().index() == arr.size());
            };
        };
    };

    bsl::ut_scenario{"riter"} = []() {
        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> arr = {4, 8, 15, 16, 23, 42};
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(*(arr.riter(1).get_if()) == 8);
                bsl::ut_check(arr.riter(1).index() == 1);
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> const arr = {4, 8, 15, 16, 23, 42};
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(*(arr.riter(1).get_if()) == 8);
                bsl::ut_check(arr.riter(1).index() == 1);
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> const arr = {4, 8, 15, 16, 23, 42};
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(*(arr.criter(1).get_if()) == 8);
                bsl::ut_check(arr.criter(1).index() == 1);
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> arr = {4, 8, 15, 16, 23, 42};
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(*(arr.riter(bsl::npos).get_if()) == 42);
                bsl::ut_check(arr.riter(bsl::npos).index() == 5);
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> const arr = {4, 8, 15, 16, 23, 42};
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(*(arr.riter(bsl::npos).get_if()) == 42);
                bsl::ut_check(arr.riter(bsl::npos).index() == 5);
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> const arr = {4, 8, 15, 16, 23, 42};
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(*(arr.criter(bsl::npos).get_if()) == 42);
                bsl::ut_check(arr.criter(bsl::npos).index() == 5);
            };
        };
    };

    bsl::ut_scenario{"empty"} = []() {
        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> arr = {4, 8, 15, 16, 23, 42};
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(!arr.empty());
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> const arr = {4, 8, 15, 16, 23, 42};
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(!arr.empty());
            };
        };
    };

    bsl::ut_scenario{"size"} = []() {
        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> arr = {4, 8, 15, 16, 23, 42};
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(arr.size() == 6);
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> const arr = {4, 8, 15, 16, 23, 42};
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(arr.size() == 6);
            };
        };
    };

    bsl::ut_scenario{"max_size"} = []() {
        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> arr = {4, 8, 15, 16, 23, 42};
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(arr.max_size() == max_size / sizeof(bsl::uintmax));
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> const arr = {4, 8, 15, 16, 23, 42};
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(arr.max_size() == max_size / sizeof(bsl::uintmax));
            };
        };
    };

    bsl::ut_scenario{"size_bytes"} = []() {
        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> arr = {4, 8, 15, 16, 23, 42};
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(arr.size_bytes() == 6 * sizeof(bsl::uintmax));
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> const arr = {4, 8, 15, 16, 23, 42};
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(arr.size_bytes() == 6 * sizeof(bsl::uintmax));
            };
        };
    };

    bsl::ut_scenario{"equals"} = []() {
        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> const arr1 = {4, 8, 15, 16, 23, 42};
            bsl::array<bsl::uintmax, 6> const arr2 = {4, 8, 15, 16, 23, 42};
            bsl::ut_then{} = [&arr1, &arr2]() {
                bsl::ut_check(arr1 == arr2);
            };
        };
    };

    bsl::ut_scenario{"equals"} = []() {
        bsl::ut_given{} = []() {
            bsl::array<aggregate, 6> const arr1 = {4, 8, 15, 16, 23, 42};
            bsl::array<aggregate, 6> const arr2 = {4, 8, 15, 16, 23, 42};
            bsl::ut_then{} = [&arr1, &arr2]() {
                bsl::ut_check(arr1 == arr2);
            };
        };
    };

    bsl::ut_scenario{"not equals"} = []() {
        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> const arr1 = {4, 8, 15, 16, 23, 42};
            bsl::array<bsl::uintmax, 6> const arr2 = {};
            bsl::ut_then{} = [&arr1, &arr2]() {
                bsl::ut_check(arr1 != arr2);
            };
        };
    };

    bsl::ut_scenario{"not equals"} = []() {
        bsl::ut_given{} = []() {
            bsl::array<aggregate, 6> const arr1 = {4, 8, 15, 16, 23, 42};
            bsl::array<aggregate, 6> const arr2 = {};
            bsl::ut_then{} = [&arr1, &arr2]() {
                bsl::ut_check(arr1 != arr2);
            };
        };
    };

    bsl::ut_scenario{"output doesn't crash"} = []() {
        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 1> const arr = {42};
            bsl::ut_then{} = [&arr]() {
                bsl::debug() << arr << '\n';
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> const arr = {4, 8, 15, 16, 23, 42};
            bsl::ut_then{} = [&arr]() {
                bsl::debug() << arr << '\n';
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
