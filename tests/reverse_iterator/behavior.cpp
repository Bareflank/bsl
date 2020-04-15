/// @copyright
/// Copyright (C) 2020 Assured Information Security, Inc.
///
/// @copyright
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and assoriated documentation files (the "Software"), to deal
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

#include <bsl/reverse_iterator.hpp>
#include <bsl/array.hpp>
#include <bsl/npos.hpp>
#include <bsl/numeric_limits.hpp>
#include <bsl/ut.hpp>

namespace
{
    constexpr bsl::array<bsl::uintmax, 6> arr{4, 8, 15, 16, 23, 42};
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
    bsl::ut_scenario{"constructor"} = []() {
        bsl::ut_given{} = []() {
            bsl::reverse_iterator ri{arr.begin()};
            bsl::ut_then{} = [&ri]() {
                bsl::ut_check(!ri.empty());
            };
        };

        bsl::ut_given{} = []() {
            bsl::reverse_iterator ri{arr.end()};
            bsl::ut_then{} = [&ri]() {
                bsl::ut_check(!ri.empty());
            };
        };
    };

    bsl::ut_scenario{"base"} = []() {
        bsl::ut_given{} = []() {
            bsl::reverse_iterator ri{arr.begin()};
            bsl::ut_then{} = [&ri]() {
                bsl::ut_check(ri.base() == arr.begin());
            };
        };
    };

    bsl::ut_scenario{"data"} = []() {
        bsl::ut_given{} = []() {
            bsl::reverse_iterator ri{arr.begin()};
            bsl::ut_then{} = [&ri]() {
                bsl::ut_check(ri.data() == arr.data());
            };
        };

        bsl::ut_given{} = []() {
            bsl::reverse_iterator const ri{arr.begin()};
            bsl::ut_then{} = [&ri]() {
                bsl::ut_check(ri.data() == arr.data());
            };
        };
    };

    bsl::ut_scenario{"size"} = []() {
        bsl::ut_given{} = []() {
            bsl::reverse_iterator ri{arr.begin()};
            bsl::ut_then{} = [&ri]() {
                bsl::ut_check(ri.size() == arr.size());
            };
        };
    };

    bsl::ut_scenario{"index"} = []() {
        bsl::ut_given{} = []() {
            bsl::reverse_iterator ri{arr.end()};
            bsl::ut_then{} = [&ri]() {
                bsl::ut_check(ri.index() == 5);
            };
        };

        bsl::ut_given{} = []() {
            bsl::reverse_iterator ri{arr.begin()};
            bsl::ut_then{} = [&ri]() {
                bsl::ut_check(ri.index() == 6);
            };
        };
    };

    bsl::ut_scenario{"empty"} = []() {
        bsl::ut_given{} = []() {
            bsl::reverse_iterator ri{arr.begin()};
            bsl::ut_then{} = [&ri]() {
                bsl::ut_check(!ri.empty());
            };
        };
    };

    bsl::ut_scenario{"is_end"} = []() {
        bsl::ut_given{} = []() {
            bsl::reverse_iterator ri{arr.begin()};
            bsl::ut_then{} = [&ri]() {
                bsl::ut_check(ri.is_end());
            };
        };

        bsl::ut_given{} = []() {
            bsl::reverse_iterator ri{arr.end()};
            bsl::ut_then{} = [&ri]() {
                bsl::ut_check(!ri.is_end());
            };
        };
    };

    bsl::ut_scenario{"get_if"} = []() {
        bsl::ut_given{} = []() {
            bsl::contiguous_iterator<bool> const ci{nullptr, 0, 0};
            bsl::reverse_iterator ri{ci};
            bsl::ut_then{} = [&ri]() {
                bsl::ut_check(ri.get_if() == nullptr);
            };
        };

        bsl::ut_given{} = []() {
            bsl::contiguous_iterator<bool> const ci{nullptr, 0, 0};
            bsl::reverse_iterator const ri{ci};
            bsl::ut_then{} = [&ri]() {
                bsl::ut_check(ri.get_if() == nullptr);
            };
        };

        bsl::ut_given{} = []() {
            bsl::reverse_iterator ri{arr.begin()};
            bsl::ut_then{} = [&ri]() {
                bsl::ut_check(ri.get_if() == nullptr);
            };
        };

        bsl::ut_given{} = []() {
            bsl::reverse_iterator const ri{arr.begin()};
            bsl::ut_then{} = [&ri]() {
                bsl::ut_check(ri.get_if() == nullptr);
            };
        };

        bsl::ut_given{} = []() {
            bsl::reverse_iterator ri{arr.end()};
            bsl::ut_then{} = [&ri]() {
                bsl::ut_check(ri.get_if() == arr.back_if());
            };
        };

        bsl::ut_given{} = []() {
            bsl::reverse_iterator const ri{arr.end()};
            bsl::ut_then{} = [&ri]() {
                bsl::ut_check(ri.get_if() == arr.back_if());
            };
        };
    };

    bsl::ut_scenario{"++ operator"} = []() {
        bsl::ut_given{} = []() {
            bsl::reverse_iterator ri{arr.begin()};
            bsl::ut_when{} = [&ri]() {
                ++ri;
                bsl::ut_then{} = [&ri]() {
                    bsl::ut_check(ri.get_if() == nullptr);
                    bsl::ut_check(ri.index() == arr.size());
                };
            };
        };

        bsl::ut_given{} = []() {
            bsl::reverse_iterator ri{arr.iter(1)};
            bsl::ut_when{} = [&ri]() {
                ++ri;
                bsl::ut_then{} = [&ri]() {
                    bsl::ut_check(ri.get_if() == nullptr);
                    bsl::ut_check(ri.index() == arr.size());
                };
            };
        };

        bsl::ut_given{} = []() {
            bsl::reverse_iterator ri{arr.iter(2)};
            bsl::ut_when{} = [&ri]() {
                ++ri;
                bsl::ut_then{} = [&ri]() {
                    bsl::ut_check(ri.get_if() == arr.front_if());
                    bsl::ut_check(ri.index() == 0);
                };
            };
        };

        bsl::ut_given{} = []() {
            bsl::reverse_iterator ri{arr.end()};
            bsl::ut_when{} = [&ri]() {
                ++ri;
                bsl::ut_then{} = [&ri]() {
                    bsl::ut_check(ri.get_if() == arr.at_if(4));
                    bsl::ut_check(ri.index() == 4);
                };
            };
        };
    };

    bsl::ut_scenario{"-- operator"} = []() {
        bsl::ut_given{} = []() {
            bsl::reverse_iterator ri{arr.begin()};
            bsl::ut_when{} = [&ri]() {
                --ri;
                bsl::ut_then{} = [&ri]() {
                    bsl::ut_check(ri.get_if() == arr.front_if());
                    bsl::ut_check(ri.index() == 0);
                };
            };
        };

        bsl::ut_given{} = []() {
            bsl::reverse_iterator ri{arr.iter(1)};
            bsl::ut_when{} = [&ri]() {
                --ri;
                bsl::ut_then{} = [&ri]() {
                    bsl::ut_check(ri.get_if() == arr.at_if(1));
                    bsl::ut_check(ri.index() == 1);
                };
            };
        };

        bsl::ut_given{} = []() {
            bsl::reverse_iterator ri{arr.iter(5)};
            bsl::ut_when{} = [&ri]() {
                --ri;
                bsl::ut_then{} = [&ri]() {
                    bsl::ut_check(ri.get_if() == arr.back_if());
                    bsl::ut_check(ri.index() == 5);
                };
            };
        };

        bsl::ut_given{} = []() {
            bsl::reverse_iterator ri{arr.end()};
            bsl::ut_when{} = [&ri]() {
                --ri;
                bsl::ut_then{} = [&ri]() {
                    bsl::ut_check(ri.get_if() == arr.back_if());
                    bsl::ut_check(ri.index() == 5);
                };
            };
        };
    };

    bsl::ut_scenario{"comparisons"} = []() {
        bsl::ut_given{} = []() {
            bsl::reverse_iterator ri1{arr.begin()};
            bsl::reverse_iterator ri2{arr.begin()};
            bsl::ut_then{} = [&ri1, &ri2]() {
                bsl::ut_check(ri1 == ri2);
            };
        };

        bsl::ut_given{} = []() {
            bsl::reverse_iterator ri1{arr.begin()};
            bsl::reverse_iterator ri2{arr.end()};
            bsl::ut_then{} = [&ri1, &ri2]() {
                bsl::ut_check(ri1 != ri2);
            };
        };

        bsl::ut_given{} = []() {
            bsl::reverse_iterator ri1{arr.begin()};
            bsl::reverse_iterator ri2{arr.end()};
            bsl::ut_then{} = [&ri1, &ri2]() {
                bsl::ut_check(ri1 > ri2);
                bsl::ut_check(ri1 >= ri2);
            };
        };

        bsl::ut_given{} = []() {
            bsl::reverse_iterator ri1{arr.begin()};
            bsl::reverse_iterator ri2{arr.begin()};
            bsl::ut_then{} = [&ri1, &ri2]() {
                bsl::ut_check(ri1 >= ri2);
            };
        };

        bsl::ut_given{} = []() {
            bsl::reverse_iterator ri1{arr.end()};
            bsl::reverse_iterator ri2{arr.begin()};
            bsl::ut_then{} = [&ri1, &ri2]() {
                bsl::ut_check(ri1 < ri2);
                bsl::ut_check(ri1 <= ri2);
            };
        };

        bsl::ut_given{} = []() {
            bsl::reverse_iterator ri1{arr.begin()};
            bsl::reverse_iterator ri2{arr.begin()};
            bsl::ut_then{} = [&ri1, &ri2]() {
                bsl::ut_check(ri1 <= ri2);
            };
        };
    };

    bsl::ut_scenario{"output doesn't crash"} = []() {
        bsl::ut_given{} = []() {
            bsl::reverse_iterator ri{arr.begin()};
            bsl::ut_then{} = [&ri]() {
                bsl::debug() << ri << '\n';
            };
        };

        bsl::ut_given{} = []() {
            bsl::reverse_iterator ri{arr.end()};
            bsl::ut_then{} = [&ri]() {
                bsl::debug() << ri << '\n';
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
