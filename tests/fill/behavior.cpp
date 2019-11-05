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

#include <bsl/fill.hpp>
#include <bsl/array.hpp>
#include <bsl/for_each.hpp>
#include <bsl/span.hpp>
#include <bsl/ut.hpp>

namespace
{
    enum myenum : bsl::uintmax
    {
        init = 1,
        zero = 0
    };
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
    bsl::ut_scenario{"empty span doesn't crash"} = []() {
        bsl::ut_given{} = []() {
            bsl::span<bool> spn{};
            bsl::ut_when{} = [&spn]() {
                bsl::fill(spn, true);
            };
        };
    };

    bsl::ut_scenario{"fill view"} = []() {
        bsl::ut_given{} = []() {
            bsl::array<bool, 5> arr{};
            bsl::ut_when{} = [&arr]() {
                bsl::fill(arr, true);
                bsl::ut_then{} = [&arr]() {
                    bsl::for_each(arr, [](auto &e) {
                        bsl::ut_check(e);
                    });
                };
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 5> arr{1, 1, 1, 1, 1};
            bsl::ut_when{} = [&arr]() {
                bsl::fill(arr, 0U);
                bsl::ut_then{} = [&arr]() {
                    bsl::for_each(arr, [](auto &e) {
                        bsl::ut_check(e == 0);
                    });
                };
            };
        };

        bsl::ut_given{} = []() {
            bsl::array<myenum, 5> arr{init, init, init, init, init};
            bsl::ut_when{} = [&arr]() {
                bsl::fill(arr, zero);
                bsl::ut_then{} = [&arr]() {
                    bsl::for_each(arr, [](auto &e) {
                        bsl::ut_check(e == zero);
                    });
                };
            };
        };
    };

    bsl::ut_scenario{"fill with being()/end()"} = []() {
        bsl::ut_given{} = []() {
            bsl::array<bool, 5> arr{};
            bsl::ut_when{} = [&arr]() {
                bsl::fill(arr.begin(), arr.end(), true);
                bsl::ut_then{} = [&arr]() {
                    bsl::for_each(arr, [](auto &e) {
                        bsl::ut_check(e);
                    });
                };
            };
        };
    };

    bsl::ut_scenario{"fill with rbeing()/rend()"} = []() {
        bsl::ut_given{} = []() {
            bsl::array<bool, 5> arr{};
            bsl::ut_when{} = [&arr]() {
                bsl::fill(arr.rbegin(), arr.rend(), true);
                bsl::ut_then{} = [&arr]() {
                    bsl::for_each(arr, [](auto &e) {
                        bsl::ut_check(e);
                    });
                };
            };
        };
    };

    bsl::ut_scenario{"fill with iter()"} = []() {
        bsl::ut_given{} = []() {
            bsl::array<bool, 5> arr{};
            bsl::ut_when{} = [&arr]() {
                bsl::fill(arr.iter(1), arr.iter(4), true);
                bsl::ut_then{} = [&arr]() {
                    bsl::ut_check(!*arr.at_if(0));
                    bsl::ut_check(*arr.at_if(1));
                    bsl::ut_check(*arr.at_if(2));
                    bsl::ut_check(*arr.at_if(3));
                    bsl::ut_check(!*arr.at_if(4));
                };
            };
        };
    };

    bsl::ut_scenario{"fill with riter()"} = []() {
        bsl::ut_given{} = []() {
            bsl::array<bool, 5> arr{};
            bsl::ut_when{} = [&arr]() {
                bsl::fill(arr.riter(3), arr.riter(0), true);
                bsl::ut_then{} = [&arr]() {
                    bsl::ut_check(!*arr.at_if(0));
                    bsl::ut_check(*arr.at_if(1));
                    bsl::ut_check(*arr.at_if(2));
                    bsl::ut_check(*arr.at_if(3));
                    bsl::ut_check(!*arr.at_if(4));
                };
            };
        };
    };

    bsl::ut_scenario{"fill with invalid being()/end()"} = []() {
        bsl::ut_given{} = []() {
            bsl::array<bool, 5> arr{};
            bsl::ut_when{} = [&arr]() {
                bsl::fill(arr.end(), arr.begin(), true);
                bsl::ut_then{} = [&arr]() {
                    bsl::for_each(arr, [](auto &e) {
                        bsl::ut_check(!e);
                    });
                };
            };
        };
    };

    bsl::ut_scenario{"fill with invalid rbeing()/rend()"} = []() {
        bsl::ut_given{} = []() {
            bsl::array<bool, 5> arr{};
            bsl::ut_when{} = [&arr]() {
                bsl::fill(arr.rend(), arr.rbegin(), true);
                bsl::ut_then{} = [&arr]() {
                    bsl::for_each(arr, [](auto &e) {
                        bsl::ut_check(!e);
                    });
                };
            };
        };
    };

    bsl::ut_scenario{"fill with invalid iter()"} = []() {
        bsl::ut_given{} = []() {
            bsl::array<bool, 5> arr{};
            bsl::ut_when{} = [&arr]() {
                bsl::fill(arr.iter(4), arr.iter(1), true);
                bsl::ut_then{} = [&arr]() {
                    bsl::for_each(arr, [](auto &e) {
                        bsl::ut_check(!e);
                    });
                };
            };
        };
    };

    bsl::ut_scenario{"fill with invalid riter()"} = []() {
        bsl::ut_given{} = []() {
            bsl::array<bool, 5> arr{};
            bsl::ut_when{} = [&arr]() {
                bsl::fill(arr.riter(0), arr.riter(3), true);
                bsl::ut_then{} = [&arr]() {
                    bsl::for_each(arr, [](auto &e) {
                        bsl::ut_check(!e);
                    });
                };
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
