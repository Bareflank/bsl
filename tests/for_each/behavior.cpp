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

#include <bsl/for_each.hpp>
#include <bsl/array.hpp>
#include <bsl/span.hpp>
#include <bsl/ut.hpp>

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

    // clang-format off

    bsl::ut_scenario{"empty span"} = []() {
        bsl::ut_given{} = []() {
            bool touched{};
            bsl::span<bool> spn{};
            bsl::ut_when{} = [&spn, &touched]() {
                bsl::for_each(spn, [&touched](auto &e) {
                    bsl::discard(e);
                    touched = true;
                });
                bsl::ut_then{} = [&touched]() {
                    bsl::ut_check(!touched);
                };
            };
        };

        bsl::ut_given{} = []() {
            bool touched{};
            bsl::span<bool> spn{};
            bsl::ut_when{} = [&spn, &touched]() {
                bsl::for_each(spn, [&touched](auto &e, auto i) {
                    bsl::discard(e);
                    bsl::discard(i);
                    touched = true;
                });
                bsl::ut_then{} = [&touched]() {
                    bsl::ut_check(!touched);
                };
            };
        };

        bsl::ut_given{} = []() {
            bool touched{};
            bsl::span<bool> spn{};
            bsl::ut_when{} = [&spn, &touched]() {
                bsl::for_each(spn, [&touched](auto &e) -> bool {
                    bsl::discard(e);
                    touched = true;
                    return bsl::for_each_continue;
                });
                bsl::ut_then{} = [&touched]() {
                    bsl::ut_check(!touched);
                };
            };
        };

        bsl::ut_given{} = []() {
            bool touched{};
            bsl::span<bool> spn{};
            bsl::ut_when{} = [&spn, &touched]() {
                bsl::for_each(spn, [&touched](auto &e, auto i) -> bool {
                    bsl::discard(e);
                    bsl::discard(i);
                    touched = true;
                    return bsl::for_each_continue;
                });
                bsl::ut_then{} = [&touched]() {
                    bsl::ut_check(!touched);
                };
            };
        };
    };

    bsl::ut_scenario{"loop over a view"} = []() {
        bsl::ut_given{} = []() {
            bsl::safe_int32 sum{};
            bsl::array<safe_int32, 3> arr = {to_i32(1), to_i32(1), to_i32(1)};
            bsl::ut_when{} = [&arr, &sum]() {
                bsl::for_each(arr, [&sum](auto &e) {
                    sum += e;
                });
                bsl::ut_then{} = [&sum]() {
                    bsl::ut_check(sum == 3);
                };
            };
        };

        bsl::ut_given{} = []() {
            bsl::safe_int32 sum{};
            bsl::array<safe_int32, 3> arr = {to_i32(1), to_i32(1), to_i32(1)};
            bsl::ut_when{} = [&arr, &sum]() {
                bsl::for_each(arr, [&sum](auto &e, auto i) {
                    sum += e;
                    sum += to_i32(i);
                });
                bsl::ut_then{} = [&sum]() {
                    bsl::ut_check(sum == 6);
                };
            };
        };

        bsl::ut_given{} = []() {
            bsl::safe_int32 sum{};
            bsl::array<safe_int32, 3> arr = {to_i32(1), to_i32(1), to_i32(1)};
            bsl::ut_when{} = [&arr, &sum]() {
                bsl::for_each(arr, [&sum](auto &e) -> bool {
                    if (e == 1) {
                        return bsl::for_each_break;
                    }

                    sum += e;
                    return bsl::for_each_continue;
                });
                bsl::ut_then{} = [&sum]() {
                    bsl::ut_check(sum == 0);
                };
            };
        };

        bsl::ut_given{} = []() {
            bsl::safe_int32 sum{};
            bsl::array<safe_int32, 3> arr = {to_i32(1), to_i32(1), to_i32(1)};
            bsl::ut_when{} = [&arr, &sum]() {
                bsl::for_each(arr, [&sum](auto &e, auto i) -> bool {
                    if (i == to_umax(2)) {
                        return bsl::for_each_break;
                    }

                    sum += e;
                    sum += to_i32(i);
                    return bsl::for_each_continue;
                });
                bsl::ut_then{} = [&sum]() {
                    bsl::ut_check(sum == 3);
                };
            };
        };
    };

    bsl::ut_scenario{"loop using begin()/end() iterators"} = []() {
        bsl::ut_given{} = []() {
            bsl::safe_int32 sum{};
            bsl::array<safe_int32, 3> arr = {to_i32(1), to_i32(1), to_i32(1)};
            bsl::ut_when{} = [&arr, &sum]() {
                bsl::for_each(arr.begin(), arr.end(), [&sum](auto &e) {
                    sum += e;
                });
                bsl::ut_then{} = [&sum]() {
                    bsl::ut_check(sum == 3);
                };
            };
        };

        bsl::ut_given{} = []() {
            bsl::safe_int32 sum{};
            bsl::array<safe_int32, 3> arr = {to_i32(1), to_i32(1), to_i32(1)};
            bsl::ut_when{} = [&arr, &sum]() {
                bsl::for_each(arr.begin(), arr.end(), [&sum](auto &e, auto i) {
                    sum += e;
                    sum += to_i32(i);
                });
                bsl::ut_then{} = [&sum]() {
                    bsl::ut_check(sum == 6);
                };
            };
        };

        bsl::ut_given{} = []() {
            bsl::safe_int32 sum{};
            bsl::array<safe_int32, 3> arr = {to_i32(1), to_i32(1), to_i32(1)};
            bsl::ut_when{} = [&arr, &sum]() {
                bsl::for_each(arr.begin(), arr.end(), [&sum](auto &e) -> bool {
                    if (e == 1) {
                        return bsl::for_each_break;
                    }

                    sum += e;
                    return bsl::for_each_continue;
                });
                bsl::ut_then{} = [&sum]() {
                    bsl::ut_check(sum == 0);
                };
            };
        };

        bsl::ut_given{} = []() {
            bsl::safe_int32 sum{};
            bsl::array<safe_int32, 3> arr = {to_i32(1), to_i32(1), to_i32(1)};
            bsl::ut_when{} = [&arr, &sum]() {
                bsl::for_each(arr.begin(), arr.end(), [&sum](auto &e, auto i) -> bool {
                    if (i == to_umax(2)) {
                        return bsl::for_each_break;
                    }

                    sum += e;
                    sum += to_i32(i);
                    return bsl::for_each_continue;
                });
                bsl::ut_then{} = [&sum]() {
                    bsl::ut_check(sum == 3);
                };
            };
        };
    };

    bsl::ut_scenario{"loop using rbegin()/rend() iterators"} = []() {
        bsl::ut_given{} = []() {
            bsl::safe_int32 sum{};
            bsl::array<safe_int32, 3> arr = {to_i32(1), to_i32(1), to_i32(1)};
            bsl::ut_when{} = [&arr, &sum]() {
                bsl::for_each(arr.rbegin(), arr.rend(), [&sum](auto &e) {
                    sum += e;
                });
                bsl::ut_then{} = [&sum]() {
                    bsl::ut_check(sum == 3);
                };
            };
        };

        bsl::ut_given{} = []() {
            bsl::safe_int32 sum{};
            bsl::array<safe_int32, 3> arr = {to_i32(1), to_i32(1), to_i32(1)};
            bsl::ut_when{} = [&arr, &sum]() {
                bsl::for_each(arr.rbegin(), arr.rend(), [&sum](auto &e, auto i) {
                    sum += e;
                    sum += to_i32(i);
                });
                bsl::ut_then{} = [&sum]() {
                    bsl::ut_check(sum == 6);
                };
            };
        };

        bsl::ut_given{} = []() {
            bsl::safe_int32 sum{};
            bsl::array<safe_int32, 3> arr = {to_i32(1), to_i32(1), to_i32(1)};
            bsl::ut_when{} = [&arr, &sum]() {
                bsl::for_each(arr.rbegin(), arr.rend(), [&sum](auto &e) -> bool {
                    if (e == 1) {
                        return bsl::for_each_break;
                    }

                    sum += e;
                    return bsl::for_each_continue;
                });
                bsl::ut_then{} = [&sum]() {
                    bsl::ut_check(sum == 0);
                };
            };
        };

        bsl::ut_given{} = []() {
            bsl::safe_int32 sum{};
            bsl::array<safe_int32, 3> arr = {to_i32(1), to_i32(1), to_i32(1)};
            bsl::ut_when{} = [&arr, &sum]() {
                bsl::for_each(arr.rbegin(), arr.rend(), [&sum](auto &e, auto i) -> bool {
                    if (i == to_umax(2)) {
                        return bsl::for_each_break;
                    }

                    sum += e;
                    sum += to_i32(i);
                    return bsl::for_each_continue;
                });
                bsl::ut_then{} = [&sum]() {
                    bsl::ut_check(sum == 0);
                };
            };
        };
    };

    bsl::ut_scenario{"loop using iter() iterators"} = []() {
        bsl::ut_given{} = []() {
            bsl::safe_int32 sum{};
            bsl::array<safe_int32, 5> arr{to_i32(1), to_i32(1), to_i32(1), to_i32(1), to_i32(1)};
            bsl::ut_when{} = [&arr, &sum]() {
                bsl::for_each(arr.iter(to_umax(1)), arr.iter(to_umax(4)), [&sum](auto &e) {
                    sum += e;
                });
                bsl::ut_then{} = [&sum]() {
                    bsl::ut_check(sum == 3);
                };
            };
        };

        bsl::ut_given{} = []() {
            bsl::safe_int32 sum{};
            bsl::array<safe_int32, 5> arr{to_i32(1), to_i32(1), to_i32(1), to_i32(1), to_i32(1)};
            bsl::ut_when{} = [&arr, &sum]() {
                bsl::for_each(arr.iter(to_umax(1)), arr.iter(to_umax(4)), [&sum](auto &e, auto i) {
                    sum += e;
                    sum += to_i32(i);
                });
                bsl::ut_then{} = [&sum]() {
                    bsl::ut_check(sum == 9);
                };
            };
        };
    };

    bsl::ut_scenario{"loop using riter() iterators"} = []() {
        bsl::ut_given{} = []() {
            bsl::safe_int32 sum{};
            bsl::array<safe_int32, 5> arr{to_i32(1), to_i32(1), to_i32(1), to_i32(1), to_i32(1)};
            bsl::ut_when{} = [&arr, &sum]() {
                bsl::for_each(arr.riter(to_umax(3)), arr.riter(to_umax(0)), [&sum](auto &e) {
                    sum += e;
                });
                bsl::ut_then{} = [&sum]() {
                    bsl::ut_check(sum == 3);
                };
            };
        };

        bsl::ut_given{} = []() {
            bsl::safe_int32 sum{};
            bsl::array<safe_int32, 5> arr{to_i32(1), to_i32(1), to_i32(1), to_i32(1), to_i32(1)};
            bsl::ut_when{} = [&arr, &sum]() {
                bsl::for_each(arr.riter(to_umax(3)), arr.riter(to_umax(0)), [&sum](auto &e, auto i) {
                    sum += e;
                    sum += to_i32(i);
                });
                bsl::ut_then{} = [&sum]() {
                    bsl::ut_check(sum == 9);
                };
            };
        };
    };

    bsl::ut_scenario{"loop using invalid begin()/end() iterators"} = []() {
        bsl::ut_given{} = []() {
            bsl::safe_int32 sum{};
            bsl::array<safe_int32, 3> arr = {to_i32(1), to_i32(1), to_i32(1)};
            bsl::ut_when{} = [&arr, &sum]() {
                bsl::for_each(arr.end(), arr.begin(), [&sum](auto &e) {
                    sum += e;
                });
                bsl::ut_then{} = [&sum]() {
                    bsl::ut_check(sum == 0);
                };
            };
        };

        bsl::ut_given{} = []() {
            bsl::safe_int32 sum{};
            bsl::array<safe_int32, 3> arr = {to_i32(1), to_i32(1), to_i32(1)};
            bsl::ut_when{} = [&arr, &sum]() {
                bsl::for_each(arr.end(), arr.begin(), [&sum](auto &e, auto i) {
                    sum += e;
                    sum += to_i32(i);
                });
                bsl::ut_then{} = [&sum]() {
                    bsl::ut_check(sum == 0);
                };
            };
        };
    };

    bsl::ut_scenario{"loop using invalid rbegin()/rend() iterators"} = []() {
        bsl::ut_given{} = []() {
            bsl::safe_int32 sum{};
            bsl::array<safe_int32, 3> arr = {to_i32(1), to_i32(1), to_i32(1)};
            bsl::ut_when{} = [&arr, &sum]() {
                bsl::for_each(arr.rend(), arr.rbegin(), [&sum](auto &e) {
                    sum += e;
                });
                bsl::ut_then{} = [&sum]() {
                    bsl::ut_check(sum == 0);
                };
            };
        };

        bsl::ut_given{} = []() {
            bsl::safe_int32 sum{};
            bsl::array<safe_int32, 3> arr = {to_i32(1), to_i32(1), to_i32(1)};
            bsl::ut_when{} = [&arr, &sum]() {
                bsl::for_each(arr.rend(), arr.rbegin(), [&sum](auto &e, auto i) {
                    sum += e;
                    sum += to_i32(i);
                });
                bsl::ut_then{} = [&sum]() {
                    bsl::ut_check(sum == 0);
                };
            };
        };
    };

    bsl::ut_scenario{"loop using invalid iter() iterators"} = []() {
        bsl::ut_given{} = []() {
            bsl::safe_int32 sum{};
            bsl::array<safe_int32, 5> arr{to_i32(1), to_i32(1), to_i32(1), to_i32(1), to_i32(1)};
            bsl::ut_when{} = [&arr, &sum]() {
                bsl::for_each(arr.iter(to_umax(4)), arr.iter(to_umax(1)), [&sum](auto &e) {
                    sum += e;
                });
                bsl::ut_then{} = [&sum]() {
                    bsl::ut_check(sum == 0);
                };
            };
        };

        bsl::ut_given{} = []() {
            bsl::safe_int32 sum{};
            bsl::array<safe_int32, 5> arr{to_i32(1), to_i32(1), to_i32(1), to_i32(1), to_i32(1)};
            bsl::ut_when{} = [&arr, &sum]() {
                bsl::for_each(arr.iter(to_umax(4)), arr.iter(to_umax(1)), [&sum](auto &e, auto i) {
                    sum += e;
                    sum += to_i32(i);
                });
                bsl::ut_then{} = [&sum]() {
                    bsl::ut_check(sum == 0);
                };
            };
        };
    };

    bsl::ut_scenario{"loop using invalid riter() iterators"} = []() {
        bsl::ut_given{} = []() {
            bsl::safe_int32 sum{};
            bsl::array<safe_int32, 5> arr{to_i32(1), to_i32(1), to_i32(1), to_i32(1), to_i32(1)};
            bsl::ut_when{} = [&arr, &sum]() {
                bsl::for_each(arr.riter(to_umax(0)), arr.riter(to_umax(3)), [&sum](auto &e) {
                    sum += e;
                });
                bsl::ut_then{} = [&sum]() {
                    bsl::ut_check(sum == 0);
                };
            };
        };

        bsl::ut_given{} = []() {
            bsl::safe_int32 sum{};
            bsl::array<safe_int32, 5> arr{to_i32(1), to_i32(1), to_i32(1), to_i32(1), to_i32(1)};
            bsl::ut_when{} = [&arr, &sum]() {
                bsl::for_each(arr.riter(to_umax(0)), arr.riter(to_umax(3)), [&sum](auto &e, auto i) {
                    sum += e;
                    sum += to_i32(i);
                });
                bsl::ut_then{} = [&sum]() {
                    bsl::ut_check(sum == 0);
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
