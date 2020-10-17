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

#include <bsl/result.hpp>
#include <bsl/ut.hpp>

namespace
{
    /// <!-- description -->
    ///   @brief Used to execute the actual checks. We put the checks in this
    ///     function so that we can validate the tests both at compile-time
    ///     and at run-time. If a bsl::ut_check fails, the tests will either
    ///     fail fast at run-time, or will produce a compile-time error.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Always returns bsl::exit_success.
    ///
    [[nodiscard]] constexpr auto
    tests() noexcept -> bsl::exit_code
    {
        bsl::ut_scenario{"default"} = []() {
            bsl::ut_given{} = []() {
                bsl::result<bool> const test{};
                bsl::ut_then{} = [&test]() {
                    bsl::ut_check(test.success());
                    bsl::ut_check(test.errc() == bsl::errc_success);
                };
            };
        };

        bsl::ut_scenario{"make copy t"} = []() {
            bsl::ut_given{} = []() {
                bool const val{true};
                bsl::result<bool> const test{val};
                bsl::ut_then{} = [&test]() {
                    bsl::ut_check(test.success());
                    bsl::ut_check(test.errc() == bsl::errc_success);
                };
            };
        };

        bsl::ut_scenario{"make move t"} = []() {
            bsl::ut_given{} = []() {
                bool val{true};
                bsl::result<bool> const test{bsl::move(val)};
                bsl::ut_then{} = [&test]() {
                    bsl::ut_check(test.success());
                    bsl::ut_check(test.errc() == bsl::errc_success);
                };
            };
        };

        bsl::ut_scenario{"make in place"} = []() {
            bsl::ut_given{} = []() {
                bsl::result<bool> const test{bsl::in_place, true};
                bsl::ut_then{} = [&test]() {
                    bsl::ut_check(test.success());
                    bsl::ut_check(test.errc() == bsl::errc_success);
                };
            };
        };

        bsl::ut_scenario{"make copy errc"} = []() {
            bsl::ut_given{} = []() {
                bsl::errc_type const myerror{42};
                bsl::result<bool> const test{myerror};
                bsl::ut_then{} = [&test, &myerror]() {
                    bsl::ut_check(test.failure());
                    bsl::ut_check(test.errc() == myerror);
                };
            };
        };

        bsl::ut_scenario{"make move errc"} = []() {
            bsl::ut_given{} = []() {
                bsl::errc_type myerror{42};
                bsl::result<bool> const test{bsl::move(myerror)};
                bsl::ut_then{} = [&test, &myerror]() {
                    bsl::ut_check(test.failure());
                    bsl::ut_check(test.errc() == myerror);
                };
            };
        };

        bsl::ut_scenario{"copy with t"} = []() {
            bsl::ut_given{} = []() {
                bsl::result<bool> const test1{bsl::in_place, true};
                bsl::result<bool> const test2{test1};
                bsl::ut_then{} = [&test1, &test2]() {
                    bsl::ut_check(test1.success());
                    bsl::ut_check(test2.success());
                };
            };
        };

        bsl::ut_scenario{"copy with errc"} = []() {
            bsl::ut_given{} = []() {
                bsl::result<bool> const test1{bsl::errc_failure};
                bsl::result<bool> const test2{test1};
                bsl::ut_then{} = [&test1, &test2]() {
                    bsl::ut_check(test1.failure());
                    bsl::ut_check(test2.failure());
                };
            };
        };

        bsl::ut_scenario{"move with t"} = []() {
            bsl::ut_given{} = []() {
                bsl::result<bool> test1{bsl::in_place, true};
                bsl::result<bool> const test2{bsl::move(test1)};
                bsl::ut_then{} = [&test2]() {
                    bsl::ut_check(test2.success());
                };
            };
        };

        bsl::ut_scenario{"move with errc"} = []() {
            bsl::ut_given{} = []() {
                bsl::result<bool> test1{bsl::errc_failure};
                bsl::result<bool> const test2{bsl::move(test1)};
                bsl::ut_then{} = [&test2]() {
                    bsl::ut_check(test2.failure());
                };
            };
        };

        bsl::ut_scenario{"copy assignment with t"} = []() {
            bsl::ut_given{} = []() {
                bsl::result<bool> const test1{bsl::in_place, true};
                bsl::result<bool> test2{bsl::in_place, true};
                bsl::ut_when{} = [&test1, &test2]() {
                    test2 = test1;
                    bsl::ut_then{} = [&test1, &test2]() {
                        bsl::ut_check(test1.success());
                        bsl::ut_check(test2.success());
                    };
                };
            };
        };

        bsl::ut_scenario{"move assignment with t"} = []() {
            bsl::ut_given{} = []() {
                bsl::result<bool> test1{bsl::in_place, true};
                bsl::result<bool> test2{bsl::in_place, true};
                bsl::ut_when{} = [&test1, &test2]() {
                    test2 = bsl::move(test1);
                    bsl::ut_then{} = [&test1, &test2]() {
                        bsl::ut_check(test1.success());
                        bsl::ut_check(test2.success());
                    };
                };
            };
        };

        bsl::ut_scenario{"copy assignment with e"} = []() {
            bsl::ut_given{} = []() {
                bsl::result<bool> const test1{bsl::errc_failure};
                bsl::result<bool> test2{bsl::errc_failure};
                bsl::ut_when{} = [&test1, &test2]() {
                    test2 = test1;
                    bsl::ut_then{} = [&test1, &test2]() {
                        bsl::ut_check(test1.failure());
                        bsl::ut_check(test2.failure());
                    };
                };
            };
        };

        bsl::ut_scenario{"move assignment with e"} = []() {
            bsl::ut_given{} = []() {
                bsl::result<bool> test1{bsl::errc_failure};
                bsl::result<bool> test2{bsl::errc_failure};
                bsl::ut_when{} = [&test1, &test2]() {
                    test2 = bsl::move(test1);
                    bsl::ut_then{} = [&test1, &test2]() {
                        bsl::ut_check(test1.failure());
                        bsl::ut_check(test2.failure());
                    };
                };
            };
        };

        bsl::ut_scenario{"copy assignment with t/e"} = []() {
            bsl::ut_given{} = []() {
                bsl::result<bool> const test1{bsl::in_place, true};
                bsl::result<bool> test2{bsl::errc_failure};
                bsl::ut_when{} = [&test1, &test2]() {
                    test2 = test1;
                    bsl::ut_then{} = [&test1, &test2]() {
                        bsl::ut_check(test1.success());
                        bsl::ut_check(test2.success());
                    };
                };
            };
        };

        bsl::ut_scenario{"copy assignment with e/t"} = []() {
            bsl::ut_given{} = []() {
                bsl::result<bool> const test1{bsl::errc_failure};
                bsl::result<bool> test2{bsl::in_place, true};
                bsl::ut_when{} = [&test1, &test2]() {
                    test2 = test1;
                    bsl::ut_then{} = [&test1, &test2]() {
                        bsl::ut_check(test1.failure());
                        bsl::ut_check(test2.failure());
                    };
                };
            };
        };

        bsl::ut_scenario{"move assignment with t/e"} = []() {
            bsl::ut_given{} = []() {
                bsl::result<bool> test1{bsl::in_place, true};
                bsl::result<bool> test2{bsl::errc_failure};
                bsl::ut_when{} = [&test1, &test2]() {
                    test2 = bsl::move(test1);
                    bsl::ut_then{} = [&test1, &test2]() {
                        bsl::ut_check(test1.success());
                        bsl::ut_check(test2.success());
                    };
                };
            };
        };

        bsl::ut_scenario{"move assignment with e/t"} = []() {
            bsl::ut_given{} = []() {
                bsl::result<bool> test1{bsl::errc_failure};
                bsl::result<bool> test2{bsl::in_place, true};
                bsl::ut_when{} = [&test1, &test2]() {
                    test2 = bsl::move(test1);
                    bsl::ut_then{} = [&test1, &test2]() {
                        bsl::ut_check(test1.failure());
                        bsl::ut_check(test2.failure());
                    };
                };
            };
        };

        bsl::ut_scenario{"equality success"} = []() {
            bsl::ut_given{} = []() {
                bsl::result<bool> test1{bsl::in_place, true};
                bsl::result<bool> test2{bsl::in_place, true};
                bsl::ut_then{} = [&test1, &test2]() {
                    bsl::ut_check(test1 == test2);
                };
            };
        };

        bsl::ut_scenario{"equality success and failure"} = []() {
            bsl::ut_given{} = []() {
                bsl::result<bool> test1{bsl::in_place, true};
                bsl::result<bool> test2{bsl::errc_failure};
                bsl::ut_then{} = [&test1, &test2]() {
                    bsl::ut_check(test1 != test2);
                };
            };

            bsl::ut_given{} = []() {
                bsl::result<bool> test1{bsl::errc_failure};
                bsl::result<bool> test2{bsl::in_place, true};
                bsl::ut_then{} = [&test1, &test2]() {
                    bsl::ut_check(test1 != test2);
                };
            };
        };

        bsl::ut_scenario{"equality failure"} = []() {
            bsl::ut_given{} = []() {
                bsl::result<bool> test1{bsl::errc_failure};
                bsl::result<bool> test2{bsl::errc_failure};
                bsl::ut_then{} = [&test1, &test2]() {
                    bsl::ut_check(test1 == test2);
                };
            };
        };

        bsl::ut_scenario{"not equal"} = []() {
            bsl::ut_given{} = []() {
                bsl::result<bool> test1{bsl::in_place, true};
                bsl::result<bool> test2{bsl::in_place, false};
                bsl::ut_then{} = [&test1, &test2]() {
                    bsl::ut_check(test1 != test2);
                };
            };

            bsl::ut_given{} = []() {
                bsl::result<bool> test1{bsl::errc_failure};
                bsl::result<bool> test2{bsl::errc_nullptr_dereference};
                bsl::ut_then{} = [&test1, &test2]() {
                    bsl::ut_check(test1 != test2);
                };
            };
        };

        bsl::ut_scenario{"get_if"} = []() {
            bsl::ut_given{} = []() {
                bsl::result<bool> test{bsl::in_place, true};
                bsl::ut_then{} = [&test]() {
                    bsl::ut_check(test.get_if() != nullptr);
                    bsl::ut_check(*test.get_if());
                };
            };

            bsl::ut_given{} = []() {
                bsl::result<bool> test{bsl::errc_failure};
                bsl::ut_then{} = [&test]() {
                    bsl::ut_check(test.get_if() == nullptr);
                };
            };

            bsl::ut_given{} = []() {
                bsl::result<bool> const test{bsl::in_place, true};
                bsl::ut_then{} = [&test]() {
                    bsl::ut_check(test.get_if() != nullptr);
                    bsl::ut_check(*test.get_if());
                };
            };

            bsl::ut_given{} = []() {
                bsl::result<bool> const test{bsl::errc_failure};
                bsl::ut_then{} = [&test]() {
                    bsl::ut_check(test.get_if() == nullptr);
                };
            };
        };

        bsl::ut_scenario{"errc"} = []() {
            bsl::ut_given{} = []() {
                bsl::result<bool> const test{bsl::in_place, true};
                bsl::ut_then{} = [&test]() {
                    bsl::ut_check(test.errc() == bsl::errc_success);
                };
            };

            bsl::ut_given{} = []() {
                bsl::result<bool> const test{bsl::errc_failure};
                bsl::ut_then{} = [&test]() {
                    bsl::ut_check(test.errc() == bsl::errc_failure);
                };
            };
        };

        bsl::ut_scenario{"operator bool"} = []() {
            bsl::ut_given{} = []() {
                bsl::result<bool> const test{bsl::in_place, true};
                bsl::ut_then{} = [&test]() {
                    bsl::ut_check(!!test);
                };
            };

            bsl::ut_given{} = []() {
                bsl::result<bool> const test{bsl::errc_failure};
                bsl::ut_then{} = [&test]() {
                    bsl::ut_check(!test);
                };
            };
        };

        bsl::ut_scenario{"success"} = []() {
            bsl::ut_given{} = []() {
                bsl::result<bool> const test{bsl::in_place, true};
                bsl::ut_then{} = [&test]() {
                    bsl::ut_check(test.success());
                };
            };

            bsl::ut_given{} = []() {
                bsl::result<bool> const test{bsl::errc_failure};
                bsl::ut_then{} = [&test]() {
                    bsl::ut_check(!test.success());
                };
            };
        };

        bsl::ut_scenario{"failure"} = []() {
            bsl::ut_given{} = []() {
                bsl::result<bool> const test{bsl::in_place, true};
                bsl::ut_then{} = [&test]() {
                    bsl::ut_check(!test.failure());
                };
            };

            bsl::ut_given{} = []() {
                bsl::result<bool> const test{bsl::errc_failure};
                bsl::ut_then{} = [&test]() {
                    bsl::ut_check(test.failure());
                };
            };
        };

        bsl::ut_scenario{"output doesn't crash"} = []() {
            bsl::ut_given{} = []() {
                bsl::result<bool> const test{bsl::in_place, true};
                bsl::ut_then{} = [&test]() {
                    bsl::debug() << test << '\n';
                };
            };

            bsl::ut_given{} = []() {
                bsl::result<bool> const test{bsl::errc_failure};
                bsl::ut_then{} = [&test]() {
                    bsl::debug() << test << '\n';
                };
            };
        };

        return bsl::ut_success();
    }
}

/// <!-- description -->
///   @brief Main function for this unit test. If a call to bsl::ut_check() fails
///     the application will fast fail. If all calls to bsl::ut_check() pass, this
///     function will successfully return with bsl::exit_success.
///
/// <!-- inputs/outputs -->
///   @return Always returns bsl::exit_success.
///
[[nodiscard]] auto
main() noexcept -> bsl::exit_code
{
    static_assert(tests() == bsl::ut_success());
    return tests();
}
