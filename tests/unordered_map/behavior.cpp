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

#include <bsl/add_const.hpp>
#include <bsl/as_const.hpp>
#include <bsl/convert.hpp>
#include <bsl/move.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/unordered_map.hpp>
#include <bsl/ut.hpp>

#pragma clang diagnostic ignored "-Wself-assign-overloaded"

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
        bsl::ut_scenario{"empty"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::unordered_map<bool, bool> mut_map{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(bsl::as_const(mut_map).empty());
                    };

                    mut_map.at(true) = true;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!bsl::as_const(mut_map).empty());
                    };

                    mut_map.at(false) = true;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!bsl::as_const(mut_map).empty());
                    };

                    mut_map.clear();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(bsl::as_const(mut_map).empty());
                    };
                };
            };
        };

        bsl::ut_scenario{"size"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::unordered_map<bool, bool> mut_map{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(bsl::as_const(mut_map).size().is_zero());
                    };

                    mut_map.at(true) = true;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(bsl::as_const(mut_map).size() == 1_umx);
                    };

                    mut_map.at(false) = true;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(bsl::as_const(mut_map).size() == 2_umx);
                    };

                    mut_map.clear();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(bsl::as_const(mut_map).size().is_zero());
                    };
                };
            };
        };

        bsl::ut_scenario{"clear"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::unordered_map<bool, bool> mut_map{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!bsl::as_const(mut_map).at(true));
                    };

                    mut_map.clear();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!bsl::as_const(mut_map).at(true));
                    };

                    mut_map.at(true) = true;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(bsl::as_const(mut_map).at(true));
                    };

                    mut_map.at(true) = true;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(bsl::as_const(mut_map).at(true));
                    };

                    mut_map.clear();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!bsl::as_const(mut_map).at(true));
                    };

                    mut_map.clear();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!bsl::as_const(mut_map).at(true));
                    };
                };
            };
        };

        bsl::ut_scenario{"at"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::unordered_map<bool, bool> mut_map{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_map.at(true));
                        bsl::ut_check(!bsl::as_const(mut_map).at(true));
                    };

                    mut_map.at(true) = true;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_map.at(true));
                        bsl::ut_check(bsl::as_const(mut_map).at(true));
                    };

                    mut_map.at(false) = true;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_map.at(false));
                        bsl::ut_check(bsl::as_const(mut_map).at(false));
                    };

                    mut_map.at(true) = false;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_map.at(true));
                        bsl::ut_check(!bsl::as_const(mut_map).at(true));
                    };

                    mut_map.at(true) = true;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_map.at(true));
                        bsl::ut_check(bsl::as_const(mut_map).at(true));
                    };

                    mut_map.clear();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_map.at(true));
                        bsl::ut_check(!bsl::as_const(mut_map).at(true));
                    };
                };
            };
        };

        bsl::ut_scenario{"contains"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::unordered_map<bool, bool> mut_map{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!bsl::as_const(mut_map).contains(true));
                        bsl::ut_check(!bsl::as_const(mut_map).contains(false));
                    };

                    mut_map.at(true) = true;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(bsl::as_const(mut_map).contains(true));
                        bsl::ut_check(!bsl::as_const(mut_map).contains(false));
                    };

                    mut_map.at(false) = true;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(bsl::as_const(mut_map).contains(true));
                        bsl::ut_check(bsl::as_const(mut_map).contains(false));
                    };

                    mut_map.clear();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!bsl::as_const(mut_map).contains(true));
                        bsl::ut_check(!bsl::as_const(mut_map).contains(false));
                    };
                };
            };
        };

        bsl::ut_scenario{"copy"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::unordered_map<bool, bool> mut_map1{};
                bsl::unordered_map<bool, bool> mut_map2{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_map1.at(true) = true;
                    mut_map2 = mut_map1;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_map1.at(true));
                        bsl::ut_check(mut_map2.at(true));
                    };

                    mut_map1.at(false) = true;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_map1.at(false));
                        bsl::ut_check(!mut_map2.at(false));
                    };

                    mut_map1 = mut_map1;
                };
            };
        };

        bsl::ut_scenario{"move"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::unordered_map<bool, bool> mut_map1{};
                bsl::unordered_map<bool, bool> mut_map2{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_map1.at(true) = true;
                    mut_map2 = bsl::move(mut_map1);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!mut_map1.at(true));
                        bsl::ut_check(mut_map2.at(true));
                    };

                    mut_map1.at(false) = true;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_map1.at(false));
                        bsl::ut_check(!mut_map2.at(false));
                    };

                    mut_map2 = bsl::move(mut_map2);
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
