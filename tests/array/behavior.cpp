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
#include <bsl/convert.hpp>
#include <bsl/npos.hpp>
#include <bsl/ut.hpp>

namespace
{
    constexpr bsl::array TEST_INIT{
        bsl::to_i32(4),
        bsl::to_i32(8),
        bsl::to_i32(15),
        bsl::to_i32(16),
        bsl::to_i32(23),
        bsl::to_i32(42)};

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
        bsl::ut_scenario{"at_if"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::array mut_arr{TEST_INIT};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(*mut_arr.at_if(bsl::to_umax(0)) == bsl::to_i32(4));
                    bsl::ut_check(*mut_arr.at_if(bsl::to_umax(1)) == bsl::to_i32(8));
                    bsl::ut_check(*mut_arr.at_if(bsl::to_umax(2)) == bsl::to_i32(15));
                    bsl::ut_check(*mut_arr.at_if(bsl::to_umax(3)) == bsl::to_i32(16));
                    bsl::ut_check(*mut_arr.at_if(bsl::to_umax(4)) == bsl::to_i32(23));
                    bsl::ut_check(*mut_arr.at_if(bsl::to_umax(5)) == bsl::to_i32(42));
                    bsl::ut_check(mut_arr.at_if(bsl::to_umax(6)) == nullptr);
                    bsl::ut_check(mut_arr.at_if(bsl::npos) == nullptr);
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::array mut_arr{TEST_INIT};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_arr.at_if(bsl::safe_uintmax::failure()) == nullptr);
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::array const arr{TEST_INIT};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(*arr.at_if(bsl::to_umax(0)) == bsl::to_i32(4));
                    bsl::ut_check(*arr.at_if(bsl::to_umax(1)) == bsl::to_i32(8));
                    bsl::ut_check(*arr.at_if(bsl::to_umax(2)) == bsl::to_i32(15));
                    bsl::ut_check(*arr.at_if(bsl::to_umax(3)) == bsl::to_i32(16));
                    bsl::ut_check(*arr.at_if(bsl::to_umax(4)) == bsl::to_i32(23));
                    bsl::ut_check(*arr.at_if(bsl::to_umax(5)) == bsl::to_i32(42));
                    bsl::ut_check(arr.at_if(bsl::to_umax(6)) == nullptr);
                    bsl::ut_check(arr.at_if(bsl::npos) == nullptr);
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::array const arr{TEST_INIT};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(arr.at_if(bsl::safe_uintmax::failure()) == nullptr);
                };
            };
        };

        bsl::ut_scenario{"front"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::array mut_arr{TEST_INIT};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_arr.front() == bsl::to_i32(4));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::array const arr{TEST_INIT};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(arr.front() == bsl::to_i32(4));
                };
            };
        };

        bsl::ut_scenario{"front_if"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::array mut_arr{TEST_INIT};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(*mut_arr.front_if() == bsl::to_i32(4));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::array const arr{TEST_INIT};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(*arr.front_if() == bsl::to_i32(4));
                };
            };
        };

        bsl::ut_scenario{"back"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::array mut_arr{TEST_INIT};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_arr.back() == bsl::to_i32(42));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::array const arr{TEST_INIT};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(arr.back() == bsl::to_i32(42));
                };
            };
        };

        bsl::ut_scenario{"back_if"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::array mut_arr{TEST_INIT};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(*mut_arr.back_if() == bsl::to_i32(42));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::array const arr{TEST_INIT};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(*arr.back_if() == bsl::to_i32(42));
                };
            };
        };

        bsl::ut_scenario{"data"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::array mut_arr{TEST_INIT};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_arr.data() != nullptr);
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::array const arr{TEST_INIT};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(arr.data() != nullptr);
                };
            };
        };

        bsl::ut_scenario{"begin"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::array mut_arr{TEST_INIT};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(*(mut_arr.begin().get_if()) == bsl::to_i32(4));
                    bsl::ut_check(mut_arr.begin().index() == bsl::to_umax(0));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::array const arr{TEST_INIT};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(*(arr.begin().get_if()) == bsl::to_i32(4));
                    bsl::ut_check(arr.begin().index() == bsl::to_umax(0));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::array const arr{TEST_INIT};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(*(arr.cbegin().get_if()) == bsl::to_i32(4));
                    bsl::ut_check(arr.cbegin().index() == bsl::to_umax(0));
                };
            };
        };

        bsl::ut_scenario{"end"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::array mut_arr{TEST_INIT};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_arr.end().index() == mut_arr.size());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::array mut_arr{TEST_INIT};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_arr.end().get_if() == nullptr);
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::array const arr{TEST_INIT};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(arr.end().index() == arr.size());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::array const arr{TEST_INIT};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(arr.end().get_if() == nullptr);
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::array const arr{TEST_INIT};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(arr.cend().index() == arr.size());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::array const arr{TEST_INIT};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(arr.cend().get_if() == nullptr);
                };
            };
        };

        bsl::ut_scenario{"iter"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::array mut_arr{TEST_INIT};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(*(mut_arr.iter(bsl::to_umax(1)).get_if()) == bsl::to_i32(8));
                    bsl::ut_check(mut_arr.iter(bsl::to_umax(1)).index() == bsl::to_umax(1));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::array const arr{TEST_INIT};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(*(arr.iter(bsl::to_umax(1)).get_if()) == bsl::to_i32(8));
                    bsl::ut_check(arr.iter(bsl::to_umax(1)).index() == bsl::to_umax(1));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::array const arr{TEST_INIT};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(*(arr.citer(bsl::to_umax(1)).get_if()) == bsl::to_i32(8));
                    bsl::ut_check(arr.citer(bsl::to_umax(1)).index() == bsl::to_umax(1));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::array mut_arr{TEST_INIT};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_arr.iter(bsl::npos).get_if() == nullptr);
                    bsl::ut_check(mut_arr.iter(bsl::npos).index() == mut_arr.size());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::array const arr{TEST_INIT};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(arr.iter(bsl::npos).get_if() == nullptr);
                    bsl::ut_check(arr.iter(bsl::npos).index() == arr.size());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::array const arr{TEST_INIT};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(arr.citer(bsl::npos).get_if() == nullptr);
                    bsl::ut_check(arr.citer(bsl::npos).index() == arr.size());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::array mut_arr{TEST_INIT};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_arr.iter(bsl::safe_uintmax::failure()).get_if() == nullptr);
                    bsl::ut_check(
                        mut_arr.iter(bsl::safe_uintmax::failure()).index() == mut_arr.size());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::array const arr{TEST_INIT};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(arr.iter(bsl::safe_uintmax::failure()).get_if() == nullptr);
                    bsl::ut_check(arr.iter(bsl::safe_uintmax::failure()).index() == arr.size());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::array const arr{TEST_INIT};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(arr.citer(bsl::safe_uintmax::failure()).get_if() == nullptr);
                    bsl::ut_check(arr.citer(bsl::safe_uintmax::failure()).index() == arr.size());
                };
            };
        };

        bsl::ut_scenario{"rbegin"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::array mut_arr{TEST_INIT};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(*(mut_arr.rbegin().get_if()) == bsl::to_i32(42));
                    bsl::ut_check(mut_arr.rbegin().index() == bsl::to_umax(5));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::array const arr{TEST_INIT};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(*(arr.rbegin().get_if()) == bsl::to_i32(42));
                    bsl::ut_check(arr.rbegin().index() == bsl::to_umax(5));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::array const arr{TEST_INIT};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(*(arr.crbegin().get_if()) == bsl::to_i32(42));
                    bsl::ut_check(arr.crbegin().index() == bsl::to_umax(5));
                };
            };
        };

        bsl::ut_scenario{"rend"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::array mut_arr{TEST_INIT};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_arr.rend().index() == mut_arr.size());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::array mut_arr{TEST_INIT};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_arr.rend().get_if() == nullptr);
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::array const arr{TEST_INIT};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(arr.rend().index() == arr.size());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::array const arr{TEST_INIT};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(arr.rend().get_if() == nullptr);
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::array const arr{TEST_INIT};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(arr.crend().index() == arr.size());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::array const arr{TEST_INIT};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(arr.crend().get_if() == nullptr);
                };
            };
        };

        bsl::ut_scenario{"riter"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::array mut_arr{TEST_INIT};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(*(mut_arr.riter(bsl::to_umax(1)).get_if()) == bsl::to_i32(8));
                    bsl::ut_check(mut_arr.riter(bsl::to_umax(1)).index() == bsl::to_umax(1));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::array const arr{TEST_INIT};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(*(arr.riter(bsl::to_umax(1)).get_if()) == bsl::to_i32(8));
                    bsl::ut_check(arr.riter(bsl::to_umax(1)).index() == bsl::to_umax(1));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::array const arr{TEST_INIT};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(*(arr.criter(bsl::to_umax(1)).get_if()) == bsl::to_i32(8));
                    bsl::ut_check(arr.criter(bsl::to_umax(1)).index() == bsl::to_umax(1));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::array mut_arr{TEST_INIT};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_arr.riter(bsl::npos).get_if() == nullptr);
                    bsl::ut_check(mut_arr.riter(bsl::npos).index() == mut_arr.size());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::array const arr{TEST_INIT};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(arr.riter(bsl::npos).get_if() == nullptr);
                    bsl::ut_check(arr.riter(bsl::npos).index() == arr.size());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::array const arr{TEST_INIT};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(arr.criter(bsl::npos).get_if() == nullptr);
                    bsl::ut_check(arr.criter(bsl::npos).index() == arr.size());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::array mut_arr{TEST_INIT};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_arr.riter(bsl::safe_uintmax::failure()).get_if() == nullptr);
                    bsl::ut_check(
                        mut_arr.riter(bsl::safe_uintmax::failure()).index() == mut_arr.size());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::array const arr{TEST_INIT};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(arr.riter(bsl::safe_uintmax::failure()).get_if() == nullptr);
                    bsl::ut_check(arr.riter(bsl::safe_uintmax::failure()).index() == arr.size());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::array const arr{TEST_INIT};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(arr.criter(bsl::safe_uintmax::failure()).get_if() == nullptr);
                    bsl::ut_check(arr.criter(bsl::safe_uintmax::failure()).index() == arr.size());
                };
            };
        };

        bsl::ut_scenario{"empty"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::array mut_arr{TEST_INIT};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!mut_arr.empty());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::array const arr{TEST_INIT};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!arr.empty());
                };
            };
        };

        bsl::ut_scenario{"operator bool"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::array mut_arr{TEST_INIT};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!!mut_arr);
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::array const arr{TEST_INIT};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!!arr);
                };
            };
        };

        bsl::ut_scenario{"size"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::array mut_arr{TEST_INIT};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_arr.size() == bsl::to_umax(6));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::array const arr{TEST_INIT};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(arr.size() == bsl::to_umax(6));
                };
            };
        };

        bsl::ut_scenario{"max_size"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::array mut_arr{TEST_INIT};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(
                        mut_arr.max_size() == bsl::safe_uintmax::max() / sizeof(bsl::safe_int32));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::array const arr{TEST_INIT};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(
                        arr.max_size() == bsl::safe_uintmax::max() / sizeof(bsl::safe_int32));
                };
            };
        };

        bsl::ut_scenario{"size_bytes"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::array mut_arr{TEST_INIT};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_arr.size_bytes() == bsl::to_umax(6) * sizeof(bsl::uintmax));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::array const arr{TEST_INIT};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(arr.size_bytes() == bsl::to_umax(6) * sizeof(bsl::uintmax));
                };
            };
        };

        bsl::ut_scenario{"equals"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::array const arr1{TEST_INIT};
                bsl::array const arr2{TEST_INIT};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(arr1 == arr2);
                };
            };
        };

        bsl::ut_scenario{"not equals"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::array const arr1{TEST_INIT};
                bsl::array<bsl::safe_int32, TEST_INIT.size().get()> const arr2{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(arr1 != arr2);
                };
            };
        };

        bsl::ut_scenario{"output doesn't crash"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::array const arr{bsl::to_i32(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::debug() << arr << '\n';
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::array const arr{TEST_INIT};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::debug() << arr << '\n';
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
