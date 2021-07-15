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

#include <bsl/convert.hpp>
#include <bsl/reference_wrapper.hpp>
#include <bsl/ut.hpp>

// TODO: Remove the  from this test so that we can provide a pointer
//       to a function for the reference wrapper.

namespace
{
    [[nodiscard]] constexpr auto
    func(bsl::safe_int32 const val) noexcept -> bsl::safe_int32
    {
        return val;
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
    [[nodiscard]] constexpr auto
    tests() noexcept -> bsl::exit_code
    {
        bsl::ut_scenario{"constructor / get"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_int32 mut_data{};
                bsl::reference_wrapper mut_rw{mut_data};
                bsl::ut_when{} = [&]() noexcept {
                    mut_rw.get() = 42;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_rw.get() == 42);
                    };
                };
            };
        };

        bsl::ut_scenario{"const constructor / get"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_int32 const data{42};
                bsl::reference_wrapper mut_rw{data};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_rw.get() == 42);
                };
            };
        };

        bsl::ut_scenario{"invoke"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                // BUG: Need to figure out why we cannot use & here
                // NOLINTNEXTLINE(bsl-function-name-use)
                bsl::reference_wrapper mut_rw{func};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_rw(bsl::to_i32(42)) == 42);
                };
            };
        };

        bsl::ut_scenario{"bsl::ref"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_int32 mut_data{};
                bsl::reference_wrapper mut_rw{bsl::ref(mut_data)};
                bsl::ut_when{} = [&]() noexcept {
                    mut_rw.get() = 42;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_rw.get() == 42);
                    };
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_int32 mut_data{};
                bsl::reference_wrapper mut_rw1{bsl::ref(mut_data)};
                bsl::reference_wrapper mut_rw2{bsl::ref(mut_rw1)};
                bsl::ut_when{} = [&]() noexcept {
                    mut_rw2.get() = 42;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_rw2.get() == 42);
                    };
                };
            };
        };

        bsl::ut_scenario{"bsl::cref"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_int32 const data{42};
                bsl::reference_wrapper mut_rw{bsl::cref(data)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_rw.get() == 42);
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_int32 const data{42};
                bsl::reference_wrapper mut_rw1{bsl::cref(data)};
                bsl::reference_wrapper mut_rw2{bsl::cref(mut_rw1)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_rw2.get() == 42);
                };
            };
        };

        bsl::ut_scenario{"output doesn't crash"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_int32 const data{42};
                bsl::reference_wrapper mut_rw{data};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::debug() << mut_rw << '\n';
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
