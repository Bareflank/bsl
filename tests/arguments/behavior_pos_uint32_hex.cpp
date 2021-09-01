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

#include "../carray_init.hpp"

#include <bsl/arguments.hpp>
#include <bsl/carray.hpp>
#include <bsl/convert.hpp>
#include <bsl/cstr_type.hpp>
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
        bsl::ut_scenario{"get positional safe_u32"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::carray const argv{test::CARRAY_INIT_STR_DASH_APP};
                bsl::arguments const args{bsl::to_umx(argv.size()), argv.data()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(args.get<bsl::safe_u32, 16>(bsl::to_umx(0)).is_invalid());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::carray const argv{test::CARRAY_INIT_STR_42};
                bsl::arguments const args{bsl::to_umx(argv.size()), argv.data()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(args.get<bsl::safe_u32, 16>(bsl::to_umx(1)).is_invalid());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::carray const argv{test::CARRAY_INIT_STR_APP};
                bsl::arguments const args{bsl::to_umx(argv.size()), argv.data()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(args.get<bsl::safe_u32, 16>(bsl::to_umx(0)).is_invalid());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::carray const argv{test::CARRAY_INIT_STR_42_SPACE};
                bsl::arguments const args{bsl::to_umx(argv.size()), argv.data()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(args.get<bsl::safe_u32, 16>(bsl::to_umx(0)).is_invalid());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::carray const argv{test::CARRAY_INIT_STR_ARGS_POS};
                bsl::arguments const args{bsl::to_umx(argv.size()), argv.data()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(args.get<bsl::safe_u32, 16>(bsl::to_umx(0)) == bsl::to_u32(0x4));
                    bsl::ut_check(args.get<bsl::safe_u32, 16>(bsl::to_umx(1)) == bsl::to_u32(0x8));
                    bsl::ut_check(args.get<bsl::safe_u32, 16>(bsl::to_umx(2)) == bsl::to_u32(0x15));
                    bsl::ut_check(args.get<bsl::safe_u32, 16>(bsl::to_umx(3)) == bsl::to_u32(0x16));
                    bsl::ut_check(args.get<bsl::safe_u32, 16>(bsl::to_umx(4)) == bsl::to_u32(0x23));
                    bsl::ut_check(args.get<bsl::safe_u32, 16>(bsl::to_umx(5)) == bsl::to_u32(0x42));
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
