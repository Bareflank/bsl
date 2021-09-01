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
#include <bsl/discard.hpp>
#include <bsl/ut.hpp>

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
    bsl::ut_scenario{"verify noexcept"} = []() noexcept {
        bsl::ut_given{} = []() noexcept {
            bsl::carray const argv{test::CARRAY_INIT_STR_ARGS_POS};
            bsl::arguments mut_args{bsl::to_umx(argv.size()), argv.data()};
            bsl::arguments const args{bsl::to_umx(argv.size()), argv.data()};
            bsl::ut_then{} = []() noexcept {
                static_assert(noexcept(bsl::arguments{bsl::to_umx(argv.size()), argv.data()}));

                static_assert(noexcept(mut_args.args()));
                static_assert(noexcept(mut_args.index()));
                static_assert(noexcept(mut_args.get<bool>(bsl::to_umx(0))));
                static_assert(noexcept(mut_args.get<bsl::string_view>(bsl::to_umx(0))));
                static_assert(noexcept(mut_args.get<bsl::safe_i8>(bsl::to_umx(0))));
                static_assert(noexcept(mut_args.get<bsl::safe_i16>(bsl::to_umx(0))));
                static_assert(noexcept(mut_args.get<bsl::safe_i32>(bsl::to_umx(0))));
                static_assert(noexcept(mut_args.get<bsl::safe_i64>(bsl::to_umx(0))));
                static_assert(noexcept(mut_args.get<bsl::safe_u8>(bsl::to_umx(0))));
                static_assert(noexcept(mut_args.get<bsl::safe_u16>(bsl::to_umx(0))));
                static_assert(noexcept(mut_args.get<bsl::safe_u32>(bsl::to_umx(0))));
                static_assert(noexcept(mut_args.get<bsl::safe_u64>(bsl::to_umx(0))));
                static_assert(noexcept(mut_args.get<bool>("")));
                static_assert(noexcept(mut_args.get<bsl::string_view>("")));
                static_assert(noexcept(mut_args.get<bsl::safe_i8>("")));
                static_assert(noexcept(mut_args.get<bsl::safe_i16>("")));
                static_assert(noexcept(mut_args.get<bsl::safe_i32>("")));
                static_assert(noexcept(mut_args.get<bsl::safe_i64>("")));
                static_assert(noexcept(mut_args.get<bsl::safe_u8>("")));
                static_assert(noexcept(mut_args.get<bsl::safe_u16>("")));
                static_assert(noexcept(mut_args.get<bsl::safe_u32>("")));
                static_assert(noexcept(mut_args.get<bsl::safe_u64>("")));
                static_assert(noexcept(mut_args.at<bool>(bsl::to_umx(0))));
                static_assert(noexcept(mut_args.at<bsl::string_view>(bsl::to_umx(0))));
                static_assert(noexcept(mut_args.at<bsl::safe_i8>(bsl::to_umx(0))));
                static_assert(noexcept(mut_args.at<bsl::safe_i16>(bsl::to_umx(0))));
                static_assert(noexcept(mut_args.at<bsl::safe_i32>(bsl::to_umx(0))));
                static_assert(noexcept(mut_args.at<bsl::safe_i64>(bsl::to_umx(0))));
                static_assert(noexcept(mut_args.at<bsl::safe_u8>(bsl::to_umx(0))));
                static_assert(noexcept(mut_args.at<bsl::safe_u16>(bsl::to_umx(0))));
                static_assert(noexcept(mut_args.at<bsl::safe_u32>(bsl::to_umx(0))));
                static_assert(noexcept(mut_args.at<bsl::safe_u64>(bsl::to_umx(0))));
                static_assert(noexcept(mut_args.front<bool>()));
                static_assert(noexcept(mut_args.front<bsl::string_view>()));
                static_assert(noexcept(mut_args.front<bsl::safe_i8>()));
                static_assert(noexcept(mut_args.front<bsl::safe_i16>()));
                static_assert(noexcept(mut_args.front<bsl::safe_i32>()));
                static_assert(noexcept(mut_args.front<bsl::safe_i64>()));
                static_assert(noexcept(mut_args.front<bsl::safe_u8>()));
                static_assert(noexcept(mut_args.front<bsl::safe_u16>()));
                static_assert(noexcept(mut_args.front<bsl::safe_u32>()));
                static_assert(noexcept(mut_args.front<bsl::safe_u64>()));
                static_assert(noexcept(mut_args.empty()));
                static_assert(noexcept(mut_args.size()));
                static_assert(noexcept(mut_args.remaining()));
                static_assert(noexcept(++mut_args));

                static_assert(noexcept(args.args()));
                static_assert(noexcept(args.index()));
                static_assert(noexcept(args.get<bool>(bsl::to_umx(0))));
                static_assert(noexcept(args.get<bsl::string_view>(bsl::to_umx(0))));
                static_assert(noexcept(args.get<bsl::safe_i8>(bsl::to_umx(0))));
                static_assert(noexcept(args.get<bsl::safe_i16>(bsl::to_umx(0))));
                static_assert(noexcept(args.get<bsl::safe_i32>(bsl::to_umx(0))));
                static_assert(noexcept(args.get<bsl::safe_i64>(bsl::to_umx(0))));
                static_assert(noexcept(args.get<bsl::safe_u8>(bsl::to_umx(0))));
                static_assert(noexcept(args.get<bsl::safe_u16>(bsl::to_umx(0))));
                static_assert(noexcept(args.get<bsl::safe_u32>(bsl::to_umx(0))));
                static_assert(noexcept(args.get<bsl::safe_u64>(bsl::to_umx(0))));
                static_assert(noexcept(args.get<bool>("")));
                static_assert(noexcept(args.get<bsl::string_view>("")));
                static_assert(noexcept(args.get<bsl::safe_i8>("")));
                static_assert(noexcept(args.get<bsl::safe_i16>("")));
                static_assert(noexcept(args.get<bsl::safe_i32>("")));
                static_assert(noexcept(args.get<bsl::safe_i64>("")));
                static_assert(noexcept(args.get<bsl::safe_u8>("")));
                static_assert(noexcept(args.get<bsl::safe_u16>("")));
                static_assert(noexcept(args.get<bsl::safe_u32>("")));
                static_assert(noexcept(args.get<bsl::safe_u64>("")));
                static_assert(noexcept(args.at<bool>(bsl::to_umx(0))));
                static_assert(noexcept(args.at<bsl::string_view>(bsl::to_umx(0))));
                static_assert(noexcept(args.at<bsl::safe_i8>(bsl::to_umx(0))));
                static_assert(noexcept(args.at<bsl::safe_i16>(bsl::to_umx(0))));
                static_assert(noexcept(args.at<bsl::safe_i32>(bsl::to_umx(0))));
                static_assert(noexcept(args.at<bsl::safe_i64>(bsl::to_umx(0))));
                static_assert(noexcept(args.at<bsl::safe_u8>(bsl::to_umx(0))));
                static_assert(noexcept(args.at<bsl::safe_u16>(bsl::to_umx(0))));
                static_assert(noexcept(args.at<bsl::safe_u32>(bsl::to_umx(0))));
                static_assert(noexcept(args.at<bsl::safe_u64>(bsl::to_umx(0))));
                static_assert(noexcept(args.front<bool>()));
                static_assert(noexcept(args.front<bsl::string_view>()));
                static_assert(noexcept(args.front<bsl::safe_i8>()));
                static_assert(noexcept(args.front<bsl::safe_i16>()));
                static_assert(noexcept(args.front<bsl::safe_i32>()));
                static_assert(noexcept(args.front<bsl::safe_i64>()));
                static_assert(noexcept(args.front<bsl::safe_u8>()));
                static_assert(noexcept(args.front<bsl::safe_u16>()));
                static_assert(noexcept(args.front<bsl::safe_u32>()));
                static_assert(noexcept(args.front<bsl::safe_u64>()));
                static_assert(noexcept(args.empty()));
                static_assert(noexcept(args.size()));
                static_assert(noexcept(args.remaining()));
            };
        };
    };

    return bsl::ut_success();
}
