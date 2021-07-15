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
            bsl::ut_then{} = []() noexcept {
                static_assert(noexcept(bsl::convert<bsl::int32>(0)));
                static_assert(noexcept(bsl::convert<bsl::int32>(bsl::safe_int32{})));
                static_assert(noexcept(bsl::to_i8(0)));
                static_assert(noexcept(bsl::to_i8(bsl::safe_int32{})));
                static_assert(noexcept(bsl::to_i16(0)));
                static_assert(noexcept(bsl::to_i16(bsl::safe_int32{})));
                static_assert(noexcept(bsl::to_i32(0)));
                static_assert(noexcept(bsl::to_i32(bsl::safe_int32{})));
                static_assert(noexcept(bsl::to_i64(0)));
                static_assert(noexcept(bsl::to_i64(bsl::safe_int32{})));
                static_assert(noexcept(bsl::to_imax(0)));
                static_assert(noexcept(bsl::to_imax(bsl::safe_int32{})));
                static_assert(noexcept(bsl::to_u8(0)));
                static_assert(noexcept(bsl::to_u8(bsl::safe_int32{})));
                static_assert(noexcept(bsl::to_u8_unsafe(0)));
                static_assert(noexcept(bsl::to_u8_unsafe(bsl::safe_int32{})));
                static_assert(noexcept(bsl::to_u16(0)));
                static_assert(noexcept(bsl::to_u16(bsl::safe_int32{})));
                static_assert(noexcept(bsl::to_u16_unsafe(0)));
                static_assert(noexcept(bsl::to_u16_unsafe(bsl::safe_int32{})));
                static_assert(noexcept(bsl::to_u32(0)));
                static_assert(noexcept(bsl::to_u32(bsl::safe_int32{})));
                static_assert(noexcept(bsl::to_u32_unsafe(0)));
                static_assert(noexcept(bsl::to_u32_unsafe(bsl::safe_int32{})));
                static_assert(noexcept(bsl::to_u64(0)));
                static_assert(noexcept(bsl::to_u64(bsl::safe_int32{})));
                static_assert(noexcept(bsl::to_u64_unsafe(0)));
                static_assert(noexcept(bsl::to_u64_unsafe(bsl::safe_int32{})));
                static_assert(noexcept(bsl::to_umax(0)));
                static_assert(noexcept(bsl::to_umax(bsl::safe_int32{})));
                static_assert(noexcept(bsl::to_umax_unsafe(0)));
                static_assert(noexcept(bsl::to_umax_unsafe(bsl::safe_int32{})));
            };
        };
    };

    return bsl::ut_success();
}
