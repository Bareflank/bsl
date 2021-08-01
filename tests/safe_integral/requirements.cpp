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
#include <bsl/safe_integral.hpp>
#include <bsl/ut.hpp>

namespace
{
    constinit bsl::safe_i32 const g_verify_constinit{};
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
    bsl::ut_scenario{"verify supports constinit"} = []() noexcept {
        bsl::discard(g_verify_constinit);
    };

    bsl::ut_scenario{"verify noexcept"} = []() noexcept {
        bsl::ut_given{} = []() noexcept {
            auto mut_ival1{42_i32};    // NOLINT
            auto mut_ival2{42_i32};    // NOLINT
            auto mut_uval1{42_u32};    // NOLINT
            auto mut_uval2{42_u32};    // NOLINT
            constexpr auto ival1{42_i32};
            constexpr auto ival2{42_i32};
            constexpr auto uval1{42_u32};
            constexpr auto uval2{42_u32};
            bsl::ut_then{} = []() noexcept {
                static_assert(noexcept(bsl::safe_i32{}));
                static_assert(noexcept(bsl::safe_i32{42}));
                static_assert(noexcept(bsl::safe_i32{42, bsl::safe_i32{}}));
                static_assert(noexcept(bsl::safe_i32{bsl::safe_i32{}, bsl::safe_i32{}}));

                static_assert(noexcept(mut_ival1 = 42));
                static_assert(noexcept(mut_ival1.max_value()));
                static_assert(noexcept(mut_ival1.min_value()));
                static_assert(noexcept(mut_ival1.magic_neg_1()));
                static_assert(noexcept(mut_ival1.magic_neg_2()));
                static_assert(noexcept(mut_ival1.magic_neg_3()));
                static_assert(noexcept(mut_ival1.magic_0()));
                static_assert(noexcept(mut_ival1.magic_1()));
                static_assert(noexcept(mut_ival1.magic_2()));
                static_assert(noexcept(mut_ival1.magic_3()));
                static_assert(noexcept(mut_ival1.data_as_ref()));
                static_assert(noexcept(mut_ival1.data()));
                static_assert(noexcept(mut_ival1.get()));
                static_assert(noexcept(mut_ival1.is_pos()));
                static_assert(noexcept(mut_ival1.is_neg()));
                static_assert(noexcept(mut_ival1.is_zero()));
                static_assert(noexcept(mut_ival1.is_poisoned()));
                static_assert(noexcept(mut_ival1.is_invalid()));
                static_assert(noexcept(mut_ival1.is_valid()));
                static_assert(noexcept(mut_ival1.is_zero_or_poisoned()));
                static_assert(noexcept(mut_ival1.is_zero_or_invalid()));
                static_assert(noexcept(mut_ival1.checked()));
                static_assert(noexcept(mut_ival1.is_unchecked()));
                static_assert(noexcept(mut_ival1.is_checked()));
                static_assert(noexcept(mut_ival1.is_valid_and_checked()));
                static_assert(noexcept(mut_ival1.failure()));
                static_assert(noexcept(mut_ival1.max({})));
                static_assert(noexcept(mut_ival1.min({})));
                static_assert(noexcept(mut_ival1 += mut_ival2));
                static_assert(noexcept(mut_ival1 += 42));
                static_assert(noexcept(mut_ival1 -= mut_ival2));
                static_assert(noexcept(mut_ival1 -= 42));
                static_assert(noexcept(mut_ival1 *= mut_ival2));
                static_assert(noexcept(mut_ival1 *= 42));
                static_assert(noexcept(mut_ival1 /= mut_ival2));
                static_assert(noexcept(mut_ival1 /= 42));
                static_assert(noexcept(mut_ival1 %= mut_ival2));
                static_assert(noexcept(mut_ival1 %= 42));
                static_assert(noexcept(mut_uval1 <<= mut_uval2));
                static_assert(noexcept(mut_uval1 <<= 42U));
                static_assert(noexcept(mut_uval1 >>= mut_uval2));
                static_assert(noexcept(mut_uval1 >>= 42U));
                static_assert(noexcept(mut_uval1 &= mut_uval2));
                static_assert(noexcept(mut_uval1 &= 42U));
                static_assert(noexcept(mut_uval1 |= mut_uval2));
                static_assert(noexcept(mut_uval1 |= 42U));
                static_assert(noexcept(mut_uval1 ^= mut_uval2));
                static_assert(noexcept(mut_uval1 ^= 42U));
                static_assert(noexcept(++mut_ival1));
                static_assert(noexcept(--mut_ival1));
                static_assert(noexcept(mut_ival1 == mut_ival2));
                static_assert(noexcept(mut_ival1 == 42));
                static_assert(noexcept(42 == mut_ival1));
                static_assert(noexcept(mut_ival1 != mut_ival2));
                static_assert(noexcept(mut_ival1 != 42));
                static_assert(noexcept(42 != mut_ival1));
                static_assert(noexcept(mut_ival1 < mut_ival2));
                static_assert(noexcept(mut_ival1 < 42));
                static_assert(noexcept(42 < mut_ival1));
                static_assert(noexcept(mut_ival1 > mut_ival2));
                static_assert(noexcept(mut_ival1 > 42));
                static_assert(noexcept(42 > mut_ival1));
                static_assert(noexcept(mut_ival1 <= mut_ival2));
                static_assert(noexcept(mut_ival1 <= 42));
                static_assert(noexcept(42 <= mut_ival1));
                static_assert(noexcept(mut_ival1 >= mut_ival2));
                static_assert(noexcept(mut_ival1 >= 42));
                static_assert(noexcept(42 >= mut_ival1));
                static_assert(noexcept(mut_ival1 + mut_ival2));
                static_assert(noexcept(mut_ival1 + 42));
                static_assert(noexcept(42 + mut_ival1));
                static_assert(noexcept(mut_ival1 - mut_ival2));
                static_assert(noexcept(mut_ival1 - 42));
                static_assert(noexcept(42 - mut_ival1));
                static_assert(noexcept(mut_ival1 * mut_ival2));
                static_assert(noexcept(mut_ival1 * 42));
                static_assert(noexcept(42 * mut_ival1));
                static_assert(noexcept(mut_ival1 / mut_ival2));
                static_assert(noexcept(mut_ival1 / 42));
                static_assert(noexcept(42 / mut_ival1));
                static_assert(noexcept(mut_ival1 % mut_ival2));
                static_assert(noexcept(mut_ival1 % 42));
                static_assert(noexcept(42 % mut_ival1));
                static_assert(noexcept(mut_uval1 << mut_uval2));
                static_assert(noexcept(mut_uval1 << 42U));
                static_assert(noexcept(42U << mut_uval1));
                static_assert(noexcept(mut_uval1 >> mut_uval2));
                static_assert(noexcept(mut_uval1 >> 42U));
                static_assert(noexcept(42U >> mut_uval1));
                static_assert(noexcept(mut_uval1 & mut_uval2));
                static_assert(noexcept(mut_uval1 & 42U));
                static_assert(noexcept(42U & mut_uval1));
                static_assert(noexcept(mut_uval1 | mut_uval2));
                static_assert(noexcept(mut_uval1 | 42U));
                static_assert(noexcept(42U | mut_uval1));
                static_assert(noexcept(mut_uval1 ^ mut_uval2));
                static_assert(noexcept(mut_uval1 ^ 42U));
                static_assert(noexcept(42U ^ mut_uval2));
                static_assert(noexcept(-mut_ival1));
                static_assert(noexcept(~mut_uval1));

                static_assert(noexcept(ival1.max_value()));
                static_assert(noexcept(ival1.min_value()));
                static_assert(noexcept(ival1.magic_neg_1()));
                static_assert(noexcept(ival1.magic_neg_2()));
                static_assert(noexcept(ival1.magic_neg_3()));
                static_assert(noexcept(ival1.magic_0()));
                static_assert(noexcept(ival1.magic_1()));
                static_assert(noexcept(ival1.magic_2()));
                static_assert(noexcept(ival1.magic_3()));
                static_assert(noexcept(ival1.data_as_ref()));
                static_assert(noexcept(ival1.data()));
                static_assert(noexcept(ival1.get()));
                static_assert(noexcept(ival1.is_pos()));
                static_assert(noexcept(ival1.is_neg()));
                static_assert(noexcept(ival1.is_zero()));
                static_assert(noexcept(ival1.is_invalid()));
                static_assert(noexcept(ival1.is_valid()));
                static_assert(noexcept(ival1.is_zero_or_invalid()));
                static_assert(noexcept(ival1.checked()));
                static_assert(noexcept(ival1.is_unchecked()));
                static_assert(noexcept(ival1.is_checked()));
                static_assert(noexcept(ival1.is_valid_and_checked()));
                static_assert(noexcept(ival1.failure()));
                static_assert(noexcept(ival1.max({})));
                static_assert(noexcept(ival1.min({})));
                static_assert(noexcept(ival1 == ival2));
                static_assert(noexcept(ival1 == 42));
                static_assert(noexcept(42 == ival1));
                static_assert(noexcept(ival1 != ival2));
                static_assert(noexcept(ival1 != 42));
                static_assert(noexcept(42 != ival1));
                static_assert(noexcept(ival1 < ival2));
                static_assert(noexcept(ival1 < 42));
                static_assert(noexcept(42 < ival1));
                static_assert(noexcept(ival1 > ival2));
                static_assert(noexcept(ival1 > 42));
                static_assert(noexcept(42 > ival1));
                static_assert(noexcept(ival1 <= ival2));
                static_assert(noexcept(ival1 <= 42));
                static_assert(noexcept(42 <= ival1));
                static_assert(noexcept(ival1 >= ival2));
                static_assert(noexcept(ival1 >= 42));
                static_assert(noexcept(42 >= ival1));
                static_assert(noexcept(ival1 + ival2));
                static_assert(noexcept(ival1 + 42));
                static_assert(noexcept(42 + ival1));
                static_assert(noexcept(ival1 - ival2));
                static_assert(noexcept(ival1 - 42));
                static_assert(noexcept(42 - ival1));
                static_assert(noexcept(ival1 * ival2));
                static_assert(noexcept(ival1 * 42));
                static_assert(noexcept(42 * ival1));
                static_assert(noexcept(ival1 / ival2));
                static_assert(noexcept(ival1 / 42));
                static_assert(noexcept(42 / ival1));
                static_assert(noexcept(ival1 % ival2));
                static_assert(noexcept(ival1 % 42));
                static_assert(noexcept(42 % ival1));
                static_assert(noexcept(uval1 << uval2));
                static_assert(noexcept(uval1 << 42U));
                static_assert(noexcept(42U << uval1));
                static_assert(noexcept(uval1 >> uval2));
                static_assert(noexcept(uval1 >> 42U));
                static_assert(noexcept(42U >> uval1));
                static_assert(noexcept(uval1 & uval2));
                static_assert(noexcept(uval1 & 42U));
                static_assert(noexcept(42U & uval1));
                static_assert(noexcept(uval1 | uval2));
                static_assert(noexcept(uval1 | 42U));
                static_assert(noexcept(42U | uval1));
                static_assert(noexcept(uval1 ^ uval2));
                static_assert(noexcept(uval1 ^ 42U));
                static_assert(noexcept(42U ^ uval2));
                static_assert(noexcept(-ival1));
                static_assert(noexcept(~uval1));

                static_assert(noexcept(bsl::make_safe(42)));
            };
        };
    };

    return bsl::ut_success();
}
