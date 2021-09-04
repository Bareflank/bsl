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

#include <limits>

#include <bsl/cstdint.hpp>
#include <bsl/numeric_limits.hpp>
#include <bsl/ut.hpp>

// clang-format off

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
    static_assert(bsl::numeric_limits<void *>::is_specialized == std::numeric_limits<void *>::is_specialized); // NOLINT
    static_assert(bsl::numeric_limits<bool>::is_specialized == std::numeric_limits<bool>::is_specialized); // NOLINT
    static_assert(bsl::numeric_limits<bsl::char_type>::is_specialized == std::numeric_limits<bsl::char_type>::is_specialized); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int8>::is_specialized == std::numeric_limits<bsl::int8>::is_specialized); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint8>::is_specialized == std::numeric_limits<bsl::uint8>::is_specialized); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int16>::is_specialized == std::numeric_limits<bsl::int16>::is_specialized); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint16>::is_specialized == std::numeric_limits<bsl::uint16>::is_specialized); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int32>::is_specialized == std::numeric_limits<bsl::int32>::is_specialized); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint32>::is_specialized == std::numeric_limits<bsl::uint32>::is_specialized); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int64>::is_specialized == std::numeric_limits<bsl::int64>::is_specialized); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint64>::is_specialized == std::numeric_limits<bsl::uint64>::is_specialized); // NOLINT

    static_assert(bsl::numeric_limits<void *>::is_exact == std::numeric_limits<void *>::is_exact); // NOLINT
    static_assert(bsl::numeric_limits<bool>::is_exact == std::numeric_limits<bool>::is_exact); // NOLINT
    static_assert(bsl::numeric_limits<bsl::char_type>::is_exact == std::numeric_limits<bsl::char_type>::is_exact); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int8>::is_exact == std::numeric_limits<bsl::int8>::is_exact); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint8>::is_exact == std::numeric_limits<bsl::uint8>::is_exact); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int16>::is_exact == std::numeric_limits<bsl::int16>::is_exact); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint16>::is_exact == std::numeric_limits<bsl::uint16>::is_exact); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int32>::is_exact == std::numeric_limits<bsl::int32>::is_exact); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint32>::is_exact == std::numeric_limits<bsl::uint32>::is_exact); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int64>::is_exact == std::numeric_limits<bsl::int64>::is_exact); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint64>::is_exact == std::numeric_limits<bsl::uint64>::is_exact); // NOLINT

    static_assert(bsl::numeric_limits<void *>::has_infinity == std::numeric_limits<void *>::has_infinity); // NOLINT
    static_assert(bsl::numeric_limits<bool>::has_infinity == std::numeric_limits<bool>::has_infinity); // NOLINT
    static_assert(bsl::numeric_limits<bsl::char_type>::has_infinity == std::numeric_limits<bsl::char_type>::has_infinity); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int8>::has_infinity == std::numeric_limits<bsl::int8>::has_infinity); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint8>::has_infinity == std::numeric_limits<bsl::uint8>::has_infinity); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int16>::has_infinity == std::numeric_limits<bsl::int16>::has_infinity); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint16>::has_infinity == std::numeric_limits<bsl::uint16>::has_infinity); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int32>::has_infinity == std::numeric_limits<bsl::int32>::has_infinity); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint32>::has_infinity == std::numeric_limits<bsl::uint32>::has_infinity); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int64>::has_infinity == std::numeric_limits<bsl::int64>::has_infinity); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint64>::has_infinity == std::numeric_limits<bsl::uint64>::has_infinity); // NOLINT

    static_assert(bsl::numeric_limits<void *>::has_quiet_NaN == std::numeric_limits<void *>::has_quiet_NaN); // NOLINT
    static_assert(bsl::numeric_limits<bool>::has_quiet_NaN == std::numeric_limits<bool>::has_quiet_NaN); // NOLINT
    static_assert(bsl::numeric_limits<bsl::char_type>::has_quiet_NaN == std::numeric_limits<bsl::char_type>::has_quiet_NaN); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int8>::has_quiet_NaN == std::numeric_limits<bsl::int8>::has_quiet_NaN); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint8>::has_quiet_NaN == std::numeric_limits<bsl::uint8>::has_quiet_NaN); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int16>::has_quiet_NaN == std::numeric_limits<bsl::int16>::has_quiet_NaN); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint16>::has_quiet_NaN == std::numeric_limits<bsl::uint16>::has_quiet_NaN); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int32>::has_quiet_NaN == std::numeric_limits<bsl::int32>::has_quiet_NaN); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint32>::has_quiet_NaN == std::numeric_limits<bsl::uint32>::has_quiet_NaN); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int64>::has_quiet_NaN == std::numeric_limits<bsl::int64>::has_quiet_NaN); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint64>::has_quiet_NaN == std::numeric_limits<bsl::uint64>::has_quiet_NaN); // NOLINT

    static_assert(bsl::numeric_limits<void *>::has_signaling_NaN == std::numeric_limits<void *>::has_signaling_NaN); // NOLINT
    static_assert(bsl::numeric_limits<bool>::has_signaling_NaN == std::numeric_limits<bool>::has_signaling_NaN); // NOLINT
    static_assert(bsl::numeric_limits<bsl::char_type>::has_signaling_NaN == std::numeric_limits<bsl::char_type>::has_signaling_NaN); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int8>::has_signaling_NaN == std::numeric_limits<bsl::int8>::has_signaling_NaN); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint8>::has_signaling_NaN == std::numeric_limits<bsl::uint8>::has_signaling_NaN); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int16>::has_signaling_NaN == std::numeric_limits<bsl::int16>::has_signaling_NaN); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint16>::has_signaling_NaN == std::numeric_limits<bsl::uint16>::has_signaling_NaN); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int32>::has_signaling_NaN == std::numeric_limits<bsl::int32>::has_signaling_NaN); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint32>::has_signaling_NaN == std::numeric_limits<bsl::uint32>::has_signaling_NaN); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int64>::has_signaling_NaN == std::numeric_limits<bsl::int64>::has_signaling_NaN); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint64>::has_signaling_NaN == std::numeric_limits<bsl::uint64>::has_signaling_NaN); // NOLINT

    static_assert(static_cast<bsl::int32>(bsl::numeric_limits<void *>::has_denorm) == static_cast<bsl::int32>(std::numeric_limits<void *>::has_denorm));
    static_assert(static_cast<bsl::int32>(bsl::numeric_limits<bool>::has_denorm) == static_cast<bsl::int32>(std::numeric_limits<bool>::has_denorm));
    static_assert(static_cast<bsl::int32>(bsl::numeric_limits<bsl::char_type>::has_denorm) == static_cast<bsl::int32>(std::numeric_limits<bsl::char_type>::has_denorm));
    static_assert(static_cast<bsl::int32>(bsl::numeric_limits<bsl::int8>::has_denorm) == static_cast<bsl::int32>(std::numeric_limits<bsl::int8>::has_denorm));
    static_assert(static_cast<bsl::int32>(bsl::numeric_limits<bsl::uint8>::has_denorm) == static_cast<bsl::int32>(std::numeric_limits<bsl::uint8>::has_denorm));
    static_assert(static_cast<bsl::int32>(bsl::numeric_limits<bsl::int16>::has_denorm) == static_cast<bsl::int32>(std::numeric_limits<bsl::int16>::has_denorm));
    static_assert(static_cast<bsl::int32>(bsl::numeric_limits<bsl::uint16>::has_denorm) == static_cast<bsl::int32>(std::numeric_limits<bsl::uint16>::has_denorm));
    static_assert(static_cast<bsl::int32>(bsl::numeric_limits<bsl::int32>::has_denorm) == static_cast<bsl::int32>(std::numeric_limits<bsl::int32>::has_denorm));
    static_assert(static_cast<bsl::int32>(bsl::numeric_limits<bsl::uint32>::has_denorm) == static_cast<bsl::int32>(std::numeric_limits<bsl::uint32>::has_denorm));
    static_assert(static_cast<bsl::int32>(bsl::numeric_limits<bsl::int64>::has_denorm) == static_cast<bsl::int32>(std::numeric_limits<bsl::int64>::has_denorm));
    static_assert(static_cast<bsl::int32>(bsl::numeric_limits<bsl::uint64>::has_denorm) == static_cast<bsl::int32>(std::numeric_limits<bsl::uint64>::has_denorm));

    static_assert(bsl::numeric_limits<void *>::has_denorm_loss == std::numeric_limits<void *>::has_denorm_loss); // NOLINT
    static_assert(bsl::numeric_limits<bool>::has_denorm_loss == std::numeric_limits<bool>::has_denorm_loss); // NOLINT
    static_assert(bsl::numeric_limits<bsl::char_type>::has_denorm_loss == std::numeric_limits<bsl::char_type>::has_denorm_loss); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int8>::has_denorm_loss == std::numeric_limits<bsl::int8>::has_denorm_loss); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint8>::has_denorm_loss == std::numeric_limits<bsl::uint8>::has_denorm_loss); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int16>::has_denorm_loss == std::numeric_limits<bsl::int16>::has_denorm_loss); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint16>::has_denorm_loss == std::numeric_limits<bsl::uint16>::has_denorm_loss); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int32>::has_denorm_loss == std::numeric_limits<bsl::int32>::has_denorm_loss); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint32>::has_denorm_loss == std::numeric_limits<bsl::uint32>::has_denorm_loss); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int64>::has_denorm_loss == std::numeric_limits<bsl::int64>::has_denorm_loss); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint64>::has_denorm_loss == std::numeric_limits<bsl::uint64>::has_denorm_loss); // NOLINT

    static_assert(static_cast<bsl::int32>(bsl::numeric_limits<void *>::round_style) == static_cast<bsl::int32>(std::numeric_limits<void *>::round_style));
    static_assert(static_cast<bsl::int32>(bsl::numeric_limits<bool>::round_style) == static_cast<bsl::int32>(std::numeric_limits<bool>::round_style));
    static_assert(static_cast<bsl::int32>(bsl::numeric_limits<bsl::char_type>::round_style) == static_cast<bsl::int32>(std::numeric_limits<bsl::char_type>::round_style));
    static_assert(static_cast<bsl::int32>(bsl::numeric_limits<bsl::int8>::round_style) == static_cast<bsl::int32>(std::numeric_limits<bsl::int8>::round_style));
    static_assert(static_cast<bsl::int32>(bsl::numeric_limits<bsl::uint8>::round_style) == static_cast<bsl::int32>(std::numeric_limits<bsl::uint8>::round_style));
    static_assert(static_cast<bsl::int32>(bsl::numeric_limits<bsl::int16>::round_style) == static_cast<bsl::int32>(std::numeric_limits<bsl::int16>::round_style));
    static_assert(static_cast<bsl::int32>(bsl::numeric_limits<bsl::uint16>::round_style) == static_cast<bsl::int32>(std::numeric_limits<bsl::uint16>::round_style));
    static_assert(static_cast<bsl::int32>(bsl::numeric_limits<bsl::int32>::round_style) == static_cast<bsl::int32>(std::numeric_limits<bsl::int32>::round_style));
    static_assert(static_cast<bsl::int32>(bsl::numeric_limits<bsl::uint32>::round_style) == static_cast<bsl::int32>(std::numeric_limits<bsl::uint32>::round_style));
    static_assert(static_cast<bsl::int32>(bsl::numeric_limits<bsl::int64>::round_style) == static_cast<bsl::int32>(std::numeric_limits<bsl::int64>::round_style));
    static_assert(static_cast<bsl::int32>(bsl::numeric_limits<bsl::uint64>::round_style) == static_cast<bsl::int32>(std::numeric_limits<bsl::uint64>::round_style));

    static_assert(bsl::numeric_limits<void *>::is_iec559 == std::numeric_limits<void *>::is_iec559); // NOLINT
    static_assert(bsl::numeric_limits<bool>::is_iec559 == std::numeric_limits<bool>::is_iec559); // NOLINT
    static_assert(bsl::numeric_limits<bsl::char_type>::is_iec559 == std::numeric_limits<bsl::char_type>::is_iec559); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int8>::is_iec559 == std::numeric_limits<bsl::int8>::is_iec559); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint8>::is_iec559 == std::numeric_limits<bsl::uint8>::is_iec559); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int16>::is_iec559 == std::numeric_limits<bsl::int16>::is_iec559); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint16>::is_iec559 == std::numeric_limits<bsl::uint16>::is_iec559); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int32>::is_iec559 == std::numeric_limits<bsl::int32>::is_iec559); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint32>::is_iec559 == std::numeric_limits<bsl::uint32>::is_iec559); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int64>::is_iec559 == std::numeric_limits<bsl::int64>::is_iec559); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint64>::is_iec559 == std::numeric_limits<bsl::uint64>::is_iec559); // NOLINT

    static_assert(bsl::numeric_limits<void *>::is_bounded == std::numeric_limits<void *>::is_bounded); // NOLINT
    static_assert(bsl::numeric_limits<bool>::is_bounded == std::numeric_limits<bool>::is_bounded); // NOLINT
    static_assert(bsl::numeric_limits<bsl::char_type>::is_bounded == std::numeric_limits<bsl::char_type>::is_bounded); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int8>::is_bounded == std::numeric_limits<bsl::int8>::is_bounded); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint8>::is_bounded == std::numeric_limits<bsl::uint8>::is_bounded); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int16>::is_bounded == std::numeric_limits<bsl::int16>::is_bounded); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint16>::is_bounded == std::numeric_limits<bsl::uint16>::is_bounded); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int32>::is_bounded == std::numeric_limits<bsl::int32>::is_bounded); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint32>::is_bounded == std::numeric_limits<bsl::uint32>::is_bounded); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int64>::is_bounded == std::numeric_limits<bsl::int64>::is_bounded); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint64>::is_bounded == std::numeric_limits<bsl::uint64>::is_bounded); // NOLINT

    static_assert(bsl::numeric_limits<void *>::is_modulo == std::numeric_limits<void *>::is_modulo); // NOLINT
    static_assert(bsl::numeric_limits<bool>::is_modulo == std::numeric_limits<bool>::is_modulo); // NOLINT
    // static_assert(bsl::numeric_limits<bsl::char_type>::is_modulo == std::numeric_limits<bsl::char_type>::is_modulo); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int8>::is_modulo == std::numeric_limits<bsl::int8>::is_modulo); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint8>::is_modulo == std::numeric_limits<bsl::uint8>::is_modulo); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int16>::is_modulo == std::numeric_limits<bsl::int16>::is_modulo); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint16>::is_modulo == std::numeric_limits<bsl::uint16>::is_modulo); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int32>::is_modulo == std::numeric_limits<bsl::int32>::is_modulo); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint32>::is_modulo == std::numeric_limits<bsl::uint32>::is_modulo); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int64>::is_modulo == std::numeric_limits<bsl::int64>::is_modulo); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint64>::is_modulo == std::numeric_limits<bsl::uint64>::is_modulo); // NOLINT

    static_assert(bsl::numeric_limits<void *>::digits == std::numeric_limits<void *>::digits); // NOLINT
    static_assert(bsl::numeric_limits<bool>::digits == std::numeric_limits<bool>::digits); // NOLINT
    // static_assert(bsl::numeric_limits<bsl::char_type>::digits == std::numeric_limits<bsl::char_type>::digits); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int8>::digits == std::numeric_limits<bsl::int8>::digits); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint8>::digits == std::numeric_limits<bsl::uint8>::digits); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int16>::digits == std::numeric_limits<bsl::int16>::digits); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint16>::digits == std::numeric_limits<bsl::uint16>::digits); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int32>::digits == std::numeric_limits<bsl::int32>::digits); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint32>::digits == std::numeric_limits<bsl::uint32>::digits); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int64>::digits == std::numeric_limits<bsl::int64>::digits); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint64>::digits == std::numeric_limits<bsl::uint64>::digits); // NOLINT

    static_assert(bsl::numeric_limits<void *>::digits10 == std::numeric_limits<void *>::digits10); // NOLINT
    static_assert(bsl::numeric_limits<bool>::digits10 == std::numeric_limits<bool>::digits10); // NOLINT
    // static_assert(bsl::numeric_limits<bsl::char_type>::digits10 == std::numeric_limits<bsl::char_type>::digits10); // NOLINT
    // static_assert(bsl::numeric_limits<bsl::int8>::digits10 == std::numeric_limits<bsl::int8>::digits10); // NOLINT
    // static_assert(bsl::numeric_limits<bsl::uint8>::digits10 == std::numeric_limits<bsl::uint8>::digits10); // NOLINT
    // static_assert(bsl::numeric_limits<bsl::int16>::digits10 == std::numeric_limits<bsl::int16>::digits10); // NOLINT
    // static_assert(bsl::numeric_limits<bsl::uint16>::digits10 == std::numeric_limits<bsl::uint16>::digits10); // NOLINT
    // static_assert(bsl::numeric_limits<bsl::int32>::digits10 == std::numeric_limits<bsl::int32>::digits10); // NOLINT
    // static_assert(bsl::numeric_limits<bsl::uint32>::digits10 == std::numeric_limits<bsl::uint32>::digits10); // NOLINT
    // static_assert(bsl::numeric_limits<bsl::int64>::digits10 == std::numeric_limits<bsl::int64>::digits10); // NOLINT
    // static_assert(bsl::numeric_limits<bsl::uint64>::digits10 == std::numeric_limits<bsl::uint64>::digits10); // NOLINT

    static_assert(bsl::numeric_limits<void *>::max_digits10 == std::numeric_limits<void *>::max_digits10); // NOLINT
    static_assert(bsl::numeric_limits<bool>::max_digits10 == std::numeric_limits<bool>::max_digits10); // NOLINT
    static_assert(bsl::numeric_limits<bsl::char_type>::max_digits10 == std::numeric_limits<bsl::char_type>::max_digits10); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int8>::max_digits10 == std::numeric_limits<bsl::int8>::max_digits10); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint8>::max_digits10 == std::numeric_limits<bsl::uint8>::max_digits10); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int16>::max_digits10 == std::numeric_limits<bsl::int16>::max_digits10); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint16>::max_digits10 == std::numeric_limits<bsl::uint16>::max_digits10); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int32>::max_digits10 == std::numeric_limits<bsl::int32>::max_digits10); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint32>::max_digits10 == std::numeric_limits<bsl::uint32>::max_digits10); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int64>::max_digits10 == std::numeric_limits<bsl::int64>::max_digits10); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint64>::max_digits10 == std::numeric_limits<bsl::uint64>::max_digits10); // NOLINT

    static_assert(bsl::numeric_limits<void *>::radix == std::numeric_limits<void *>::radix); // NOLINT
    static_assert(bsl::numeric_limits<bool>::radix == std::numeric_limits<bool>::radix); // NOLINT
    static_assert(bsl::numeric_limits<bsl::char_type>::radix == std::numeric_limits<bsl::char_type>::radix); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int8>::radix == std::numeric_limits<bsl::int8>::radix); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint8>::radix == std::numeric_limits<bsl::uint8>::radix); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int16>::radix == std::numeric_limits<bsl::int16>::radix); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint16>::radix == std::numeric_limits<bsl::uint16>::radix); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int32>::radix == std::numeric_limits<bsl::int32>::radix); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint32>::radix == std::numeric_limits<bsl::uint32>::radix); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int64>::radix == std::numeric_limits<bsl::int64>::radix); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint64>::radix == std::numeric_limits<bsl::uint64>::radix); // NOLINT

    static_assert(bsl::numeric_limits<void *>::min_exponent == std::numeric_limits<void *>::min_exponent); // NOLINT
    static_assert(bsl::numeric_limits<bool>::min_exponent == std::numeric_limits<bool>::min_exponent); // NOLINT
    static_assert(bsl::numeric_limits<bsl::char_type>::min_exponent == std::numeric_limits<bsl::char_type>::min_exponent); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int8>::min_exponent == std::numeric_limits<bsl::int8>::min_exponent); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint8>::min_exponent == std::numeric_limits<bsl::uint8>::min_exponent); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int16>::min_exponent == std::numeric_limits<bsl::int16>::min_exponent); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint16>::min_exponent == std::numeric_limits<bsl::uint16>::min_exponent); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int32>::min_exponent == std::numeric_limits<bsl::int32>::min_exponent); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint32>::min_exponent == std::numeric_limits<bsl::uint32>::min_exponent); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int64>::min_exponent == std::numeric_limits<bsl::int64>::min_exponent); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint64>::min_exponent == std::numeric_limits<bsl::uint64>::min_exponent); // NOLINT

    static_assert(bsl::numeric_limits<void *>::min_exponent10 == std::numeric_limits<void *>::min_exponent10); // NOLINT
    static_assert(bsl::numeric_limits<bool>::min_exponent10 == std::numeric_limits<bool>::min_exponent10); // NOLINT
    static_assert(bsl::numeric_limits<bsl::char_type>::min_exponent10 == std::numeric_limits<bsl::char_type>::min_exponent10); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int8>::min_exponent10 == std::numeric_limits<bsl::int8>::min_exponent10); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint8>::min_exponent10 == std::numeric_limits<bsl::uint8>::min_exponent10); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int16>::min_exponent10 == std::numeric_limits<bsl::int16>::min_exponent10); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint16>::min_exponent10 == std::numeric_limits<bsl::uint16>::min_exponent10); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int32>::min_exponent10 == std::numeric_limits<bsl::int32>::min_exponent10); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint32>::min_exponent10 == std::numeric_limits<bsl::uint32>::min_exponent10); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int64>::min_exponent10 == std::numeric_limits<bsl::int64>::min_exponent10); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint64>::min_exponent10 == std::numeric_limits<bsl::uint64>::min_exponent10); // NOLINT

    static_assert(bsl::numeric_limits<void *>::max_exponent == std::numeric_limits<void *>::max_exponent); // NOLINT
    static_assert(bsl::numeric_limits<bool>::max_exponent == std::numeric_limits<bool>::max_exponent); // NOLINT
    static_assert(bsl::numeric_limits<bsl::char_type>::max_exponent == std::numeric_limits<bsl::char_type>::max_exponent); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int8>::max_exponent == std::numeric_limits<bsl::int8>::max_exponent); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint8>::max_exponent == std::numeric_limits<bsl::uint8>::max_exponent); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int16>::max_exponent == std::numeric_limits<bsl::int16>::max_exponent); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint16>::max_exponent == std::numeric_limits<bsl::uint16>::max_exponent); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int32>::max_exponent == std::numeric_limits<bsl::int32>::max_exponent); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint32>::max_exponent == std::numeric_limits<bsl::uint32>::max_exponent); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int64>::max_exponent == std::numeric_limits<bsl::int64>::max_exponent); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint64>::max_exponent == std::numeric_limits<bsl::uint64>::max_exponent); // NOLINT

    static_assert(bsl::numeric_limits<void *>::max_exponent10 == std::numeric_limits<void *>::max_exponent10); // NOLINT
    static_assert(bsl::numeric_limits<bool>::max_exponent10 == std::numeric_limits<bool>::max_exponent10); // NOLINT
    static_assert(bsl::numeric_limits<bsl::char_type>::max_exponent10 == std::numeric_limits<bsl::char_type>::max_exponent10); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int8>::max_exponent10 == std::numeric_limits<bsl::int8>::max_exponent10); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint8>::max_exponent10 == std::numeric_limits<bsl::uint8>::max_exponent10); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int16>::max_exponent10 == std::numeric_limits<bsl::int16>::max_exponent10); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint16>::max_exponent10 == std::numeric_limits<bsl::uint16>::max_exponent10); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int32>::max_exponent10 == std::numeric_limits<bsl::int32>::max_exponent10); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint32>::max_exponent10 == std::numeric_limits<bsl::uint32>::max_exponent10); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int64>::max_exponent10 == std::numeric_limits<bsl::int64>::max_exponent10); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint64>::max_exponent10 == std::numeric_limits<bsl::uint64>::max_exponent10); // NOLINT

    static_assert(!bsl::numeric_limits<void *>::traps);
    static_assert(!bsl::numeric_limits<bool>::traps);
    static_assert(!bsl::numeric_limits<bsl::char_type>::traps);
    static_assert(!bsl::numeric_limits<bsl::int8>::traps);
    static_assert(!bsl::numeric_limits<bsl::uint8>::traps);
    static_assert(!bsl::numeric_limits<bsl::int16>::traps);
    static_assert(!bsl::numeric_limits<bsl::uint16>::traps);
    static_assert(!bsl::numeric_limits<bsl::int32>::traps);
    static_assert(!bsl::numeric_limits<bsl::uint32>::traps);
    static_assert(!bsl::numeric_limits<bsl::int64>::traps);
    static_assert(!bsl::numeric_limits<bsl::uint64>::traps);

    static_assert(bsl::numeric_limits<void *>::tinyness_before == std::numeric_limits<void *>::tinyness_before); // NOLINT
    static_assert(bsl::numeric_limits<bool>::tinyness_before == std::numeric_limits<bool>::tinyness_before); // NOLINT
    static_assert(bsl::numeric_limits<bsl::char_type>::tinyness_before == std::numeric_limits<bsl::char_type>::tinyness_before); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int8>::tinyness_before == std::numeric_limits<bsl::int8>::tinyness_before); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint8>::tinyness_before == std::numeric_limits<bsl::uint8>::tinyness_before); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int16>::tinyness_before == std::numeric_limits<bsl::int16>::tinyness_before); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint16>::tinyness_before == std::numeric_limits<bsl::uint16>::tinyness_before); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int32>::tinyness_before == std::numeric_limits<bsl::int32>::tinyness_before); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint32>::tinyness_before == std::numeric_limits<bsl::uint32>::tinyness_before); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int64>::tinyness_before == std::numeric_limits<bsl::int64>::tinyness_before); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint64>::tinyness_before == std::numeric_limits<bsl::uint64>::tinyness_before); // NOLINT

    static_assert(bsl::numeric_limits<void *>::min_value() == std::numeric_limits<void *>::min()); // NOLINT
    static_assert(bsl::numeric_limits<bool>::min_value() == std::numeric_limits<bool>::min()); // NOLINT
    static_assert(bsl::numeric_limits<bsl::char_type>::min_value() == std::numeric_limits<bsl::char_type>::min()); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int8>::min_value() == std::numeric_limits<bsl::int8>::min()); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint8>::min_value() == std::numeric_limits<bsl::uint8>::min()); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int16>::min_value() == std::numeric_limits<bsl::int16>::min()); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint16>::min_value() == std::numeric_limits<bsl::uint16>::min()); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int32>::min_value() == std::numeric_limits<bsl::int32>::min()); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint32>::min_value() == std::numeric_limits<bsl::uint32>::min()); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int64>::min_value() == std::numeric_limits<bsl::int64>::min()); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint64>::min_value() == std::numeric_limits<bsl::uint64>::min()); // NOLINT

    static_assert(bsl::numeric_limits<void *>::lowest() == std::numeric_limits<void *>::lowest()); // NOLINT
    static_assert(bsl::numeric_limits<bool>::lowest() == std::numeric_limits<bool>::lowest()); // NOLINT
    static_assert(bsl::numeric_limits<bsl::char_type>::lowest() == std::numeric_limits<bsl::char_type>::lowest()); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int8>::lowest() == std::numeric_limits<bsl::int8>::lowest()); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint8>::lowest() == std::numeric_limits<bsl::uint8>::lowest()); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int16>::lowest() == std::numeric_limits<bsl::int16>::lowest()); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint16>::lowest() == std::numeric_limits<bsl::uint16>::lowest()); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int32>::lowest() == std::numeric_limits<bsl::int32>::lowest()); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint32>::lowest() == std::numeric_limits<bsl::uint32>::lowest()); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int64>::lowest() == std::numeric_limits<bsl::int64>::lowest()); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint64>::lowest() == std::numeric_limits<bsl::uint64>::lowest()); // NOLINT

    static_assert(bsl::numeric_limits<void *>::max_value() == std::numeric_limits<void *>::max()); // NOLINT
    static_assert(bsl::numeric_limits<bool>::max_value() == std::numeric_limits<bool>::max()); // NOLINT
    static_assert(bsl::numeric_limits<bsl::char_type>::max_value() == std::numeric_limits<bsl::char_type>::max()); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int8>::max_value() == std::numeric_limits<bsl::int8>::max()); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint8>::max_value() == std::numeric_limits<bsl::uint8>::max()); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int16>::max_value() == std::numeric_limits<bsl::int16>::max()); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint16>::max_value() == std::numeric_limits<bsl::uint16>::max()); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int32>::max_value() == std::numeric_limits<bsl::int32>::max()); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint32>::max_value() == std::numeric_limits<bsl::uint32>::max()); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int64>::max_value() == std::numeric_limits<bsl::int64>::max()); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint64>::max_value() == std::numeric_limits<bsl::uint64>::max()); // NOLINT

    static_assert(bsl::numeric_limits<void *>::epsilon() == std::numeric_limits<void *>::epsilon()); // NOLINT
    static_assert(bsl::numeric_limits<bool>::epsilon() == std::numeric_limits<bool>::epsilon()); // NOLINT
    static_assert(bsl::numeric_limits<bsl::char_type>::epsilon() == std::numeric_limits<bsl::char_type>::epsilon()); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int8>::epsilon() == std::numeric_limits<bsl::int8>::epsilon()); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint8>::epsilon() == std::numeric_limits<bsl::uint8>::epsilon()); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int16>::epsilon() == std::numeric_limits<bsl::int16>::epsilon()); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint16>::epsilon() == std::numeric_limits<bsl::uint16>::epsilon()); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int32>::epsilon() == std::numeric_limits<bsl::int32>::epsilon()); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint32>::epsilon() == std::numeric_limits<bsl::uint32>::epsilon()); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int64>::epsilon() == std::numeric_limits<bsl::int64>::epsilon()); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint64>::epsilon() == std::numeric_limits<bsl::uint64>::epsilon()); // NOLINT

    static_assert(bsl::numeric_limits<void *>::round_error() == std::numeric_limits<void *>::round_error()); // NOLINT
    static_assert(bsl::numeric_limits<bool>::round_error() == std::numeric_limits<bool>::round_error()); // NOLINT
    static_assert(bsl::numeric_limits<bsl::char_type>::round_error() == std::numeric_limits<bsl::char_type>::round_error()); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int8>::round_error() == std::numeric_limits<bsl::int8>::round_error()); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint8>::round_error() == std::numeric_limits<bsl::uint8>::round_error()); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int16>::round_error() == std::numeric_limits<bsl::int16>::round_error()); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint16>::round_error() == std::numeric_limits<bsl::uint16>::round_error()); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int32>::round_error() == std::numeric_limits<bsl::int32>::round_error()); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint32>::round_error() == std::numeric_limits<bsl::uint32>::round_error()); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int64>::round_error() == std::numeric_limits<bsl::int64>::round_error()); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint64>::round_error() == std::numeric_limits<bsl::uint64>::round_error()); // NOLINT

    static_assert(bsl::numeric_limits<void *>::infinity() == std::numeric_limits<void *>::infinity()); // NOLINT
    static_assert(bsl::numeric_limits<bool>::infinity() == std::numeric_limits<bool>::infinity()); // NOLINT
    static_assert(bsl::numeric_limits<bsl::char_type>::infinity() == std::numeric_limits<bsl::char_type>::infinity()); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int8>::infinity() == std::numeric_limits<bsl::int8>::infinity()); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint8>::infinity() == std::numeric_limits<bsl::uint8>::infinity()); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int16>::infinity() == std::numeric_limits<bsl::int16>::infinity()); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint16>::infinity() == std::numeric_limits<bsl::uint16>::infinity()); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int32>::infinity() == std::numeric_limits<bsl::int32>::infinity()); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint32>::infinity() == std::numeric_limits<bsl::uint32>::infinity()); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int64>::infinity() == std::numeric_limits<bsl::int64>::infinity()); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint64>::infinity() == std::numeric_limits<bsl::uint64>::infinity()); // NOLINT

    static_assert(bsl::numeric_limits<void *>::quiet_NaN() == std::numeric_limits<void *>::quiet_NaN()); // NOLINT
    static_assert(bsl::numeric_limits<bool>::quiet_NaN() == std::numeric_limits<bool>::quiet_NaN()); // NOLINT
    static_assert(bsl::numeric_limits<bsl::char_type>::quiet_NaN() == std::numeric_limits<bsl::char_type>::quiet_NaN()); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int8>::quiet_NaN() == std::numeric_limits<bsl::int8>::quiet_NaN()); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint8>::quiet_NaN() == std::numeric_limits<bsl::uint8>::quiet_NaN()); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int16>::quiet_NaN() == std::numeric_limits<bsl::int16>::quiet_NaN()); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint16>::quiet_NaN() == std::numeric_limits<bsl::uint16>::quiet_NaN()); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int32>::quiet_NaN() == std::numeric_limits<bsl::int32>::quiet_NaN()); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint32>::quiet_NaN() == std::numeric_limits<bsl::uint32>::quiet_NaN()); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int64>::quiet_NaN() == std::numeric_limits<bsl::int64>::quiet_NaN()); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint64>::quiet_NaN() == std::numeric_limits<bsl::uint64>::quiet_NaN()); // NOLINT

    static_assert(bsl::numeric_limits<void *>::signaling_NaN() == std::numeric_limits<void *>::signaling_NaN()); // NOLINT
    static_assert(bsl::numeric_limits<bool>::signaling_NaN() == std::numeric_limits<bool>::signaling_NaN()); // NOLINT
    static_assert(bsl::numeric_limits<bsl::char_type>::signaling_NaN() == std::numeric_limits<bsl::char_type>::signaling_NaN()); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int8>::signaling_NaN() == std::numeric_limits<bsl::int8>::signaling_NaN()); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint8>::signaling_NaN() == std::numeric_limits<bsl::uint8>::signaling_NaN()); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int16>::signaling_NaN() == std::numeric_limits<bsl::int16>::signaling_NaN()); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint16>::signaling_NaN() == std::numeric_limits<bsl::uint16>::signaling_NaN()); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int32>::signaling_NaN() == std::numeric_limits<bsl::int32>::signaling_NaN()); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint32>::signaling_NaN() == std::numeric_limits<bsl::uint32>::signaling_NaN()); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int64>::signaling_NaN() == std::numeric_limits<bsl::int64>::signaling_NaN()); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint64>::signaling_NaN() == std::numeric_limits<bsl::uint64>::signaling_NaN()); // NOLINT

    static_assert(bsl::numeric_limits<void *>::denorm_min() == std::numeric_limits<void *>::denorm_min()); // NOLINT
    static_assert(bsl::numeric_limits<bool>::denorm_min() == std::numeric_limits<bool>::denorm_min()); // NOLINT
    static_assert(bsl::numeric_limits<bsl::char_type>::denorm_min() == std::numeric_limits<bsl::char_type>::denorm_min()); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int8>::denorm_min() == std::numeric_limits<bsl::int8>::denorm_min()); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint8>::denorm_min() == std::numeric_limits<bsl::uint8>::denorm_min()); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int16>::denorm_min() == std::numeric_limits<bsl::int16>::denorm_min()); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint16>::denorm_min() == std::numeric_limits<bsl::uint16>::denorm_min()); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int32>::denorm_min() == std::numeric_limits<bsl::int32>::denorm_min()); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint32>::denorm_min() == std::numeric_limits<bsl::uint32>::denorm_min()); // NOLINT
    static_assert(bsl::numeric_limits<bsl::int64>::denorm_min() == std::numeric_limits<bsl::int64>::denorm_min()); // NOLINT
    static_assert(bsl::numeric_limits<bsl::uint64>::denorm_min() == std::numeric_limits<bsl::uint64>::denorm_min()); // NOLINT

    return bsl::ut_success();
}

// clang-format on
