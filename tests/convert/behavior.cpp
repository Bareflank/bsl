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

#undef BSL_ASSERT_FAST_FAILS
// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define BSL_ASSERT_FAST_FAILS false

#include <bsl/convert.hpp>
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
        using namespace bsl;    // NOLINT

        // ---------------------------------------------------------------------
        // int8
        // ---------------------------------------------------------------------

        bsl::ut_scenario{"bsl::safe_i8"} = []() noexcept {
            ut_check(to_i8(safe_i8::failure()).is_invalid());
            ut_check(to_i16(safe_i8::failure()).is_invalid());
            ut_check(to_i32(safe_i8::failure()).is_invalid());
            ut_check(to_i64(safe_i8::failure()).is_invalid());
            ut_check(to_u8(safe_i8::failure()).is_invalid());
            ut_check(to_u16(safe_i8::failure()).is_invalid());
            ut_check(to_u32(safe_i8::failure()).is_invalid());
            ut_check(to_u64(safe_i8::failure()).is_invalid());
            ut_check(to_umx(safe_i8::failure()).is_invalid());
            bsl::ut_given_at_runtime{} = []() noexcept {
                ut_check(to_idx(safe_i8::failure()).is_invalid());
            };

            ut_check(to_i8(safe_i8::magic_neg_1()) == safe_i8::magic_neg_1());
            ut_check(to_i16(safe_i8::magic_neg_1()) == safe_i16::magic_neg_1());
            ut_check(to_i32(safe_i8::magic_neg_1()) == safe_i32::magic_neg_1());
            ut_check(to_i64(safe_i8::magic_neg_1()) == safe_i64::magic_neg_1());
            ut_check(to_u8(safe_i8::magic_neg_1()).is_invalid());
            ut_check(to_u16(safe_i8::magic_neg_1()).is_invalid());
            ut_check(to_u32(safe_i8::magic_neg_1()).is_invalid());
            ut_check(to_u64(safe_i8::magic_neg_1()).is_invalid());
            ut_check(to_umx(safe_i8::magic_neg_1()).is_invalid());

            ut_check(to_i8(safe_i8::magic_0()) == safe_i8::magic_0());
            ut_check(to_i16(safe_i8::magic_0()) == safe_i16::magic_0());
            ut_check(to_i32(safe_i8::magic_0()) == safe_i32::magic_0());
            ut_check(to_i64(safe_i8::magic_0()) == safe_i64::magic_0());
            ut_check(to_u8(safe_i8::magic_0()) == safe_u8::magic_0());
            ut_check(to_u16(safe_i8::magic_0()) == safe_u16::magic_0());
            ut_check(to_u32(safe_i8::magic_0()) == safe_u32::magic_0());
            ut_check(to_u64(safe_i8::magic_0()) == safe_u64::magic_0());
            ut_check(to_umx(safe_i8::magic_0()) == safe_umx::magic_0());
            ut_check(to_idx(safe_i8::magic_0()) == safe_umx::magic_0());

            ut_check(to_i8(safe_i8::magic_1()) == safe_i8::magic_1());
            ut_check(to_i16(safe_i8::magic_1()) == safe_i16::magic_1());
            ut_check(to_i32(safe_i8::magic_1()) == safe_i32::magic_1());
            ut_check(to_i64(safe_i8::magic_1()) == safe_i64::magic_1());
            ut_check(to_u8(safe_i8::magic_1()) == safe_u8::magic_1());
            ut_check(to_u16(safe_i8::magic_1()) == safe_u16::magic_1());
            ut_check(to_u32(safe_i8::magic_1()) == safe_u32::magic_1());
            ut_check(to_u64(safe_i8::magic_1()) == safe_u64::magic_1());
            ut_check(to_umx(safe_i8::magic_1()) == safe_umx::magic_1());
            ut_check(to_idx(safe_i8::magic_1()) == safe_umx::magic_1());

            auto const max{numeric_limits<int8>::max_value()};    // NOLINT
            ut_check(to_i8(safe_i8::max_value()) == static_cast<int8>(max));
            ut_check(to_i16(safe_i8::max_value()) == static_cast<int16>(max));
            ut_check(to_i32(safe_i8::max_value()) == static_cast<int32>(max));
            ut_check(to_i64(safe_i8::max_value()) == static_cast<int64>(max));
            ut_check(to_u8(safe_i8::max_value()) == static_cast<uint8>(max));
            ut_check(to_u16(safe_i8::max_value()) == static_cast<uint16>(max));
            ut_check(to_u32(safe_i8::max_value()) == static_cast<uint32>(max));
            ut_check(to_u64(safe_i8::max_value()) == static_cast<uint64>(max));
            ut_check(to_umx(safe_i8::max_value()) == static_cast<uintmx>(max));
            ut_check(to_idx(safe_i8::max_value()) == static_cast<uintmx>(max));

            auto const min{numeric_limits<int8>::min_value()};    // NOLINT
            ut_check(to_i8(safe_i8::min_value()) == static_cast<int8>(min));
            ut_check(to_i16(safe_i8::min_value()) == static_cast<int16>(min));
            ut_check(to_i32(safe_i8::min_value()) == static_cast<int32>(min));
            ut_check(to_i64(safe_i8::min_value()) == static_cast<int64>(min));
            ut_check(to_u8(safe_i8::min_value()).is_invalid());
            ut_check(to_u16(safe_i8::min_value()).is_invalid());
            ut_check(to_u32(safe_i8::min_value()).is_invalid());
            ut_check(to_u64(safe_i8::min_value()).is_invalid());
            ut_check(to_umx(safe_i8::min_value()).is_invalid());
            bsl::ut_given_at_runtime{} = []() noexcept {
                ut_check(to_idx(safe_i8::min_value()).is_invalid());
            };
        };

        bsl::ut_scenario{"bsl::int8"} = []() noexcept {
            ut_check(to_i8(static_cast<bsl::int8>(-1)) == safe_i8::magic_neg_1());
            ut_check(to_i16(static_cast<bsl::int8>(-1)) == safe_i16::magic_neg_1());
            ut_check(to_i32(static_cast<bsl::int8>(-1)) == safe_i32::magic_neg_1());
            ut_check(to_i64(static_cast<bsl::int8>(-1)) == safe_i64::magic_neg_1());
            ut_check(to_u8(static_cast<bsl::int8>(-1)).is_invalid());
            ut_check(to_u16(static_cast<bsl::int8>(-1)).is_invalid());
            ut_check(to_u32(static_cast<bsl::int8>(-1)).is_invalid());
            ut_check(to_u64(static_cast<bsl::int8>(-1)).is_invalid());
            ut_check(to_umx(static_cast<bsl::int8>(-1)).is_invalid());

            ut_check(to_i8(static_cast<bsl::int8>(0)) == safe_i8::magic_0());
            ut_check(to_i16(static_cast<bsl::int8>(0)) == safe_i16::magic_0());
            ut_check(to_i32(static_cast<bsl::int8>(0)) == safe_i32::magic_0());
            ut_check(to_i64(static_cast<bsl::int8>(0)) == safe_i64::magic_0());
            ut_check(to_u8(static_cast<bsl::int8>(0)) == safe_u8::magic_0());
            ut_check(to_u16(static_cast<bsl::int8>(0)) == safe_u16::magic_0());
            ut_check(to_u32(static_cast<bsl::int8>(0)) == safe_u32::magic_0());
            ut_check(to_u64(static_cast<bsl::int8>(0)) == safe_u64::magic_0());
            ut_check(to_umx(static_cast<bsl::int8>(0)) == safe_umx::magic_0());
            ut_check(to_idx(static_cast<bsl::int8>(0)) == safe_umx::magic_0());

            ut_check(to_i8(static_cast<bsl::int8>(1)) == safe_i8::magic_1());
            ut_check(to_i16(static_cast<bsl::int8>(1)) == safe_i16::magic_1());
            ut_check(to_i32(static_cast<bsl::int8>(1)) == safe_i32::magic_1());
            ut_check(to_i64(static_cast<bsl::int8>(1)) == safe_i64::magic_1());
            ut_check(to_u8(static_cast<bsl::int8>(1)) == safe_u8::magic_1());
            ut_check(to_u16(static_cast<bsl::int8>(1)) == safe_u16::magic_1());
            ut_check(to_u32(static_cast<bsl::int8>(1)) == safe_u32::magic_1());
            ut_check(to_u64(static_cast<bsl::int8>(1)) == safe_u64::magic_1());
            ut_check(to_umx(static_cast<bsl::int8>(1)) == safe_umx::magic_1());
            ut_check(to_idx(static_cast<bsl::int8>(1)) == safe_umx::magic_1());

            auto const max{numeric_limits<int8>::max_value()};    // NOLINT
            ut_check(to_i8(numeric_limits<int8>::max_value()) == static_cast<int8>(max));
            ut_check(to_i16(numeric_limits<int8>::max_value()) == static_cast<int16>(max));
            ut_check(to_i32(numeric_limits<int8>::max_value()) == static_cast<int32>(max));
            ut_check(to_i64(numeric_limits<int8>::max_value()) == static_cast<int64>(max));
            ut_check(to_u8(numeric_limits<int8>::max_value()) == static_cast<uint8>(max));
            ut_check(to_u16(numeric_limits<int8>::max_value()) == static_cast<uint16>(max));
            ut_check(to_u32(numeric_limits<int8>::max_value()) == static_cast<uint32>(max));
            ut_check(to_u64(numeric_limits<int8>::max_value()) == static_cast<uint64>(max));
            ut_check(to_umx(numeric_limits<int8>::max_value()) == static_cast<uintmx>(max));
            ut_check(to_idx(numeric_limits<int8>::max_value()) == static_cast<uintmx>(max));

            auto const min{numeric_limits<int8>::min_value()};    // NOLINT
            ut_check(to_i8(numeric_limits<int8>::min_value()) == static_cast<int8>(min));
            ut_check(to_i16(numeric_limits<int8>::min_value()) == static_cast<int16>(min));
            ut_check(to_i32(numeric_limits<int8>::min_value()) == static_cast<int32>(min));
            ut_check(to_i64(numeric_limits<int8>::min_value()) == static_cast<int64>(min));
            ut_check(to_u8(numeric_limits<int8>::min_value()).is_invalid());
            ut_check(to_u16(numeric_limits<int8>::min_value()).is_invalid());
            ut_check(to_u32(numeric_limits<int8>::min_value()).is_invalid());
            ut_check(to_u64(numeric_limits<int8>::min_value()).is_invalid());
            ut_check(to_umx(numeric_limits<int8>::min_value()).is_invalid());
            bsl::ut_given_at_runtime{} = []() noexcept {
                ut_check(to_idx(numeric_limits<int8>::min_value()).is_invalid());
            };
        };

        // ---------------------------------------------------------------------
        // int16
        // ---------------------------------------------------------------------

        bsl::ut_scenario{"bsl::safe_i16"} = []() noexcept {
            ut_check(to_i8(safe_i16::failure()).is_invalid());
            ut_check(to_i16(safe_i16::failure()).is_invalid());
            ut_check(to_i32(safe_i16::failure()).is_invalid());
            ut_check(to_i64(safe_i16::failure()).is_invalid());
            ut_check(to_u8(safe_i16::failure()).is_invalid());
            ut_check(to_u16(safe_i16::failure()).is_invalid());
            ut_check(to_u32(safe_i16::failure()).is_invalid());
            ut_check(to_u64(safe_i16::failure()).is_invalid());
            ut_check(to_umx(safe_i16::failure()).is_invalid());
            bsl::ut_given_at_runtime{} = []() noexcept {
                ut_check(to_idx(safe_i16::failure()).is_invalid());
            };

            ut_check(to_i8(safe_i16::magic_neg_1()) == safe_i8::magic_neg_1());
            ut_check(to_i16(safe_i16::magic_neg_1()) == safe_i16::magic_neg_1());
            ut_check(to_i32(safe_i16::magic_neg_1()) == safe_i32::magic_neg_1());
            ut_check(to_i64(safe_i16::magic_neg_1()) == safe_i64::magic_neg_1());
            ut_check(to_u8(safe_i16::magic_neg_1()).is_invalid());
            ut_check(to_u16(safe_i16::magic_neg_1()).is_invalid());
            ut_check(to_u32(safe_i16::magic_neg_1()).is_invalid());
            ut_check(to_u64(safe_i16::magic_neg_1()).is_invalid());
            ut_check(to_umx(safe_i16::magic_neg_1()).is_invalid());

            ut_check(to_i8(safe_i16::magic_0()) == safe_i8::magic_0());
            ut_check(to_i16(safe_i16::magic_0()) == safe_i16::magic_0());
            ut_check(to_i32(safe_i16::magic_0()) == safe_i32::magic_0());
            ut_check(to_i64(safe_i16::magic_0()) == safe_i64::magic_0());
            ut_check(to_u8(safe_i16::magic_0()) == safe_u8::magic_0());
            ut_check(to_u16(safe_i16::magic_0()) == safe_u16::magic_0());
            ut_check(to_u32(safe_i16::magic_0()) == safe_u32::magic_0());
            ut_check(to_u64(safe_i16::magic_0()) == safe_u64::magic_0());
            ut_check(to_umx(safe_i16::magic_0()) == safe_umx::magic_0());
            ut_check(to_idx(safe_i16::magic_0()) == safe_umx::magic_0());

            ut_check(to_i8(safe_i16::magic_1()) == safe_i8::magic_1());
            ut_check(to_i16(safe_i16::magic_1()) == safe_i16::magic_1());
            ut_check(to_i32(safe_i16::magic_1()) == safe_i32::magic_1());
            ut_check(to_i64(safe_i16::magic_1()) == safe_i64::magic_1());
            ut_check(to_u8(safe_i16::magic_1()) == safe_u8::magic_1());
            ut_check(to_u16(safe_i16::magic_1()) == safe_u16::magic_1());
            ut_check(to_u32(safe_i16::magic_1()) == safe_u32::magic_1());
            ut_check(to_u64(safe_i16::magic_1()) == safe_u64::magic_1());
            ut_check(to_umx(safe_i16::magic_1()) == safe_umx::magic_1());
            ut_check(to_idx(safe_i16::magic_1()) == safe_umx::magic_1());

            auto const max{numeric_limits<int16>::max_value()};    // NOLINT
            ut_check(to_i8(safe_i16::max_value()).is_invalid());
            ut_check(to_i16(safe_i16::max_value()) == static_cast<int16>(max));
            ut_check(to_i32(safe_i16::max_value()) == static_cast<int32>(max));
            ut_check(to_i64(safe_i16::max_value()) == static_cast<int64>(max));
            ut_check(to_u8(safe_i16::max_value()).is_invalid());
            ut_check(to_u16(safe_i16::max_value()) == static_cast<uint16>(max));
            ut_check(to_u32(safe_i16::max_value()) == static_cast<uint32>(max));
            ut_check(to_u64(safe_i16::max_value()) == static_cast<uint64>(max));
            ut_check(to_umx(safe_i16::max_value()) == static_cast<uintmx>(max));
            ut_check(to_idx(safe_i16::max_value()) == static_cast<uintmx>(max));

            auto const min{numeric_limits<int16>::min_value()};    // NOLINT
            ut_check(to_i8(safe_i16::min_value()).is_invalid());
            ut_check(to_i16(safe_i16::min_value()) == static_cast<int16>(min));
            ut_check(to_i32(safe_i16::min_value()) == static_cast<int32>(min));
            ut_check(to_i64(safe_i16::min_value()) == static_cast<int64>(min));
            ut_check(to_u8(safe_i16::min_value()).is_invalid());
            ut_check(to_u16(safe_i16::min_value()).is_invalid());
            ut_check(to_u32(safe_i16::min_value()).is_invalid());
            ut_check(to_u64(safe_i16::min_value()).is_invalid());
            ut_check(to_umx(safe_i16::min_value()).is_invalid());
            bsl::ut_given_at_runtime{} = []() noexcept {
                ut_check(to_idx(safe_i16::min_value()).is_invalid());
            };
        };

        bsl::ut_scenario{"bsl::int16"} = []() noexcept {
            ut_check(to_i8(static_cast<int16>(-1)) == safe_i8::magic_neg_1());
            ut_check(to_i16(static_cast<int16>(-1)) == safe_i16::magic_neg_1());
            ut_check(to_i32(static_cast<int16>(-1)) == safe_i32::magic_neg_1());
            ut_check(to_i64(static_cast<int16>(-1)) == safe_i64::magic_neg_1());
            ut_check(to_u8(static_cast<int16>(-1)).is_invalid());
            ut_check(to_u16(static_cast<int16>(-1)).is_invalid());
            ut_check(to_u32(static_cast<int16>(-1)).is_invalid());
            ut_check(to_u64(static_cast<int16>(-1)).is_invalid());
            ut_check(to_umx(static_cast<int16>(-1)).is_invalid());

            ut_check(to_i8(static_cast<int16>(0)) == safe_i8::magic_0());
            ut_check(to_i16(static_cast<int16>(0)) == safe_i16::magic_0());
            ut_check(to_i32(static_cast<int16>(0)) == safe_i32::magic_0());
            ut_check(to_i64(static_cast<int16>(0)) == safe_i64::magic_0());
            ut_check(to_u8(static_cast<int16>(0)) == safe_u8::magic_0());
            ut_check(to_u16(static_cast<int16>(0)) == safe_u16::magic_0());
            ut_check(to_u32(static_cast<int16>(0)) == safe_u32::magic_0());
            ut_check(to_u64(static_cast<int16>(0)) == safe_u64::magic_0());
            ut_check(to_umx(static_cast<int16>(0)) == safe_umx::magic_0());
            ut_check(to_idx(static_cast<int16>(0)) == safe_umx::magic_0());

            ut_check(to_i8(static_cast<int16>(1)) == safe_i8::magic_1());
            ut_check(to_i16(static_cast<int16>(1)) == safe_i16::magic_1());
            ut_check(to_i32(static_cast<int16>(1)) == safe_i32::magic_1());
            ut_check(to_i64(static_cast<int16>(1)) == safe_i64::magic_1());
            ut_check(to_u8(static_cast<int16>(1)) == safe_u8::magic_1());
            ut_check(to_u16(static_cast<int16>(1)) == safe_u16::magic_1());
            ut_check(to_u32(static_cast<int16>(1)) == safe_u32::magic_1());
            ut_check(to_u64(static_cast<int16>(1)) == safe_u64::magic_1());
            ut_check(to_umx(static_cast<int16>(1)) == safe_umx::magic_1());
            ut_check(to_idx(static_cast<int16>(1)) == safe_umx::magic_1());

            auto const max{numeric_limits<int16>::max_value()};    // NOLINT
            ut_check(to_i8(numeric_limits<int16>::max_value()).is_invalid());
            ut_check(to_i16(numeric_limits<int16>::max_value()) == static_cast<int16>(max));
            ut_check(to_i32(numeric_limits<int16>::max_value()) == static_cast<int32>(max));
            ut_check(to_i64(numeric_limits<int16>::max_value()) == static_cast<int64>(max));
            ut_check(to_u8(numeric_limits<int16>::max_value()).is_invalid());
            ut_check(to_u16(numeric_limits<int16>::max_value()) == static_cast<uint16>(max));
            ut_check(to_u32(numeric_limits<int16>::max_value()) == static_cast<uint32>(max));
            ut_check(to_u64(numeric_limits<int16>::max_value()) == static_cast<uint64>(max));
            ut_check(to_umx(numeric_limits<int16>::max_value()) == static_cast<uintmx>(max));
            ut_check(to_idx(numeric_limits<int16>::max_value()) == static_cast<uintmx>(max));

            auto const min{numeric_limits<int16>::min_value()};    // NOLINT
            ut_check(to_i8(numeric_limits<int16>::min_value()).is_invalid());
            ut_check(to_i16(numeric_limits<int16>::min_value()) == static_cast<int16>(min));
            ut_check(to_i32(numeric_limits<int16>::min_value()) == static_cast<int32>(min));
            ut_check(to_i64(numeric_limits<int16>::min_value()) == static_cast<int64>(min));
            ut_check(to_u8(numeric_limits<int16>::min_value()).is_invalid());
            ut_check(to_u16(numeric_limits<int16>::min_value()).is_invalid());
            ut_check(to_u32(numeric_limits<int16>::min_value()).is_invalid());
            ut_check(to_u64(numeric_limits<int16>::min_value()).is_invalid());
            ut_check(to_umx(numeric_limits<int16>::min_value()).is_invalid());
            bsl::ut_given_at_runtime{} = []() noexcept {
                ut_check(to_idx(numeric_limits<int16>::min_value()).is_invalid());
            };
        };

        // ---------------------------------------------------------------------
        // int32
        // ---------------------------------------------------------------------

        bsl::ut_scenario{"bsl::safe_i32"} = []() noexcept {
            ut_check(to_i8(safe_i32::failure()).is_invalid());
            ut_check(to_i16(safe_i32::failure()).is_invalid());
            ut_check(to_i32(safe_i32::failure()).is_invalid());
            ut_check(to_i64(safe_i32::failure()).is_invalid());
            ut_check(to_u8(safe_i32::failure()).is_invalid());
            ut_check(to_u16(safe_i32::failure()).is_invalid());
            ut_check(to_u32(safe_i32::failure()).is_invalid());
            ut_check(to_u64(safe_i32::failure()).is_invalid());
            ut_check(to_umx(safe_i32::failure()).is_invalid());
            bsl::ut_given_at_runtime{} = []() noexcept {
                ut_check(to_idx(safe_i32::failure()).is_invalid());
            };

            ut_check(to_i8(safe_i32::magic_neg_1()) == safe_i8::magic_neg_1());
            ut_check(to_i16(safe_i32::magic_neg_1()) == safe_i16::magic_neg_1());
            ut_check(to_i32(safe_i32::magic_neg_1()) == safe_i32::magic_neg_1());
            ut_check(to_i64(safe_i32::magic_neg_1()) == safe_i64::magic_neg_1());
            ut_check(to_u8(safe_i32::magic_neg_1()).is_invalid());
            ut_check(to_u16(safe_i32::magic_neg_1()).is_invalid());
            ut_check(to_u32(safe_i32::magic_neg_1()).is_invalid());
            ut_check(to_u64(safe_i32::magic_neg_1()).is_invalid());
            ut_check(to_umx(safe_i32::magic_neg_1()).is_invalid());

            ut_check(to_i8(safe_i32::magic_0()) == safe_i8::magic_0());
            ut_check(to_i16(safe_i32::magic_0()) == safe_i16::magic_0());
            ut_check(to_i32(safe_i32::magic_0()) == safe_i32::magic_0());
            ut_check(to_i64(safe_i32::magic_0()) == safe_i64::magic_0());
            ut_check(to_u8(safe_i32::magic_0()) == safe_u8::magic_0());
            ut_check(to_u16(safe_i32::magic_0()) == safe_u16::magic_0());
            ut_check(to_u32(safe_i32::magic_0()) == safe_u32::magic_0());
            ut_check(to_u64(safe_i32::magic_0()) == safe_u64::magic_0());
            ut_check(to_umx(safe_i32::magic_0()) == safe_umx::magic_0());
            ut_check(to_idx(safe_i32::magic_0()) == safe_umx::magic_0());

            ut_check(to_i8(safe_i32::magic_1()) == safe_i8::magic_1());
            ut_check(to_i16(safe_i32::magic_1()) == safe_i16::magic_1());
            ut_check(to_i32(safe_i32::magic_1()) == safe_i32::magic_1());
            ut_check(to_i64(safe_i32::magic_1()) == safe_i64::magic_1());
            ut_check(to_u8(safe_i32::magic_1()) == safe_u8::magic_1());
            ut_check(to_u16(safe_i32::magic_1()) == safe_u16::magic_1());
            ut_check(to_u32(safe_i32::magic_1()) == safe_u32::magic_1());
            ut_check(to_u64(safe_i32::magic_1()) == safe_u64::magic_1());
            ut_check(to_umx(safe_i32::magic_1()) == safe_umx::magic_1());
            ut_check(to_idx(safe_i32::magic_1()) == safe_umx::magic_1());

            auto const max{numeric_limits<int32>::max_value()};    // NOLINT
            ut_check(to_i8(safe_i32::max_value()).is_invalid());
            ut_check(to_i16(safe_i32::max_value()).is_invalid());
            ut_check(to_i32(safe_i32::max_value()) == static_cast<int32>(max));
            ut_check(to_i64(safe_i32::max_value()) == static_cast<int64>(max));
            ut_check(to_u8(safe_i32::max_value()).is_invalid());
            ut_check(to_u16(safe_i32::max_value()).is_invalid());
            ut_check(to_u32(safe_i32::max_value()) == static_cast<uint32>(max));
            ut_check(to_u64(safe_i32::max_value()) == static_cast<uint64>(max));
            ut_check(to_umx(safe_i32::max_value()) == static_cast<uintmx>(max));
            ut_check(to_idx(safe_i32::max_value()) == static_cast<uintmx>(max));

            auto const min{numeric_limits<int32>::min_value()};    // NOLINT
            ut_check(to_i8(safe_i32::min_value()).is_invalid());
            ut_check(to_i16(safe_i32::min_value()).is_invalid());
            ut_check(to_i32(safe_i32::min_value()) == static_cast<int32>(min));
            ut_check(to_i64(safe_i32::min_value()) == static_cast<int64>(min));
            ut_check(to_u8(safe_i32::min_value()).is_invalid());
            ut_check(to_u16(safe_i32::min_value()).is_invalid());
            ut_check(to_u32(safe_i32::min_value()).is_invalid());
            ut_check(to_u64(safe_i32::min_value()).is_invalid());
            ut_check(to_umx(safe_i32::min_value()).is_invalid());
            bsl::ut_given_at_runtime{} = []() noexcept {
                ut_check(to_idx(safe_i32::min_value()).is_invalid());
            };
        };

        bsl::ut_scenario{"bsl::int32"} = []() noexcept {
            ut_check(to_i8(static_cast<int32>(-1)) == safe_i8::magic_neg_1());
            ut_check(to_i16(static_cast<int32>(-1)) == safe_i16::magic_neg_1());
            ut_check(to_i32(static_cast<int32>(-1)) == safe_i32::magic_neg_1());
            ut_check(to_i64(static_cast<int32>(-1)) == safe_i64::magic_neg_1());
            ut_check(to_u8(static_cast<int32>(-1)).is_invalid());
            ut_check(to_u16(static_cast<int32>(-1)).is_invalid());
            ut_check(to_u32(static_cast<int32>(-1)).is_invalid());
            ut_check(to_u64(static_cast<int32>(-1)).is_invalid());
            ut_check(to_umx(static_cast<int32>(-1)).is_invalid());

            ut_check(to_i8(static_cast<int32>(0)) == safe_i8::magic_0());
            ut_check(to_i16(static_cast<int32>(0)) == safe_i16::magic_0());
            ut_check(to_i32(static_cast<int32>(0)) == safe_i32::magic_0());
            ut_check(to_i64(static_cast<int32>(0)) == safe_i64::magic_0());
            ut_check(to_u8(static_cast<int32>(0)) == safe_u8::magic_0());
            ut_check(to_u16(static_cast<int32>(0)) == safe_u16::magic_0());
            ut_check(to_u32(static_cast<int32>(0)) == safe_u32::magic_0());
            ut_check(to_u64(static_cast<int32>(0)) == safe_u64::magic_0());
            ut_check(to_umx(static_cast<int32>(0)) == safe_umx::magic_0());
            ut_check(to_idx(static_cast<int32>(0)) == safe_umx::magic_0());

            ut_check(to_i8(static_cast<int32>(1)) == safe_i8::magic_1());
            ut_check(to_i16(static_cast<int32>(1)) == safe_i16::magic_1());
            ut_check(to_i32(static_cast<int32>(1)) == safe_i32::magic_1());
            ut_check(to_i64(static_cast<int32>(1)) == safe_i64::magic_1());
            ut_check(to_u8(static_cast<int32>(1)) == safe_u8::magic_1());
            ut_check(to_u16(static_cast<int32>(1)) == safe_u16::magic_1());
            ut_check(to_u32(static_cast<int32>(1)) == safe_u32::magic_1());
            ut_check(to_u64(static_cast<int32>(1)) == safe_u64::magic_1());
            ut_check(to_umx(static_cast<int32>(1)) == safe_umx::magic_1());
            ut_check(to_idx(static_cast<int32>(1)) == safe_umx::magic_1());

            auto const max{numeric_limits<int32>::max_value()};    // NOLINT
            ut_check(to_i8(numeric_limits<int32>::max_value()).is_invalid());
            ut_check(to_i16(numeric_limits<int32>::max_value()).is_invalid());
            ut_check(to_i32(numeric_limits<int32>::max_value()) == static_cast<int32>(max));
            ut_check(to_i64(numeric_limits<int32>::max_value()) == static_cast<int64>(max));
            ut_check(to_u8(numeric_limits<int32>::max_value()).is_invalid());
            ut_check(to_u16(numeric_limits<int32>::max_value()).is_invalid());
            ut_check(to_u32(numeric_limits<int32>::max_value()) == static_cast<uint32>(max));
            ut_check(to_u64(numeric_limits<int32>::max_value()) == static_cast<uint64>(max));
            ut_check(to_umx(numeric_limits<int32>::max_value()) == static_cast<uintmx>(max));
            ut_check(to_idx(numeric_limits<int32>::max_value()) == static_cast<uintmx>(max));

            auto const min{numeric_limits<int32>::min_value()};    // NOLINT
            ut_check(to_i8(numeric_limits<int32>::min_value()).is_invalid());
            ut_check(to_i16(numeric_limits<int32>::min_value()).is_invalid());
            ut_check(to_i32(numeric_limits<int32>::min_value()) == static_cast<int32>(min));
            ut_check(to_i64(numeric_limits<int32>::min_value()) == static_cast<int64>(min));
            ut_check(to_u8(numeric_limits<int32>::min_value()).is_invalid());
            ut_check(to_u16(numeric_limits<int32>::min_value()).is_invalid());
            ut_check(to_u32(numeric_limits<int32>::min_value()).is_invalid());
            ut_check(to_u64(numeric_limits<int32>::min_value()).is_invalid());
            ut_check(to_umx(numeric_limits<int32>::min_value()).is_invalid());
            bsl::ut_given_at_runtime{} = []() noexcept {
                ut_check(to_idx(numeric_limits<int32>::min_value()).is_invalid());
            };
        };

        // ---------------------------------------------------------------------
        // int64
        // ---------------------------------------------------------------------

        bsl::ut_scenario{"bsl::safe_i64"} = []() noexcept {
            ut_check(to_i8(safe_i64::failure()).is_invalid());
            ut_check(to_i16(safe_i64::failure()).is_invalid());
            ut_check(to_i32(safe_i64::failure()).is_invalid());
            ut_check(to_i64(safe_i64::failure()).is_invalid());
            ut_check(to_u8(safe_i64::failure()).is_invalid());
            ut_check(to_u16(safe_i64::failure()).is_invalid());
            ut_check(to_u32(safe_i64::failure()).is_invalid());
            ut_check(to_u64(safe_i64::failure()).is_invalid());
            ut_check(to_umx(safe_i64::failure()).is_invalid());
            bsl::ut_given_at_runtime{} = []() noexcept {
                ut_check(to_idx(safe_i64::failure()).is_invalid());
            };

            ut_check(to_i8(safe_i64::magic_neg_1()) == safe_i8::magic_neg_1());
            ut_check(to_i16(safe_i64::magic_neg_1()) == safe_i16::magic_neg_1());
            ut_check(to_i32(safe_i64::magic_neg_1()) == safe_i32::magic_neg_1());
            ut_check(to_i64(safe_i64::magic_neg_1()) == safe_i64::magic_neg_1());
            ut_check(to_u8(safe_i64::magic_neg_1()).is_invalid());
            ut_check(to_u16(safe_i64::magic_neg_1()).is_invalid());
            ut_check(to_u32(safe_i64::magic_neg_1()).is_invalid());
            ut_check(to_u64(safe_i64::magic_neg_1()).is_invalid());
            ut_check(to_umx(safe_i64::magic_neg_1()).is_invalid());

            ut_check(to_i8(safe_i64::magic_0()) == safe_i8::magic_0());
            ut_check(to_i16(safe_i64::magic_0()) == safe_i16::magic_0());
            ut_check(to_i32(safe_i64::magic_0()) == safe_i32::magic_0());
            ut_check(to_i64(safe_i64::magic_0()) == safe_i64::magic_0());
            ut_check(to_u8(safe_i64::magic_0()) == safe_u8::magic_0());
            ut_check(to_u16(safe_i64::magic_0()) == safe_u16::magic_0());
            ut_check(to_u32(safe_i64::magic_0()) == safe_u32::magic_0());
            ut_check(to_u64(safe_i64::magic_0()) == safe_u64::magic_0());
            ut_check(to_umx(safe_i64::magic_0()) == safe_umx::magic_0());
            ut_check(to_idx(safe_i64::magic_0()) == safe_umx::magic_0());

            ut_check(to_i8(safe_i64::magic_1()) == safe_i8::magic_1());
            ut_check(to_i16(safe_i64::magic_1()) == safe_i16::magic_1());
            ut_check(to_i32(safe_i64::magic_1()) == safe_i32::magic_1());
            ut_check(to_i64(safe_i64::magic_1()) == safe_i64::magic_1());
            ut_check(to_u8(safe_i64::magic_1()) == safe_u8::magic_1());
            ut_check(to_u16(safe_i64::magic_1()) == safe_u16::magic_1());
            ut_check(to_u32(safe_i64::magic_1()) == safe_u32::magic_1());
            ut_check(to_u64(safe_i64::magic_1()) == safe_u64::magic_1());
            ut_check(to_umx(safe_i64::magic_1()) == safe_umx::magic_1());
            ut_check(to_idx(safe_i64::magic_1()) == safe_umx::magic_1());

            auto const max{numeric_limits<int64>::max_value()};    // NOLINT
            ut_check(to_i8(safe_i64::max_value()).is_invalid());
            ut_check(to_i16(safe_i64::max_value()).is_invalid());
            ut_check(to_i32(safe_i64::max_value()).is_invalid());
            ut_check(to_i64(safe_i64::max_value()) == static_cast<int64>(max));
            ut_check(to_u8(safe_i64::max_value()).is_invalid());
            ut_check(to_u16(safe_i64::max_value()).is_invalid());
            ut_check(to_u32(safe_i64::max_value()).is_invalid());
            ut_check(to_u64(safe_i64::max_value()) == static_cast<uint64>(max));
            ut_check(to_umx(safe_i64::max_value()) == static_cast<uintmx>(max));
            ut_check(to_idx(safe_i64::max_value()) == static_cast<uintmx>(max));

            auto const min{numeric_limits<int64>::min_value()};    // NOLINT
            ut_check(to_i8(safe_i64::min_value()).is_invalid());
            ut_check(to_i16(safe_i64::min_value()).is_invalid());
            ut_check(to_i32(safe_i64::min_value()).is_invalid());
            ut_check(to_i64(safe_i64::min_value()) == static_cast<int64>(min));
            ut_check(to_u8(safe_i64::min_value()).is_invalid());
            ut_check(to_u16(safe_i64::min_value()).is_invalid());
            ut_check(to_u32(safe_i64::min_value()).is_invalid());
            ut_check(to_u64(safe_i64::min_value()).is_invalid());
            ut_check(to_umx(safe_i64::min_value()).is_invalid());
            bsl::ut_given_at_runtime{} = []() noexcept {
                ut_check(to_idx(safe_i64::min_value()).is_invalid());
            };
        };

        bsl::ut_scenario{"bsl::int64"} = []() noexcept {
            ut_check(to_i8(static_cast<int64>(-1)) == safe_i8::magic_neg_1());
            ut_check(to_i16(static_cast<int64>(-1)) == safe_i16::magic_neg_1());
            ut_check(to_i32(static_cast<int64>(-1)) == safe_i32::magic_neg_1());
            ut_check(to_i64(static_cast<int64>(-1)) == safe_i64::magic_neg_1());
            ut_check(to_u8(static_cast<int64>(-1)).is_invalid());
            ut_check(to_u16(static_cast<int64>(-1)).is_invalid());
            ut_check(to_u32(static_cast<int64>(-1)).is_invalid());
            ut_check(to_u64(static_cast<int64>(-1)).is_invalid());
            ut_check(to_umx(static_cast<int64>(-1)).is_invalid());

            ut_check(to_i8(static_cast<int64>(0)) == safe_i8::magic_0());
            ut_check(to_i16(static_cast<int64>(0)) == safe_i16::magic_0());
            ut_check(to_i32(static_cast<int64>(0)) == safe_i32::magic_0());
            ut_check(to_i64(static_cast<int64>(0)) == safe_i64::magic_0());
            ut_check(to_u8(static_cast<int64>(0)) == safe_u8::magic_0());
            ut_check(to_u16(static_cast<int64>(0)) == safe_u16::magic_0());
            ut_check(to_u32(static_cast<int64>(0)) == safe_u32::magic_0());
            ut_check(to_u64(static_cast<int64>(0)) == safe_u64::magic_0());
            ut_check(to_umx(static_cast<int64>(0)) == safe_umx::magic_0());
            ut_check(to_idx(static_cast<int64>(0)) == safe_umx::magic_0());

            ut_check(to_i8(static_cast<int64>(1)) == safe_i8::magic_1());
            ut_check(to_i16(static_cast<int64>(1)) == safe_i16::magic_1());
            ut_check(to_i32(static_cast<int64>(1)) == safe_i32::magic_1());
            ut_check(to_i64(static_cast<int64>(1)) == safe_i64::magic_1());
            ut_check(to_u8(static_cast<int64>(1)) == safe_u8::magic_1());
            ut_check(to_u16(static_cast<int64>(1)) == safe_u16::magic_1());
            ut_check(to_u32(static_cast<int64>(1)) == safe_u32::magic_1());
            ut_check(to_u64(static_cast<int64>(1)) == safe_u64::magic_1());
            ut_check(to_umx(static_cast<int64>(1)) == safe_umx::magic_1());
            ut_check(to_idx(static_cast<int64>(1)) == safe_umx::magic_1());

            auto const max{numeric_limits<int64>::max_value()};    // NOLINT
            ut_check(to_i8(numeric_limits<int64>::max_value()).is_invalid());
            ut_check(to_i16(numeric_limits<int64>::max_value()).is_invalid());
            ut_check(to_i32(numeric_limits<int64>::max_value()).is_invalid());
            ut_check(to_i64(numeric_limits<int64>::max_value()) == static_cast<int64>(max));
            ut_check(to_u8(numeric_limits<int64>::max_value()).is_invalid());
            ut_check(to_u16(numeric_limits<int64>::max_value()).is_invalid());
            ut_check(to_u32(numeric_limits<int64>::max_value()).is_invalid());
            ut_check(to_u64(numeric_limits<int64>::max_value()) == static_cast<uint64>(max));
            ut_check(to_umx(numeric_limits<int64>::max_value()) == static_cast<uintmx>(max));
            ut_check(to_idx(numeric_limits<int64>::max_value()) == static_cast<uintmx>(max));

            auto const min{numeric_limits<int64>::min_value()};    // NOLINT
            ut_check(to_i8(numeric_limits<int64>::min_value()).is_invalid());
            ut_check(to_i16(numeric_limits<int64>::min_value()).is_invalid());
            ut_check(to_i32(numeric_limits<int64>::min_value()).is_invalid());
            ut_check(to_i64(numeric_limits<int64>::min_value()) == static_cast<int64>(min));
            ut_check(to_u8(numeric_limits<int64>::min_value()).is_invalid());
            ut_check(to_u16(numeric_limits<int64>::min_value()).is_invalid());
            ut_check(to_u32(numeric_limits<int64>::min_value()).is_invalid());
            ut_check(to_u64(numeric_limits<int64>::min_value()).is_invalid());
            ut_check(to_umx(numeric_limits<int64>::min_value()).is_invalid());
            bsl::ut_given_at_runtime{} = []() noexcept {
                ut_check(to_idx(numeric_limits<int64>::min_value()).is_invalid());
            };
        };

        // ---------------------------------------------------------------------
        // uint8
        // ---------------------------------------------------------------------

        bsl::ut_scenario{"bsl::safe_u8"} = []() noexcept {
            ut_check(to_i8(safe_u8::failure()).is_invalid());
            ut_check(to_i16(safe_u8::failure()).is_invalid());
            ut_check(to_i32(safe_u8::failure()).is_invalid());
            ut_check(to_i64(safe_u8::failure()).is_invalid());
            ut_check(to_u8(safe_u8::failure()).is_invalid());
            ut_check(to_u16(safe_u8::failure()).is_invalid());
            ut_check(to_u32(safe_u8::failure()).is_invalid());
            ut_check(to_u64(safe_u8::failure()).is_invalid());
            ut_check(to_umx(safe_u8::failure()).is_invalid());
            bsl::ut_given_at_runtime{} = []() noexcept {
                ut_check(to_idx(safe_u8::failure()).is_invalid());
            };

            ut_check(to_i8(safe_u8::magic_0()) == safe_i8::magic_0());
            ut_check(to_i16(safe_u8::magic_0()) == safe_i16::magic_0());
            ut_check(to_i32(safe_u8::magic_0()) == safe_i32::magic_0());
            ut_check(to_i64(safe_u8::magic_0()) == safe_i64::magic_0());
            ut_check(to_u8(safe_u8::magic_0()) == safe_u8::magic_0());
            ut_check(to_u16(safe_u8::magic_0()) == safe_u16::magic_0());
            ut_check(to_u32(safe_u8::magic_0()) == safe_u32::magic_0());
            ut_check(to_u64(safe_u8::magic_0()) == safe_u64::magic_0());
            ut_check(to_umx(safe_u8::magic_0()) == safe_umx::magic_0());
            ut_check(to_idx(safe_u8::magic_0()) == safe_umx::magic_0());

            ut_check(to_i8(safe_u8::magic_1()) == safe_i8::magic_1());
            ut_check(to_i16(safe_u8::magic_1()) == safe_i16::magic_1());
            ut_check(to_i32(safe_u8::magic_1()) == safe_i32::magic_1());
            ut_check(to_i64(safe_u8::magic_1()) == safe_i64::magic_1());
            ut_check(to_u8(safe_u8::magic_1()) == safe_u8::magic_1());
            ut_check(to_u16(safe_u8::magic_1()) == safe_u16::magic_1());
            ut_check(to_u32(safe_u8::magic_1()) == safe_u32::magic_1());
            ut_check(to_u64(safe_u8::magic_1()) == safe_u64::magic_1());
            ut_check(to_umx(safe_u8::magic_1()) == safe_umx::magic_1());
            ut_check(to_idx(safe_u8::magic_1()) == safe_umx::magic_1());

            auto const max{numeric_limits<uint8>::max_value()};    // NOLINT
            ut_check(to_i8(safe_u8::max_value()).is_invalid());
            ut_check(to_i16(safe_u8::max_value()) == static_cast<int16>(max));
            ut_check(to_i32(safe_u8::max_value()) == static_cast<int32>(max));
            ut_check(to_i64(safe_u8::max_value()) == static_cast<int64>(max));
            ut_check(to_u8(safe_u8::max_value()) == static_cast<uint8>(max));
            ut_check(to_u16(safe_u8::max_value()) == static_cast<uint16>(max));
            ut_check(to_u32(safe_u8::max_value()) == static_cast<uint32>(max));
            ut_check(to_u64(safe_u8::max_value()) == static_cast<uint64>(max));
            ut_check(to_umx(safe_u8::max_value()) == static_cast<uintmx>(max));
            ut_check(to_idx(safe_u8::max_value()) == static_cast<uintmx>(max));

            auto const min{numeric_limits<uint8>::min_value()};    // NOLINT
            ut_check(to_i8(safe_u8::min_value()) == static_cast<int8>(min));
            ut_check(to_i16(safe_u8::min_value()) == static_cast<int16>(min));
            ut_check(to_i32(safe_u8::min_value()) == static_cast<int32>(min));
            ut_check(to_i64(safe_u8::min_value()) == static_cast<int64>(min));
            ut_check(to_u8(safe_u8::min_value()) == static_cast<uint8>(min));
            ut_check(to_u16(safe_u8::min_value()) == static_cast<uint16>(min));
            ut_check(to_u32(safe_u8::min_value()) == static_cast<uint32>(min));
            ut_check(to_u64(safe_u8::min_value()) == static_cast<uint64>(min));
            ut_check(to_umx(safe_u8::min_value()) == static_cast<uintmx>(min));
            ut_check(to_idx(safe_u8::min_value()) == static_cast<uintmx>(min));
        };

        bsl::ut_scenario{"bsl::uint8"} = []() noexcept {
            ut_check(to_i8(static_cast<uint8>(0)) == safe_i8::magic_0());
            ut_check(to_i16(static_cast<uint8>(0)) == safe_i16::magic_0());
            ut_check(to_i32(static_cast<uint8>(0)) == safe_i32::magic_0());
            ut_check(to_i64(static_cast<uint8>(0)) == safe_i64::magic_0());
            ut_check(to_u8(static_cast<uint8>(0)) == safe_u8::magic_0());
            ut_check(to_u16(static_cast<uint8>(0)) == safe_u16::magic_0());
            ut_check(to_u32(static_cast<uint8>(0)) == safe_u32::magic_0());
            ut_check(to_u64(static_cast<uint8>(0)) == safe_u64::magic_0());
            ut_check(to_umx(static_cast<uint8>(0)) == safe_umx::magic_0());
            ut_check(to_idx(static_cast<uint8>(0)) == safe_umx::magic_0());

            ut_check(to_i8(static_cast<uint8>(1)) == safe_i8::magic_1());
            ut_check(to_i16(static_cast<uint8>(1)) == safe_i16::magic_1());
            ut_check(to_i32(static_cast<uint8>(1)) == safe_i32::magic_1());
            ut_check(to_i64(static_cast<uint8>(1)) == safe_i64::magic_1());
            ut_check(to_u8(static_cast<uint8>(1)) == safe_u8::magic_1());
            ut_check(to_u16(static_cast<uint8>(1)) == safe_u16::magic_1());
            ut_check(to_u32(static_cast<uint8>(1)) == safe_u32::magic_1());
            ut_check(to_u64(static_cast<uint8>(1)) == safe_u64::magic_1());
            ut_check(to_umx(static_cast<uint8>(1)) == safe_umx::magic_1());
            ut_check(to_idx(static_cast<uint8>(1)) == safe_umx::magic_1());

            auto const max{numeric_limits<uint8>::max_value()};    // NOLINT
            ut_check(to_i8(numeric_limits<uint8>::max_value()).is_invalid());
            ut_check(to_i16(numeric_limits<uint8>::max_value()) == static_cast<int16>(max));
            ut_check(to_i32(numeric_limits<uint8>::max_value()) == static_cast<int32>(max));
            ut_check(to_i64(numeric_limits<uint8>::max_value()) == static_cast<int64>(max));
            ut_check(to_u8(numeric_limits<uint8>::max_value()) == static_cast<uint8>(max));
            ut_check(to_u16(numeric_limits<uint8>::max_value()) == static_cast<uint16>(max));
            ut_check(to_u32(numeric_limits<uint8>::max_value()) == static_cast<uint32>(max));
            ut_check(to_u64(numeric_limits<uint8>::max_value()) == static_cast<uint64>(max));
            ut_check(to_umx(numeric_limits<uint8>::max_value()) == static_cast<uintmx>(max));
            ut_check(to_idx(numeric_limits<uint8>::max_value()) == static_cast<uintmx>(max));

            auto const min{numeric_limits<uint8>::min_value()};    // NOLINT
            ut_check(to_i8(numeric_limits<uint8>::min_value()) == static_cast<int8>(min));
            ut_check(to_i16(numeric_limits<uint8>::min_value()) == static_cast<int16>(min));
            ut_check(to_i32(numeric_limits<uint8>::min_value()) == static_cast<int32>(min));
            ut_check(to_i64(numeric_limits<uint8>::min_value()) == static_cast<int64>(min));
            ut_check(to_u8(numeric_limits<uint8>::min_value()) == static_cast<uint8>(min));
            ut_check(to_u16(numeric_limits<uint8>::min_value()) == static_cast<uint16>(min));
            ut_check(to_u32(numeric_limits<uint8>::min_value()) == static_cast<uint32>(min));
            ut_check(to_u64(numeric_limits<uint8>::min_value()) == static_cast<uint64>(min));
            ut_check(to_umx(numeric_limits<uint8>::min_value()) == static_cast<uintmx>(min));
            ut_check(to_idx(numeric_limits<uint8>::min_value()) == static_cast<uintmx>(min));
        };

        // ---------------------------------------------------------------------
        // uint16
        // ---------------------------------------------------------------------

        bsl::ut_scenario{"bsl::safe_u16"} = []() noexcept {
            ut_check(to_i8(safe_u16::failure()).is_invalid());
            ut_check(to_i16(safe_u16::failure()).is_invalid());
            ut_check(to_i32(safe_u16::failure()).is_invalid());
            ut_check(to_i64(safe_u16::failure()).is_invalid());
            ut_check(to_u8(safe_u16::failure()).is_invalid());
            ut_check(to_u16(safe_u16::failure()).is_invalid());
            ut_check(to_u32(safe_u16::failure()).is_invalid());
            ut_check(to_u64(safe_u16::failure()).is_invalid());
            ut_check(to_umx(safe_u16::failure()).is_invalid());
            bsl::ut_given_at_runtime{} = []() noexcept {
                ut_check(to_idx(safe_u16::failure()).is_invalid());
            };

            ut_check(to_i8(safe_u16::magic_0()) == safe_i8::magic_0());
            ut_check(to_i16(safe_u16::magic_0()) == safe_i16::magic_0());
            ut_check(to_i32(safe_u16::magic_0()) == safe_i32::magic_0());
            ut_check(to_i64(safe_u16::magic_0()) == safe_i64::magic_0());
            ut_check(to_u8(safe_u16::magic_0()) == safe_u8::magic_0());
            ut_check(to_u16(safe_u16::magic_0()) == safe_u16::magic_0());
            ut_check(to_u32(safe_u16::magic_0()) == safe_u32::magic_0());
            ut_check(to_u64(safe_u16::magic_0()) == safe_u64::magic_0());
            ut_check(to_umx(safe_u16::magic_0()) == safe_umx::magic_0());
            ut_check(to_idx(safe_u16::magic_0()) == safe_umx::magic_0());

            ut_check(to_i8(safe_u16::magic_1()) == safe_i8::magic_1());
            ut_check(to_i16(safe_u16::magic_1()) == safe_i16::magic_1());
            ut_check(to_i32(safe_u16::magic_1()) == safe_i32::magic_1());
            ut_check(to_i64(safe_u16::magic_1()) == safe_i64::magic_1());
            ut_check(to_u8(safe_u16::magic_1()) == safe_u8::magic_1());
            ut_check(to_u16(safe_u16::magic_1()) == safe_u16::magic_1());
            ut_check(to_u32(safe_u16::magic_1()) == safe_u32::magic_1());
            ut_check(to_u64(safe_u16::magic_1()) == safe_u64::magic_1());
            ut_check(to_umx(safe_u16::magic_1()) == safe_umx::magic_1());
            ut_check(to_idx(safe_u16::magic_1()) == safe_umx::magic_1());

            auto const max{numeric_limits<uint16>::max_value()};    // NOLINT
            ut_check(to_i8(safe_u16::max_value()).is_invalid());
            ut_check(to_i16(safe_u16::max_value()).is_invalid());
            ut_check(to_i32(safe_u16::max_value()) == static_cast<int32>(max));
            ut_check(to_i64(safe_u16::max_value()) == static_cast<int64>(max));
            ut_check(to_u8(safe_u16::max_value()).is_invalid());
            ut_check(to_u16(safe_u16::max_value()) == static_cast<uint16>(max));
            ut_check(to_u32(safe_u16::max_value()) == static_cast<uint32>(max));
            ut_check(to_u64(safe_u16::max_value()) == static_cast<uint64>(max));
            ut_check(to_umx(safe_u16::max_value()) == static_cast<uintmx>(max));
            ut_check(to_idx(safe_u16::max_value()) == static_cast<uintmx>(max));

            auto const min{numeric_limits<uint16>::min_value()};    // NOLINT
            ut_check(to_i8(safe_u16::min_value()) == static_cast<int8>(min));
            ut_check(to_i16(safe_u16::min_value()) == static_cast<int16>(min));
            ut_check(to_i32(safe_u16::min_value()) == static_cast<int32>(min));
            ut_check(to_i64(safe_u16::min_value()) == static_cast<int64>(min));
            ut_check(to_u8(safe_u16::min_value()) == static_cast<uint8>(min));
            ut_check(to_u16(safe_u16::min_value()) == static_cast<uint16>(min));
            ut_check(to_u32(safe_u16::min_value()) == static_cast<uint32>(min));
            ut_check(to_u64(safe_u16::min_value()) == static_cast<uint64>(min));
            ut_check(to_umx(safe_u16::min_value()) == static_cast<uintmx>(min));
            ut_check(to_idx(safe_u16::min_value()) == static_cast<uintmx>(min));
        };

        bsl::ut_scenario{"bsl::uint16"} = []() noexcept {
            ut_check(to_i8(static_cast<uint16>(0)) == safe_i8::magic_0());
            ut_check(to_i16(static_cast<uint16>(0)) == safe_i16::magic_0());
            ut_check(to_i32(static_cast<uint16>(0)) == safe_i32::magic_0());
            ut_check(to_i64(static_cast<uint16>(0)) == safe_i64::magic_0());
            ut_check(to_u8(static_cast<uint16>(0)) == safe_u8::magic_0());
            ut_check(to_u16(static_cast<uint16>(0)) == safe_u16::magic_0());
            ut_check(to_u32(static_cast<uint16>(0)) == safe_u32::magic_0());
            ut_check(to_u64(static_cast<uint16>(0)) == safe_u64::magic_0());
            ut_check(to_umx(static_cast<uint16>(0)) == safe_umx::magic_0());
            ut_check(to_idx(static_cast<uint16>(0)) == safe_umx::magic_0());

            ut_check(to_i8(static_cast<uint16>(1)) == safe_i8::magic_1());
            ut_check(to_i16(static_cast<uint16>(1)) == safe_i16::magic_1());
            ut_check(to_i32(static_cast<uint16>(1)) == safe_i32::magic_1());
            ut_check(to_i64(static_cast<uint16>(1)) == safe_i64::magic_1());
            ut_check(to_u8(static_cast<uint16>(1)) == safe_u8::magic_1());
            ut_check(to_u16(static_cast<uint16>(1)) == safe_u16::magic_1());
            ut_check(to_u32(static_cast<uint16>(1)) == safe_u32::magic_1());
            ut_check(to_u64(static_cast<uint16>(1)) == safe_u64::magic_1());
            ut_check(to_umx(static_cast<uint16>(1)) == safe_umx::magic_1());
            ut_check(to_idx(static_cast<uint16>(1)) == safe_umx::magic_1());

            auto const max{numeric_limits<uint16>::max_value()};    // NOLINT
            ut_check(to_i8(numeric_limits<uint16>::max_value()).is_invalid());
            ut_check(to_i16(numeric_limits<uint16>::max_value()).is_invalid());
            ut_check(to_i32(numeric_limits<uint16>::max_value()) == static_cast<int32>(max));
            ut_check(to_i64(numeric_limits<uint16>::max_value()) == static_cast<int64>(max));
            ut_check(to_u8(numeric_limits<uint16>::max_value()).is_invalid());
            ut_check(to_u16(numeric_limits<uint16>::max_value()) == static_cast<uint16>(max));
            ut_check(to_u32(numeric_limits<uint16>::max_value()) == static_cast<uint32>(max));
            ut_check(to_u64(numeric_limits<uint16>::max_value()) == static_cast<uint64>(max));
            ut_check(to_umx(numeric_limits<uint16>::max_value()) == static_cast<uintmx>(max));
            ut_check(to_idx(numeric_limits<uint16>::max_value()) == static_cast<uintmx>(max));

            auto const min{numeric_limits<uint16>::min_value()};    // NOLINT
            ut_check(to_i8(numeric_limits<uint16>::min_value()) == static_cast<int8>(min));
            ut_check(to_i16(numeric_limits<uint16>::min_value()) == static_cast<int16>(min));
            ut_check(to_i32(numeric_limits<uint16>::min_value()) == static_cast<int32>(min));
            ut_check(to_i64(numeric_limits<uint16>::min_value()) == static_cast<int64>(min));
            ut_check(to_u8(numeric_limits<uint16>::min_value()) == static_cast<uint8>(min));
            ut_check(to_u16(numeric_limits<uint16>::min_value()) == static_cast<uint16>(min));
            ut_check(to_u32(numeric_limits<uint16>::min_value()) == static_cast<uint32>(min));
            ut_check(to_u64(numeric_limits<uint16>::min_value()) == static_cast<uint64>(min));
            ut_check(to_umx(numeric_limits<uint16>::min_value()) == static_cast<uintmx>(min));
            ut_check(to_idx(numeric_limits<uint16>::min_value()) == static_cast<uintmx>(min));
        };

        // ---------------------------------------------------------------------
        // uint32
        // ---------------------------------------------------------------------

        bsl::ut_scenario{"bsl::safe_u32"} = []() noexcept {
            ut_check(to_i8(safe_u32::failure()).is_invalid());
            ut_check(to_i16(safe_u32::failure()).is_invalid());
            ut_check(to_i32(safe_u32::failure()).is_invalid());
            ut_check(to_i64(safe_u32::failure()).is_invalid());
            ut_check(to_u8(safe_u32::failure()).is_invalid());
            ut_check(to_u16(safe_u32::failure()).is_invalid());
            ut_check(to_u32(safe_u32::failure()).is_invalid());
            ut_check(to_u64(safe_u32::failure()).is_invalid());
            ut_check(to_umx(safe_u32::failure()).is_invalid());
            bsl::ut_given_at_runtime{} = []() noexcept {
                ut_check(to_idx(safe_u32::failure()).is_invalid());
            };

            ut_check(to_i8(safe_u32::magic_0()) == safe_i8::magic_0());
            ut_check(to_i16(safe_u32::magic_0()) == safe_i16::magic_0());
            ut_check(to_i32(safe_u32::magic_0()) == safe_i32::magic_0());
            ut_check(to_i64(safe_u32::magic_0()) == safe_i64::magic_0());
            ut_check(to_u8(safe_u32::magic_0()) == safe_u8::magic_0());
            ut_check(to_u16(safe_u32::magic_0()) == safe_u16::magic_0());
            ut_check(to_u32(safe_u32::magic_0()) == safe_u32::magic_0());
            ut_check(to_u64(safe_u32::magic_0()) == safe_u64::magic_0());
            ut_check(to_umx(safe_u32::magic_0()) == safe_umx::magic_0());
            ut_check(to_idx(safe_u32::magic_0()) == safe_umx::magic_0());

            ut_check(to_i8(safe_u32::magic_1()) == safe_i8::magic_1());
            ut_check(to_i16(safe_u32::magic_1()) == safe_i16::magic_1());
            ut_check(to_i32(safe_u32::magic_1()) == safe_i32::magic_1());
            ut_check(to_i64(safe_u32::magic_1()) == safe_i64::magic_1());
            ut_check(to_u8(safe_u32::magic_1()) == safe_u8::magic_1());
            ut_check(to_u16(safe_u32::magic_1()) == safe_u16::magic_1());
            ut_check(to_u32(safe_u32::magic_1()) == safe_u32::magic_1());
            ut_check(to_u64(safe_u32::magic_1()) == safe_u64::magic_1());
            ut_check(to_umx(safe_u32::magic_1()) == safe_umx::magic_1());
            ut_check(to_idx(safe_u32::magic_1()) == safe_umx::magic_1());

            auto const max{numeric_limits<uint32>::max_value()};    // NOLINT
            ut_check(to_i8(safe_u32::max_value()).is_invalid());
            ut_check(to_i16(safe_u32::max_value()).is_invalid());
            ut_check(to_i32(safe_u32::max_value()).is_invalid());
            ut_check(to_i64(safe_u32::max_value()) == static_cast<int64>(max));
            ut_check(to_u8(safe_u32::max_value()).is_invalid());
            ut_check(to_u16(safe_u32::max_value()).is_invalid());
            ut_check(to_u32(safe_u32::max_value()) == static_cast<uint32>(max));
            ut_check(to_u64(safe_u32::max_value()) == static_cast<uint64>(max));
            ut_check(to_umx(safe_u32::max_value()) == static_cast<uintmx>(max));
            ut_check(to_idx(safe_u32::max_value()) == static_cast<uintmx>(max));

            auto const min{numeric_limits<uint32>::min_value()};    // NOLINT
            ut_check(to_i8(safe_u32::min_value()) == static_cast<int8>(min));
            ut_check(to_i16(safe_u32::min_value()) == static_cast<int16>(min));
            ut_check(to_i32(safe_u32::min_value()) == static_cast<int32>(min));
            ut_check(to_i64(safe_u32::min_value()) == static_cast<int64>(min));
            ut_check(to_u8(safe_u32::min_value()) == static_cast<uint8>(min));
            ut_check(to_u16(safe_u32::min_value()) == static_cast<uint16>(min));
            ut_check(to_u32(safe_u32::min_value()) == static_cast<uint32>(min));
            ut_check(to_u64(safe_u32::min_value()) == static_cast<uint64>(min));
            ut_check(to_umx(safe_u32::min_value()) == static_cast<uintmx>(min));
            ut_check(to_idx(safe_u32::min_value()) == static_cast<uintmx>(min));
        };

        bsl::ut_scenario{"bsl::safe_u32"} = []() noexcept {
            ut_check(to_i8(static_cast<uint32>(0)) == safe_i8::magic_0());
            ut_check(to_i16(static_cast<uint32>(0)) == safe_i16::magic_0());
            ut_check(to_i32(static_cast<uint32>(0)) == safe_i32::magic_0());
            ut_check(to_i64(static_cast<uint32>(0)) == safe_i64::magic_0());
            ut_check(to_u8(static_cast<uint32>(0)) == safe_u8::magic_0());
            ut_check(to_u16(static_cast<uint32>(0)) == safe_u16::magic_0());
            ut_check(to_u32(static_cast<uint32>(0)) == safe_u32::magic_0());
            ut_check(to_u64(static_cast<uint32>(0)) == safe_u64::magic_0());
            ut_check(to_umx(static_cast<uint32>(0)) == safe_umx::magic_0());
            ut_check(to_idx(static_cast<uint32>(0)) == safe_umx::magic_0());

            ut_check(to_i8(static_cast<uint32>(1)) == safe_i8::magic_1());
            ut_check(to_i16(static_cast<uint32>(1)) == safe_i16::magic_1());
            ut_check(to_i32(static_cast<uint32>(1)) == safe_i32::magic_1());
            ut_check(to_i64(static_cast<uint32>(1)) == safe_i64::magic_1());
            ut_check(to_u8(static_cast<uint32>(1)) == safe_u8::magic_1());
            ut_check(to_u16(static_cast<uint32>(1)) == safe_u16::magic_1());
            ut_check(to_u32(static_cast<uint32>(1)) == safe_u32::magic_1());
            ut_check(to_u64(static_cast<uint32>(1)) == safe_u64::magic_1());
            ut_check(to_umx(static_cast<uint32>(1)) == safe_umx::magic_1());
            ut_check(to_idx(static_cast<uint32>(1)) == safe_umx::magic_1());

            auto const max{numeric_limits<uint32>::max_value()};    // NOLINT
            ut_check(to_i8(numeric_limits<uint32>::max_value()).is_invalid());
            ut_check(to_i16(numeric_limits<uint32>::max_value()).is_invalid());
            ut_check(to_i32(numeric_limits<uint32>::max_value()).is_invalid());
            ut_check(to_i64(numeric_limits<uint32>::max_value()) == static_cast<int64>(max));
            ut_check(to_u8(numeric_limits<uint32>::max_value()).is_invalid());
            ut_check(to_u16(numeric_limits<uint32>::max_value()).is_invalid());
            ut_check(to_u32(numeric_limits<uint32>::max_value()) == static_cast<uint32>(max));
            ut_check(to_u64(numeric_limits<uint32>::max_value()) == static_cast<uint64>(max));
            ut_check(to_umx(numeric_limits<uint32>::max_value()) == static_cast<uintmx>(max));
            ut_check(to_idx(numeric_limits<uint32>::max_value()) == static_cast<uintmx>(max));

            auto const min{numeric_limits<uint32>::min_value()};    // NOLINT
            ut_check(to_i8(numeric_limits<uint32>::min_value()) == static_cast<int8>(min));
            ut_check(to_i16(numeric_limits<uint32>::min_value()) == static_cast<int16>(min));
            ut_check(to_i32(numeric_limits<uint32>::min_value()) == static_cast<int32>(min));
            ut_check(to_i64(numeric_limits<uint32>::min_value()) == static_cast<int64>(min));
            ut_check(to_u8(numeric_limits<uint32>::min_value()) == static_cast<uint8>(min));
            ut_check(to_u16(numeric_limits<uint32>::min_value()) == static_cast<uint16>(min));
            ut_check(to_u32(numeric_limits<uint32>::min_value()) == static_cast<uint32>(min));
            ut_check(to_u64(numeric_limits<uint32>::min_value()) == static_cast<uint64>(min));
            ut_check(to_umx(numeric_limits<uint32>::min_value()) == static_cast<uintmx>(min));
            ut_check(to_idx(numeric_limits<uint32>::min_value()) == static_cast<uintmx>(min));
        };

        // ---------------------------------------------------------------------
        // uint64
        // ---------------------------------------------------------------------

        bsl::ut_scenario{"bsl::safe_u64"} = []() noexcept {
            ut_check(to_i8(safe_u64::failure()).is_invalid());
            ut_check(to_i16(safe_u64::failure()).is_invalid());
            ut_check(to_i32(safe_u64::failure()).is_invalid());
            ut_check(to_i64(safe_u64::failure()).is_invalid());
            ut_check(to_u8(safe_u64::failure()).is_invalid());
            ut_check(to_u16(safe_u64::failure()).is_invalid());
            ut_check(to_u32(safe_u64::failure()).is_invalid());
            ut_check(to_u64(safe_u64::failure()).is_invalid());
            ut_check(to_umx(safe_u64::failure()).is_invalid());
            bsl::ut_given_at_runtime{} = []() noexcept {
                ut_check(to_idx(safe_u64::failure()).is_invalid());
            };

            ut_check(to_i8(safe_u64::magic_0()) == safe_i8::magic_0());
            ut_check(to_i16(safe_u64::magic_0()) == safe_i16::magic_0());
            ut_check(to_i32(safe_u64::magic_0()) == safe_i32::magic_0());
            ut_check(to_i64(safe_u64::magic_0()) == safe_i64::magic_0());
            ut_check(to_u8(safe_u64::magic_0()) == safe_u8::magic_0());
            ut_check(to_u16(safe_u64::magic_0()) == safe_u16::magic_0());
            ut_check(to_u32(safe_u64::magic_0()) == safe_u32::magic_0());
            ut_check(to_u64(safe_u64::magic_0()) == safe_u64::magic_0());
            ut_check(to_umx(safe_u64::magic_0()) == safe_umx::magic_0());
            ut_check(to_idx(safe_u64::magic_0()) == safe_umx::magic_0());

            ut_check(to_i8(safe_u64::magic_1()) == safe_i8::magic_1());
            ut_check(to_i16(safe_u64::magic_1()) == safe_i16::magic_1());
            ut_check(to_i32(safe_u64::magic_1()) == safe_i32::magic_1());
            ut_check(to_i64(safe_u64::magic_1()) == safe_i64::magic_1());
            ut_check(to_u8(safe_u64::magic_1()) == safe_u8::magic_1());
            ut_check(to_u16(safe_u64::magic_1()) == safe_u16::magic_1());
            ut_check(to_u32(safe_u64::magic_1()) == safe_u32::magic_1());
            ut_check(to_u64(safe_u64::magic_1()) == safe_u64::magic_1());
            ut_check(to_umx(safe_u64::magic_1()) == safe_umx::magic_1());
            ut_check(to_idx(safe_u64::magic_1()) == safe_umx::magic_1());

            auto const max{numeric_limits<uint64>::max_value()};    // NOLINT
            ut_check(to_i8(safe_u64::max_value()).is_invalid());
            ut_check(to_i16(safe_u64::max_value()).is_invalid());
            ut_check(to_i32(safe_u64::max_value()).is_invalid());
            ut_check(to_i64(safe_u64::max_value()).is_invalid());
            ut_check(to_u8(safe_u64::max_value()).is_invalid());
            ut_check(to_u16(safe_u64::max_value()).is_invalid());
            ut_check(to_u32(safe_u64::max_value()).is_invalid());
            ut_check(to_u64(safe_u64::max_value()) == static_cast<uint64>(max));
            ut_check(to_umx(safe_u64::max_value()) == static_cast<uintmx>(max));
            ut_check(to_idx(safe_u64::max_value()) == static_cast<uintmx>(max));

            auto const min{numeric_limits<uint64>::min_value()};    // NOLINT
            ut_check(to_i8(safe_u64::min_value()) == static_cast<int8>(min));
            ut_check(to_i16(safe_u64::min_value()) == static_cast<int16>(min));
            ut_check(to_i32(safe_u64::min_value()) == static_cast<int32>(min));
            ut_check(to_i64(safe_u64::min_value()) == static_cast<int64>(min));
            ut_check(to_u8(safe_u64::min_value()) == static_cast<uint8>(min));
            ut_check(to_u16(safe_u64::min_value()) == static_cast<uint16>(min));
            ut_check(to_u32(safe_u64::min_value()) == static_cast<uint32>(min));
            ut_check(to_u64(safe_u64::min_value()) == static_cast<uint64>(min));
            ut_check(to_umx(safe_u64::min_value()) == static_cast<uintmx>(min));
            ut_check(to_idx(safe_u64::min_value()) == static_cast<uintmx>(min));
        };

        bsl::ut_scenario{"bsl::uint64"} = []() noexcept {
            ut_check(to_i8(static_cast<uint64>(0)) == safe_i8::magic_0());
            ut_check(to_i16(static_cast<uint64>(0)) == safe_i16::magic_0());
            ut_check(to_i32(static_cast<uint64>(0)) == safe_i32::magic_0());
            ut_check(to_i64(static_cast<uint64>(0)) == safe_i64::magic_0());
            ut_check(to_u8(static_cast<uint64>(0)) == safe_u8::magic_0());
            ut_check(to_u16(static_cast<uint64>(0)) == safe_u16::magic_0());
            ut_check(to_u32(static_cast<uint64>(0)) == safe_u32::magic_0());
            ut_check(to_u64(static_cast<uint64>(0)) == safe_u64::magic_0());
            ut_check(to_umx(static_cast<uint64>(0)) == safe_umx::magic_0());
            ut_check(to_idx(static_cast<uint64>(0)) == safe_umx::magic_0());

            ut_check(to_i8(static_cast<uint64>(1)) == safe_i8::magic_1());
            ut_check(to_i16(static_cast<uint64>(1)) == safe_i16::magic_1());
            ut_check(to_i32(static_cast<uint64>(1)) == safe_i32::magic_1());
            ut_check(to_i64(static_cast<uint64>(1)) == safe_i64::magic_1());
            ut_check(to_u8(static_cast<uint64>(1)) == safe_u8::magic_1());
            ut_check(to_u16(static_cast<uint64>(1)) == safe_u16::magic_1());
            ut_check(to_u32(static_cast<uint64>(1)) == safe_u32::magic_1());
            ut_check(to_u64(static_cast<uint64>(1)) == safe_u64::magic_1());
            ut_check(to_umx(static_cast<uint64>(1)) == safe_umx::magic_1());
            ut_check(to_idx(static_cast<uint64>(1)) == safe_umx::magic_1());

            auto const max{numeric_limits<uint64>::max_value()};    // NOLINT
            ut_check(to_i8(numeric_limits<uint64>::max_value()).is_invalid());
            ut_check(to_i16(numeric_limits<uint64>::max_value()).is_invalid());
            ut_check(to_i32(numeric_limits<uint64>::max_value()).is_invalid());
            ut_check(to_i64(numeric_limits<uint64>::max_value()).is_invalid());
            ut_check(to_u8(numeric_limits<uint64>::max_value()).is_invalid());
            ut_check(to_u16(numeric_limits<uint64>::max_value()).is_invalid());
            ut_check(to_u32(numeric_limits<uint64>::max_value()).is_invalid());
            ut_check(to_u64(numeric_limits<uint64>::max_value()) == static_cast<uint64>(max));
            ut_check(to_umx(numeric_limits<uint64>::max_value()) == static_cast<uintmx>(max));
            ut_check(to_idx(numeric_limits<uint64>::max_value()) == static_cast<uintmx>(max));

            auto const min{numeric_limits<uint64>::min_value()};    // NOLINT
            ut_check(to_i8(numeric_limits<uint64>::min_value()) == static_cast<int8>(min));
            ut_check(to_i16(numeric_limits<uint64>::min_value()) == static_cast<int16>(min));
            ut_check(to_i32(numeric_limits<uint64>::min_value()) == static_cast<int32>(min));
            ut_check(to_i64(numeric_limits<uint64>::min_value()) == static_cast<int64>(min));
            ut_check(to_u8(numeric_limits<uint64>::min_value()) == static_cast<uint8>(min));
            ut_check(to_u16(numeric_limits<uint64>::min_value()) == static_cast<uint16>(min));
            ut_check(to_u32(numeric_limits<uint64>::min_value()) == static_cast<uint32>(min));
            ut_check(to_u64(numeric_limits<uint64>::min_value()) == static_cast<uint64>(min));
            ut_check(to_umx(numeric_limits<uint64>::min_value()) == static_cast<uintmx>(min));
            ut_check(to_idx(numeric_limits<uint64>::min_value()) == static_cast<uintmx>(min));
        };

        // ---------------------------------------------------------------------
        // uintmx
        // ---------------------------------------------------------------------

        bsl::ut_scenario{"bsl::safe_umx"} = []() noexcept {
            ut_check(to_i8(safe_umx::failure()).is_invalid());
            ut_check(to_i16(safe_umx::failure()).is_invalid());
            ut_check(to_i32(safe_umx::failure()).is_invalid());
            ut_check(to_i64(safe_umx::failure()).is_invalid());
            ut_check(to_u8(safe_umx::failure()).is_invalid());
            ut_check(to_u16(safe_umx::failure()).is_invalid());
            ut_check(to_u32(safe_umx::failure()).is_invalid());
            ut_check(to_u64(safe_umx::failure()).is_invalid());
            ut_check(to_umx(safe_umx::failure()).is_invalid());
            bsl::ut_given_at_runtime{} = []() noexcept {
                ut_check(to_idx(safe_umx::failure()).is_invalid());
            };

            ut_check(to_i8(safe_umx::magic_0()) == safe_i8::magic_0());
            ut_check(to_i16(safe_umx::magic_0()) == safe_i16::magic_0());
            ut_check(to_i32(safe_umx::magic_0()) == safe_i32::magic_0());
            ut_check(to_i64(safe_umx::magic_0()) == safe_i64::magic_0());
            ut_check(to_u8(safe_umx::magic_0()) == safe_u8::magic_0());
            ut_check(to_u16(safe_umx::magic_0()) == safe_u16::magic_0());
            ut_check(to_u32(safe_umx::magic_0()) == safe_u32::magic_0());
            ut_check(to_u64(safe_umx::magic_0()) == safe_u64::magic_0());
            ut_check(to_umx(safe_umx::magic_0()) == safe_umx::magic_0());
            ut_check(to_idx(safe_umx::magic_0()) == safe_umx::magic_0());

            ut_check(to_i8(safe_umx::magic_1()) == safe_i8::magic_1());
            ut_check(to_i16(safe_umx::magic_1()) == safe_i16::magic_1());
            ut_check(to_i32(safe_umx::magic_1()) == safe_i32::magic_1());
            ut_check(to_i64(safe_umx::magic_1()) == safe_i64::magic_1());
            ut_check(to_u8(safe_umx::magic_1()) == safe_u8::magic_1());
            ut_check(to_u16(safe_umx::magic_1()) == safe_u16::magic_1());
            ut_check(to_u32(safe_umx::magic_1()) == safe_u32::magic_1());
            ut_check(to_u64(safe_umx::magic_1()) == safe_u64::magic_1());
            ut_check(to_umx(safe_umx::magic_1()) == safe_umx::magic_1());
            ut_check(to_idx(safe_umx::magic_1()) == safe_umx::magic_1());

            auto const max{numeric_limits<uintmx>::max_value()};    // NOLINT
            ut_check(to_i8(safe_umx::max_value()).is_invalid());
            ut_check(to_i16(safe_umx::max_value()).is_invalid());
            ut_check(to_i32(safe_umx::max_value()).is_invalid());
            ut_check(to_i64(safe_umx::max_value()).is_invalid());
            ut_check(to_u8(safe_umx::max_value()).is_invalid());
            ut_check(to_u16(safe_umx::max_value()).is_invalid());
            ut_check(to_u32(safe_umx::max_value()).is_invalid());
            ut_check(to_u64(safe_umx::max_value()) == static_cast<uint64>(max));
            ut_check(to_umx(safe_umx::max_value()) == static_cast<uintmx>(max));
            ut_check(to_idx(safe_umx::max_value()) == static_cast<uintmx>(max));

            auto const min{numeric_limits<uintmx>::min_value()};    // NOLINT
            ut_check(to_i8(safe_umx::min_value()) == static_cast<int8>(min));
            ut_check(to_i16(safe_umx::min_value()) == static_cast<int16>(min));
            ut_check(to_i32(safe_umx::min_value()) == static_cast<int32>(min));
            ut_check(to_i64(safe_umx::min_value()) == static_cast<int64>(min));
            ut_check(to_u8(safe_umx::min_value()) == static_cast<uint8>(min));
            ut_check(to_u16(safe_umx::min_value()) == static_cast<uint16>(min));
            ut_check(to_u32(safe_umx::min_value()) == static_cast<uint32>(min));
            ut_check(to_u64(safe_umx::min_value()) == static_cast<uint64>(min));
            ut_check(to_umx(safe_umx::min_value()) == static_cast<uintmx>(min));
            ut_check(to_idx(safe_umx::min_value()) == static_cast<uintmx>(min));
        };

        bsl::ut_scenario{"bsl::uintmx"} = []() noexcept {
            ut_check(to_i8(static_cast<uintmx>(0)) == safe_i8::magic_0());
            ut_check(to_i16(static_cast<uintmx>(0)) == safe_i16::magic_0());
            ut_check(to_i32(static_cast<uintmx>(0)) == safe_i32::magic_0());
            ut_check(to_i64(static_cast<uintmx>(0)) == safe_i64::magic_0());
            ut_check(to_u8(static_cast<uintmx>(0)) == safe_u8::magic_0());
            ut_check(to_u16(static_cast<uintmx>(0)) == safe_u16::magic_0());
            ut_check(to_u32(static_cast<uintmx>(0)) == safe_u32::magic_0());
            ut_check(to_u64(static_cast<uintmx>(0)) == safe_u64::magic_0());
            ut_check(to_umx(static_cast<uintmx>(0)) == safe_umx::magic_0());
            ut_check(to_idx(static_cast<uintmx>(0)) == safe_umx::magic_0());

            ut_check(to_i8(static_cast<uintmx>(1)) == safe_i8::magic_1());
            ut_check(to_i16(static_cast<uintmx>(1)) == safe_i16::magic_1());
            ut_check(to_i32(static_cast<uintmx>(1)) == safe_i32::magic_1());
            ut_check(to_i64(static_cast<uintmx>(1)) == safe_i64::magic_1());
            ut_check(to_u8(static_cast<uintmx>(1)) == safe_u8::magic_1());
            ut_check(to_u16(static_cast<uintmx>(1)) == safe_u16::magic_1());
            ut_check(to_u32(static_cast<uintmx>(1)) == safe_u32::magic_1());
            ut_check(to_u64(static_cast<uintmx>(1)) == safe_u64::magic_1());
            ut_check(to_umx(static_cast<uintmx>(1)) == safe_umx::magic_1());
            ut_check(to_idx(static_cast<uintmx>(1)) == safe_umx::magic_1());

            auto const max{numeric_limits<uintmx>::max_value()};    // NOLINT
            ut_check(to_i8(numeric_limits<uintmx>::max_value()).is_invalid());
            ut_check(to_i16(numeric_limits<uintmx>::max_value()).is_invalid());
            ut_check(to_i32(numeric_limits<uintmx>::max_value()).is_invalid());
            ut_check(to_i64(numeric_limits<uintmx>::max_value()).is_invalid());
            ut_check(to_u8(numeric_limits<uintmx>::max_value()).is_invalid());
            ut_check(to_u16(numeric_limits<uintmx>::max_value()).is_invalid());
            ut_check(to_u32(numeric_limits<uintmx>::max_value()).is_invalid());
            ut_check(to_u64(numeric_limits<uintmx>::max_value()) == static_cast<uint64>(max));
            ut_check(to_umx(numeric_limits<uintmx>::max_value()) == static_cast<uintmx>(max));
            ut_check(to_idx(numeric_limits<uintmx>::max_value()) == static_cast<uintmx>(max));

            auto const min{numeric_limits<uintmx>::min_value()};    // NOLINT
            ut_check(to_i8(numeric_limits<uintmx>::min_value()) == static_cast<int8>(min));
            ut_check(to_i16(numeric_limits<uintmx>::min_value()) == static_cast<int16>(min));
            ut_check(to_i32(numeric_limits<uintmx>::min_value()) == static_cast<int32>(min));
            ut_check(to_i64(numeric_limits<uintmx>::min_value()) == static_cast<int64>(min));
            ut_check(to_u8(numeric_limits<uintmx>::min_value()) == static_cast<uint8>(min));
            ut_check(to_u16(numeric_limits<uintmx>::min_value()) == static_cast<uint16>(min));
            ut_check(to_u32(numeric_limits<uintmx>::min_value()) == static_cast<uint32>(min));
            ut_check(to_u64(numeric_limits<uintmx>::min_value()) == static_cast<uint64>(min));
            ut_check(to_umx(numeric_limits<uintmx>::min_value()) == static_cast<uintmx>(min));
            ut_check(to_idx(numeric_limits<uintmx>::min_value()) == static_cast<uintmx>(min));
        };

        // ---------------------------------------------------------------------
        // idx
        // ---------------------------------------------------------------------

        bsl::ut_scenario{"bsl::safe_idx"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                auto const val{safe_idx::max_value() + safe_idx::magic_1()};
                ut_check(to_i8(val).is_invalid());
                ut_check(to_i16(val).is_invalid());
                ut_check(to_i32(val).is_invalid());
                ut_check(to_i64(val).is_invalid());
                ut_check(to_u8(val).is_invalid());
                ut_check(to_u16(val).is_invalid());
                ut_check(to_u32(val).is_invalid());
                ut_check(to_u64(val).is_invalid());
                ut_check(to_umx(val).is_invalid());
                ut_check(to_idx(val).is_invalid());
            };

            ut_check(to_i8(safe_idx::magic_0()) == safe_i8::magic_0());
            ut_check(to_i16(safe_idx::magic_0()) == safe_i16::magic_0());
            ut_check(to_i32(safe_idx::magic_0()) == safe_i32::magic_0());
            ut_check(to_i64(safe_idx::magic_0()) == safe_i64::magic_0());
            ut_check(to_u8(safe_idx::magic_0()) == safe_u8::magic_0());
            ut_check(to_u16(safe_idx::magic_0()) == safe_u16::magic_0());
            ut_check(to_u32(safe_idx::magic_0()) == safe_u32::magic_0());
            ut_check(to_u64(safe_idx::magic_0()) == safe_u64::magic_0());
            ut_check(to_umx(safe_idx::magic_0()) == safe_umx::magic_0());
            ut_check(to_idx(safe_idx::magic_0()) == safe_umx::magic_0());

            ut_check(to_i8(safe_idx::magic_1()) == safe_i8::magic_1());
            ut_check(to_i16(safe_idx::magic_1()) == safe_i16::magic_1());
            ut_check(to_i32(safe_idx::magic_1()) == safe_i32::magic_1());
            ut_check(to_i64(safe_idx::magic_1()) == safe_i64::magic_1());
            ut_check(to_u8(safe_idx::magic_1()) == safe_u8::magic_1());
            ut_check(to_u16(safe_idx::magic_1()) == safe_u16::magic_1());
            ut_check(to_u32(safe_idx::magic_1()) == safe_u32::magic_1());
            ut_check(to_u64(safe_idx::magic_1()) == safe_u64::magic_1());
            ut_check(to_umx(safe_idx::magic_1()) == safe_umx::magic_1());
            ut_check(to_idx(safe_idx::magic_1()) == safe_umx::magic_1());

            auto const max{numeric_limits<uintmx>::max_value()};    // NOLINT
            ut_check(to_i8(safe_idx::max_value()).is_invalid());
            ut_check(to_i16(safe_idx::max_value()).is_invalid());
            ut_check(to_i32(safe_idx::max_value()).is_invalid());
            ut_check(to_i64(safe_idx::max_value()).is_invalid());
            ut_check(to_u8(safe_idx::max_value()).is_invalid());
            ut_check(to_u16(safe_idx::max_value()).is_invalid());
            ut_check(to_u32(safe_idx::max_value()).is_invalid());
            ut_check(to_u64(safe_idx::max_value()) == static_cast<uint64>(max));
            ut_check(to_umx(safe_idx::max_value()) == static_cast<uintmx>(max));
            ut_check(to_idx(safe_idx::max_value()) == static_cast<uintmx>(max));

            auto const min{numeric_limits<uintmx>::min_value()};    // NOLINT
            ut_check(to_i8(safe_idx::min_value()) == static_cast<int8>(min));
            ut_check(to_i16(safe_idx::min_value()) == static_cast<int16>(min));
            ut_check(to_i32(safe_idx::min_value()) == static_cast<int32>(min));
            ut_check(to_i64(safe_idx::min_value()) == static_cast<int64>(min));
            ut_check(to_u8(safe_idx::min_value()) == static_cast<uint8>(min));
            ut_check(to_u16(safe_idx::min_value()) == static_cast<uint16>(min));
            ut_check(to_u32(safe_idx::min_value()) == static_cast<uint32>(min));
            ut_check(to_u64(safe_idx::min_value()) == static_cast<uint64>(min));
            ut_check(to_umx(safe_idx::min_value()) == static_cast<uintmx>(min));
            ut_check(to_idx(safe_idx::min_value()) == static_cast<uintmx>(min));
        };

        // ---------------------------------------------------------------------
        // uint8 unsafe
        // ---------------------------------------------------------------------

        bsl::ut_scenario{"bsl::safe_u8 unsafe"} = []() noexcept {
            auto const max{numeric_limits<uint8>::max_value()};    // NOLINT
            ut_check(to_u8_unsafe(safe_u8::max_value()) == static_cast<uint8>(max));
            ut_check(to_u16_unsafe(safe_u8::max_value()) == static_cast<uint16>(max));
            ut_check(to_u32_unsafe(safe_u8::max_value()) == static_cast<uint32>(max));
            ut_check(to_u64_unsafe(safe_u8::max_value()) == static_cast<uint64>(max));
            ut_check(to_umx_unsafe(safe_u8::max_value()) == static_cast<uintmx>(max));

            auto const min{numeric_limits<uint8>::min_value()};    // NOLINT
            ut_check(to_u8_unsafe(safe_u8::min_value()) == static_cast<uint8>(min));
            ut_check(to_u16_unsafe(safe_u8::min_value()) == static_cast<uint16>(min));
            ut_check(to_u32_unsafe(safe_u8::min_value()) == static_cast<uint32>(min));
            ut_check(to_u64_unsafe(safe_u8::min_value()) == static_cast<uint64>(min));
            ut_check(to_umx_unsafe(safe_u8::min_value()) == static_cast<uintmx>(min));
        };

        bsl::ut_scenario{"bsl::uint8 unsafe"} = []() noexcept {
            auto const max{numeric_limits<uint8>::max_value()};    // NOLINT
            ut_check(to_u8_unsafe(max) == static_cast<uint8>(max));
            ut_check(to_u16_unsafe(max) == static_cast<uint16>(max));
            ut_check(to_u32_unsafe(max) == static_cast<uint32>(max));
            ut_check(to_u64_unsafe(max) == static_cast<uint64>(max));
            ut_check(to_umx_unsafe(max) == static_cast<uintmx>(max));

            auto const min{numeric_limits<uint8>::min_value()};    // NOLINT
            ut_check(to_u8_unsafe(min) == static_cast<uint8>(min));
            ut_check(to_u16_unsafe(min) == static_cast<uint16>(min));
            ut_check(to_u32_unsafe(min) == static_cast<uint32>(min));
            ut_check(to_u64_unsafe(min) == static_cast<uint64>(min));
            ut_check(to_umx_unsafe(min) == static_cast<uintmx>(min));
        };

        // ---------------------------------------------------------------------
        // uint16 unsafe
        // ---------------------------------------------------------------------

        bsl::ut_scenario{"bsl::safe_u16 unsafe"} = []() noexcept {
            auto const max{numeric_limits<uint16>::max_value()};    // NOLINT
            ut_check(to_u8_unsafe(safe_u16::max_value()) == static_cast<uint8>(max));
            ut_check(to_u16_unsafe(safe_u16::max_value()) == static_cast<uint16>(max));
            ut_check(to_u32_unsafe(safe_u16::max_value()) == static_cast<uint32>(max));
            ut_check(to_u64_unsafe(safe_u16::max_value()) == static_cast<uint64>(max));
            ut_check(to_umx_unsafe(safe_u16::max_value()) == static_cast<uintmx>(max));

            auto const min{numeric_limits<uint16>::min_value()};    // NOLINT
            ut_check(to_u8_unsafe(safe_u16::min_value()) == static_cast<uint8>(min));
            ut_check(to_u16_unsafe(safe_u16::min_value()) == static_cast<uint16>(min));
            ut_check(to_u32_unsafe(safe_u16::min_value()) == static_cast<uint32>(min));
            ut_check(to_u64_unsafe(safe_u16::min_value()) == static_cast<uint64>(min));
            ut_check(to_umx_unsafe(safe_u16::min_value()) == static_cast<uintmx>(min));
        };

        bsl::ut_scenario{"bsl::uint16 unsafe"} = []() noexcept {
            auto const max{numeric_limits<uint16>::max_value()};    // NOLINT
            ut_check(to_u8_unsafe(max) == static_cast<uint8>(max));
            ut_check(to_u16_unsafe(max) == static_cast<uint16>(max));
            ut_check(to_u32_unsafe(max) == static_cast<uint32>(max));
            ut_check(to_u64_unsafe(max) == static_cast<uint64>(max));
            ut_check(to_umx_unsafe(max) == static_cast<uintmx>(max));

            auto const min{numeric_limits<uint16>::min_value()};    // NOLINT
            ut_check(to_u8_unsafe(min) == static_cast<uint8>(min));
            ut_check(to_u16_unsafe(min) == static_cast<uint16>(min));
            ut_check(to_u32_unsafe(min) == static_cast<uint32>(min));
            ut_check(to_u64_unsafe(min) == static_cast<uint64>(min));
            ut_check(to_umx_unsafe(min) == static_cast<uintmx>(min));
        };

        // ---------------------------------------------------------------------
        // uint32 unsafe
        // ---------------------------------------------------------------------

        bsl::ut_scenario{"bsl::safe_u32 unsafe"} = []() noexcept {
            auto const max{numeric_limits<uint32>::max_value()};    // NOLINT
            ut_check(to_u8_unsafe(safe_u32::max_value()) == static_cast<uint8>(max));
            ut_check(to_u16_unsafe(safe_u32::max_value()) == static_cast<uint16>(max));
            ut_check(to_u32_unsafe(safe_u32::max_value()) == static_cast<uint32>(max));
            ut_check(to_u64_unsafe(safe_u32::max_value()) == static_cast<uint64>(max));
            ut_check(to_umx_unsafe(safe_u32::max_value()) == static_cast<uintmx>(max));

            auto const min{numeric_limits<uint32>::min_value()};    // NOLINT
            ut_check(to_u8_unsafe(safe_u32::min_value()) == static_cast<uint8>(min));
            ut_check(to_u16_unsafe(safe_u32::min_value()) == static_cast<uint16>(min));
            ut_check(to_u32_unsafe(safe_u32::min_value()) == static_cast<uint32>(min));
            ut_check(to_u64_unsafe(safe_u32::min_value()) == static_cast<uint64>(min));
            ut_check(to_umx_unsafe(safe_u32::min_value()) == static_cast<uintmx>(min));
        };

        bsl::ut_scenario{"bsl::uint32 unsafe"} = []() noexcept {
            auto const max{numeric_limits<uint32>::max_value()};    // NOLINT
            ut_check(to_u8_unsafe(max) == static_cast<uint8>(max));
            ut_check(to_u16_unsafe(max) == static_cast<uint16>(max));
            ut_check(to_u32_unsafe(max) == static_cast<uint32>(max));
            ut_check(to_u64_unsafe(max) == static_cast<uint64>(max));
            ut_check(to_umx_unsafe(max) == static_cast<uintmx>(max));

            auto const min{numeric_limits<uint32>::min_value()};    // NOLINT
            ut_check(to_u8_unsafe(min) == static_cast<uint8>(min));
            ut_check(to_u16_unsafe(min) == static_cast<uint16>(min));
            ut_check(to_u32_unsafe(min) == static_cast<uint32>(min));
            ut_check(to_u64_unsafe(min) == static_cast<uint64>(min));
            ut_check(to_umx_unsafe(min) == static_cast<uintmx>(min));
        };

        // ---------------------------------------------------------------------
        // uint64 unsafe
        // ---------------------------------------------------------------------

        bsl::ut_scenario{"bsl::safe_u64 unsafe"} = []() noexcept {
            auto const max{numeric_limits<uint64>::max_value()};    // NOLINT
            ut_check(to_u8_unsafe(safe_u64::max_value()) == static_cast<uint8>(max));
            ut_check(to_u16_unsafe(safe_u64::max_value()) == static_cast<uint16>(max));
            ut_check(to_u32_unsafe(safe_u64::max_value()) == static_cast<uint32>(max));
            ut_check(to_u64_unsafe(safe_u64::max_value()) == static_cast<uint64>(max));
            ut_check(to_umx_unsafe(safe_u64::max_value()) == static_cast<uintmx>(max));

            auto const min{numeric_limits<uint64>::min_value()};    // NOLINT
            ut_check(to_u8_unsafe(safe_u64::min_value()) == static_cast<uint8>(min));
            ut_check(to_u16_unsafe(safe_u64::min_value()) == static_cast<uint16>(min));
            ut_check(to_u32_unsafe(safe_u64::min_value()) == static_cast<uint32>(min));
            ut_check(to_u64_unsafe(safe_u64::min_value()) == static_cast<uint64>(min));
            ut_check(to_umx_unsafe(safe_u64::min_value()) == static_cast<uintmx>(min));
        };

        bsl::ut_scenario{"bsl::uint64 unsafe"} = []() noexcept {
            auto const max{numeric_limits<uint64>::max_value()};    // NOLINT
            ut_check(to_u8_unsafe(max) == static_cast<uint8>(max));
            ut_check(to_u16_unsafe(max) == static_cast<uint16>(max));
            ut_check(to_u32_unsafe(max) == static_cast<uint32>(max));
            ut_check(to_u64_unsafe(max) == static_cast<uint64>(max));
            ut_check(to_umx_unsafe(max) == static_cast<uintmx>(max));

            auto const min{numeric_limits<uint64>::min_value()};    // NOLINT
            ut_check(to_u8_unsafe(min) == static_cast<uint8>(min));
            ut_check(to_u16_unsafe(min) == static_cast<uint16>(min));
            ut_check(to_u32_unsafe(min) == static_cast<uint32>(min));
            ut_check(to_u64_unsafe(min) == static_cast<uint64>(min));
            ut_check(to_umx_unsafe(min) == static_cast<uintmx>(min));
        };

        // ---------------------------------------------------------------------
        // uintmx unsafe
        // ---------------------------------------------------------------------

        bsl::ut_scenario{"bsl::safe_umx unsafe"} = []() noexcept {
            auto const max{numeric_limits<uintmx>::max_value()};    // NOLINT
            ut_check(to_u8_unsafe(safe_umx::max_value()) == static_cast<uint8>(max));
            ut_check(to_u16_unsafe(safe_umx::max_value()) == static_cast<uint16>(max));
            ut_check(to_u32_unsafe(safe_umx::max_value()) == static_cast<uint32>(max));
            ut_check(to_u64_unsafe(safe_umx::max_value()) == static_cast<uint64>(max));
            ut_check(to_umx_unsafe(safe_umx::max_value()) == static_cast<uintmx>(max));

            auto const min{numeric_limits<uintmx>::min_value()};    // NOLINT
            ut_check(to_u8_unsafe(safe_umx::min_value()) == static_cast<uint8>(min));
            ut_check(to_u16_unsafe(safe_umx::min_value()) == static_cast<uint16>(min));
            ut_check(to_u32_unsafe(safe_umx::min_value()) == static_cast<uint32>(min));
            ut_check(to_u64_unsafe(safe_umx::min_value()) == static_cast<uint64>(min));
            ut_check(to_umx_unsafe(safe_umx::min_value()) == static_cast<uintmx>(min));
        };

        bsl::ut_scenario{"bsl::uintmx unsafe"} = []() noexcept {
            auto const max{numeric_limits<uintmx>::max_value()};    // NOLINT
            ut_check(to_u8_unsafe(max) == static_cast<uint8>(max));
            ut_check(to_u16_unsafe(max) == static_cast<uint16>(max));
            ut_check(to_u32_unsafe(max) == static_cast<uint32>(max));
            ut_check(to_u64_unsafe(max) == static_cast<uint64>(max));
            ut_check(to_umx_unsafe(max) == static_cast<uintmx>(max));

            auto const min{numeric_limits<uintmx>::min_value()};    // NOLINT
            ut_check(to_u8_unsafe(min) == static_cast<uint8>(min));
            ut_check(to_u16_unsafe(min) == static_cast<uint16>(min));
            ut_check(to_u32_unsafe(min) == static_cast<uint32>(min));
            ut_check(to_u64_unsafe(min) == static_cast<uint64>(min));
            ut_check(to_umx_unsafe(min) == static_cast<uintmx>(min));
        };

        // ---------------------------------------------------------------------
        // merge functions
        // ---------------------------------------------------------------------

        bsl::ut_scenario{"merge"} = []() noexcept {
            constexpr auto uppermx{0x1234567890ABCDEF_umx};
            constexpr auto lower08{0xFF_u8};
            constexpr auto lower16{0xFFFF_u16};
            constexpr auto lower32{0xFFFFFFFF_u32};

            ut_check(merge_umx_with_u8(uppermx, lower08) == 0x1234567890ABCDFF_umx);
            ut_check(merge_umx_with_u16(uppermx, lower16) == 0x1234567890ABFFFF_umx);
            ut_check(merge_umx_with_u32(uppermx, lower32) == 0x12345678FFFFFFFF_umx);

            ut_check(merge_umx_with_u8(uppermx.get(), lower08) == 0x1234567890ABCDFF_umx);
            ut_check(merge_umx_with_u16(uppermx.get(), lower16) == 0x1234567890ABFFFF_umx);
            ut_check(merge_umx_with_u32(uppermx.get(), lower32) == 0x12345678FFFFFFFF_umx);
        };

        // ---------------------------------------------------------------------
        // literals
        // ---------------------------------------------------------------------

        bsl::ut_scenario{"literals"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                ut_check((0xFFFFFFFFFFFFFFFFFFFFFFFF_u8).is_invalid());
                ut_check((0xFFFFFFFFFFFFFFFFFFFFFFFF_u16).is_invalid());
                ut_check((0xFFFFFFFFFFFFFFFFFFFFFFFF_u32).is_invalid());
                ut_check((0xFFFFFFFFFFFFFFFFFFFFFFFF_u64).is_invalid());
                ut_check((0xFFFFFFFFFFFFFFFFFFFFFFFF_umx).is_invalid());
                ut_check((0xFFFFFFFFFFFFFFFFFFFFFFFF_idx).is_valid());

                ut_check((999999999999999999999999999_i8).is_invalid());
                ut_check((999999999999999999999999999_i16).is_invalid());
                ut_check((999999999999999999999999999_i32).is_invalid());
                ut_check((999999999999999999999999999_i64).is_invalid());
                ut_check((999999999999999999999999999_u8).is_invalid());
                ut_check((999999999999999999999999999_u16).is_invalid());
                ut_check((999999999999999999999999999_u32).is_invalid());
                ut_check((999999999999999999999999999_u64).is_invalid());
                ut_check((999999999999999999999999999_umx).is_invalid());
                ut_check((999999999999999999999999999_idx).is_valid());
            };

            ut_check((-1_i8).is_neg());
            ut_check((-1_i16).is_neg());
            ut_check((-1_i32).is_neg());
            ut_check((-1_i64).is_neg());

            ut_check((0x0_u8).is_zero());
            ut_check((0x0_u16).is_zero());
            ut_check((0x0_u32).is_zero());
            ut_check((0x0_u64).is_zero());
            ut_check((0x0_umx).is_zero());
            ut_check((0x0_idx).is_zero());

            ut_check((0_i8).is_zero());
            ut_check((0_i16).is_zero());
            ut_check((0_i32).is_zero());
            ut_check((0_i64).is_zero());
            ut_check((0_u8).is_zero());
            ut_check((0_u16).is_zero());
            ut_check((0_u32).is_zero());
            ut_check((0_u64).is_zero());
            ut_check((0_umx).is_zero());
            ut_check((0_idx).is_zero());

            ut_check((0x1_u8).is_pos());
            ut_check((0x1_u16).is_pos());
            ut_check((0x1_u32).is_pos());
            ut_check((0x1_u64).is_pos());
            ut_check((0x1_umx).is_pos());
            ut_check((0x1_idx).is_pos());

            ut_check((1_i8).is_pos());
            ut_check((1_i16).is_pos());
            ut_check((1_i32).is_pos());
            ut_check((1_i64).is_pos());
            ut_check((1_u8).is_pos());
            ut_check((1_u16).is_pos());
            ut_check((1_u32).is_pos());
            ut_check((1_u64).is_pos());
            ut_check((1_umx).is_pos());
            ut_check((1_idx).is_pos());

            /// NOTE:
            /// - The min/max unit tests are actually in the convert
            ///   header file so that they are always with the code.
            ///
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
    bsl::invalid_literal_tokens();

    static_assert(tests() == bsl::ut_success());
    return tests();
}
