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
///   @brief Used to execute the actual checks. We put the checks in this
///     function so that we can validate the tests both at compile-time
///     and at run-time. If a bsl::ut_check fails, the tests will either
///     fail fast at run-time, or will produce a compile-time error.
///
/// <!-- inputs/outputs -->
///   @return Always returns bsl::exit_success.
///
constexpr bsl::exit_code
tests() noexcept
{
    using namespace bsl;

    bsl::ut_scenario{"up convert signed to signed"} = []() {
        bsl::ut_given{} = []() {
            bsl::safe_int8 val{bsl::safe_int8::max()};
            bsl::ut_then{} = [&val]() {
                bsl::ut_check(to_i8(val) == static_cast<bsl::int8>(safe_int8::max()));
                bsl::ut_check(to_i16(val) == static_cast<bsl::int16>(safe_int8::max()));
                bsl::ut_check(to_i32(val) == static_cast<bsl::int32>(safe_int8::max()));
                bsl::ut_check(to_i64(val) == static_cast<bsl::int64>(safe_int8::max()));
                bsl::ut_check(to_imax(val) == static_cast<bsl::intmax>(safe_int8::max()));
            };
        };

        bsl::ut_given{} = []() {
            bsl::safe_int8 val{bsl::safe_int8::min()};
            bsl::ut_then{} = [&val]() {
                bsl::ut_check(to_i8(val) == static_cast<bsl::int8>(safe_int8::min()));
                bsl::ut_check(to_i16(val) == static_cast<bsl::int16>(safe_int8::min()));
                bsl::ut_check(to_i32(val) == static_cast<bsl::int32>(safe_int8::min()));
                bsl::ut_check(to_i64(val) == static_cast<bsl::int64>(safe_int8::min()));
                bsl::ut_check(to_imax(val) == static_cast<bsl::intmax>(safe_int8::min()));
            };
        };
    };

    bsl::ut_scenario{"up convert unsigned to unsigned"} = []() {
        bsl::ut_given{} = []() {
            bsl::safe_uint8 val{bsl::safe_uint8::max()};
            bsl::ut_then{} = [&val]() {
                bsl::ut_check(to_u8(val) == static_cast<bsl::uint8>(safe_uint8::max()));
                bsl::ut_check(to_u16(val) == static_cast<bsl::uint16>(safe_uint8::max()));
                bsl::ut_check(to_u32(val) == static_cast<bsl::uint32>(safe_uint8::max()));
                bsl::ut_check(to_u64(val) == static_cast<bsl::uint64>(safe_uint8::max()));
                bsl::ut_check(to_umax(val) == static_cast<bsl::uintmax>(safe_uint8::max()));
            };
        };
    };

    bsl::ut_scenario{"up convert signed to unsigned"} = []() {
        bsl::ut_given{} = []() {
            bsl::safe_int8 val{bsl::safe_int8::max()};
            bsl::ut_then{} = [&val]() {
                bsl::ut_check(to_u8(val) == static_cast<bsl::uint8>(safe_int8::max()));
                bsl::ut_check(to_u16(val) == static_cast<bsl::uint16>(safe_int8::max()));
                bsl::ut_check(to_u32(val) == static_cast<bsl::uint32>(safe_int8::max()));
                bsl::ut_check(to_u64(val) == static_cast<bsl::uint64>(safe_int8::max()));
                bsl::ut_check(to_umax(val) == static_cast<bsl::uintmax>(safe_int8::max()));
            };
        };

        bsl::ut_given_at_runtime{} = []() {
            bsl::safe_int8 val{bsl::safe_int8::min()};
            bsl::ut_then{} = [&val]() {
                bsl::ut_check(to_u8(val).failure());
                bsl::ut_check(to_u16(val).failure());
                bsl::ut_check(to_u32(val).failure());
                bsl::ut_check(to_u64(val).failure());
                bsl::ut_check(to_umax(val).failure());
            };
        };
    };

    bsl::ut_scenario{"up convert unsigned to signed"} = []() {
        bsl::ut_given_at_runtime{} = []() {
            bsl::safe_uint8 val{bsl::safe_uint8::max()};
            bsl::ut_then{} = [&val]() {
                bsl::ut_check(to_i8(val).failure());
                bsl::ut_check(to_i16(val) == static_cast<bsl::int16>(bsl::safe_uint8::max()));
                bsl::ut_check(to_i32(val) == static_cast<bsl::int32>(bsl::safe_uint8::max()));
                bsl::ut_check(to_i64(val) == static_cast<bsl::int64>(bsl::safe_uint8::max()));
                bsl::ut_check(to_imax(val) == static_cast<bsl::intmax>(bsl::safe_uint8::max()));
            };
        };

        bsl::ut_given_at_runtime{} = []() {
            bsl::safe_uint16 val{bsl::safe_uint16::max()};
            bsl::ut_then{} = [&val]() {
                bsl::ut_check(to_i8(val).failure());
                bsl::ut_check(to_i16(val).failure());
                bsl::ut_check(to_i32(val) == static_cast<bsl::int32>(bsl::safe_uint16::max()));
                bsl::ut_check(to_i64(val) == static_cast<bsl::int64>(bsl::safe_uint16::max()));
                bsl::ut_check(to_imax(val) == static_cast<bsl::intmax>(bsl::safe_uint16::max()));
            };
        };

        bsl::ut_given_at_runtime{} = []() {
            bsl::safe_uint32 val{bsl::safe_uint32::max()};
            bsl::ut_then{} = [&val]() {
                bsl::ut_check(to_i8(val).failure());
                bsl::ut_check(to_i16(val).failure());
                bsl::ut_check(to_i32(val).failure());
                bsl::ut_check(to_i64(val) == static_cast<bsl::int64>(bsl::safe_uint32::max()));
                bsl::ut_check(to_imax(val) == static_cast<bsl::intmax>(bsl::safe_uint32::max()));
            };
        };

        bsl::ut_given_at_runtime{} = []() {
            bsl::safe_uint64 val{bsl::safe_uint64::max()};
            bsl::ut_then{} = [&val]() {
                bsl::ut_check(to_i8(val).failure());
                bsl::ut_check(to_i16(val).failure());
                bsl::ut_check(to_i32(val).failure());
                bsl::ut_check(to_i64(val).failure());
                bsl::ut_check(to_imax(val).failure());
            };
        };

        bsl::ut_given_at_runtime{} = []() {
            bsl::safe_uintmax val{bsl::safe_uintmax::max()};
            bsl::ut_then{} = [&val]() {
                bsl::ut_check(to_i8(val).failure());
                bsl::ut_check(to_i16(val).failure());
                bsl::ut_check(to_i32(val).failure());
                bsl::ut_check(to_i64(val).failure());
                bsl::ut_check(to_imax(val).failure());
            };
        };
    };

    bsl::ut_scenario{"down convert signed to signed"} = []() {
        bsl::ut_given{} = []() {
            bsl::safe_intmax val{static_cast<bsl::intmax>(bsl::safe_int8::max())};
            bsl::ut_then{} = [&val]() {
                bsl::ut_check(to_i8(val) == static_cast<bsl::int8>(safe_int8::max()));
                bsl::ut_check(to_i16(val) == static_cast<bsl::int16>(safe_int8::max()));
                bsl::ut_check(to_i32(val) == static_cast<bsl::int32>(safe_int8::max()));
                bsl::ut_check(to_i64(val) == static_cast<bsl::int64>(safe_int8::max()));
                bsl::ut_check(to_imax(val) == static_cast<bsl::intmax>(safe_int8::max()));
            };
        };

        bsl::ut_given_at_runtime{} = []() {
            bsl::safe_intmax val{static_cast<bsl::intmax>(bsl::safe_int16::max())};
            bsl::ut_then{} = [&val]() {
                bsl::ut_check(to_i8(val).failure());
                bsl::ut_check(to_i16(val) == static_cast<bsl::int16>(safe_int16::max()));
                bsl::ut_check(to_i32(val) == static_cast<bsl::int32>(safe_int16::max()));
                bsl::ut_check(to_i64(val) == static_cast<bsl::int64>(safe_int16::max()));
                bsl::ut_check(to_imax(val) == static_cast<bsl::intmax>(safe_int16::max()));
            };
        };

        bsl::ut_given_at_runtime{} = []() {
            bsl::safe_intmax val{static_cast<bsl::intmax>(bsl::safe_int32::max())};
            bsl::ut_then{} = [&val]() {
                bsl::ut_check(to_i8(val).failure());
                bsl::ut_check(to_i16(val).failure());
                bsl::ut_check(to_i32(val) == static_cast<bsl::int32>(safe_int32::max()));
                bsl::ut_check(to_i64(val) == static_cast<bsl::int64>(safe_int32::max()));
                bsl::ut_check(to_imax(val) == static_cast<bsl::intmax>(safe_int32::max()));
            };
        };

        bsl::ut_given_at_runtime{} = []() {
            bsl::safe_intmax val{static_cast<bsl::intmax>(bsl::safe_int64::max())};
            bsl::ut_then{} = [&val]() {
                bsl::ut_check(to_i8(val).failure());
                bsl::ut_check(to_i16(val).failure());
                bsl::ut_check(to_i32(val).failure());
                bsl::ut_check(to_i64(val) == static_cast<bsl::int64>(safe_int64::max()));
                bsl::ut_check(to_imax(val) == static_cast<bsl::intmax>(safe_int64::max()));
            };
        };

        bsl::ut_given_at_runtime{} = []() {
            bsl::safe_intmax val{static_cast<bsl::intmax>(bsl::safe_intmax::max())};
            bsl::ut_then{} = [&val]() {
                bsl::ut_check(to_i8(val).failure());
                bsl::ut_check(to_i16(val).failure());
                bsl::ut_check(to_i32(val).failure());
                bsl::ut_check(to_i64(val) == static_cast<bsl::int64>(safe_intmax::max()));
                bsl::ut_check(to_imax(val) == static_cast<bsl::intmax>(safe_intmax::max()));
            };
        };

        bsl::ut_given{} = []() {
            bsl::safe_intmax val{static_cast<bsl::intmax>(bsl::safe_int8::min())};
            bsl::ut_then{} = [&val]() {
                bsl::ut_check(to_i8(val) == static_cast<bsl::int8>(safe_int8::min()));
                bsl::ut_check(to_i16(val) == static_cast<bsl::int16>(safe_int8::min()));
                bsl::ut_check(to_i32(val) == static_cast<bsl::int32>(safe_int8::min()));
                bsl::ut_check(to_i64(val) == static_cast<bsl::int64>(safe_int8::min()));
                bsl::ut_check(to_imax(val) == static_cast<bsl::intmax>(safe_int8::min()));
            };
        };

        bsl::ut_given_at_runtime{} = []() {
            bsl::safe_intmax val{static_cast<bsl::intmax>(bsl::safe_int16::min())};
            bsl::ut_then{} = [&val]() {
                bsl::ut_check(to_i8(val).failure());
                bsl::ut_check(to_i16(val) == static_cast<bsl::int16>(safe_int16::min()));
                bsl::ut_check(to_i32(val) == static_cast<bsl::int32>(safe_int16::min()));
                bsl::ut_check(to_i64(val) == static_cast<bsl::int64>(safe_int16::min()));
                bsl::ut_check(to_imax(val) == static_cast<bsl::intmax>(safe_int16::min()));
            };
        };

        bsl::ut_given_at_runtime{} = []() {
            bsl::safe_intmax val{static_cast<bsl::intmax>(bsl::safe_int32::min())};
            bsl::ut_then{} = [&val]() {
                bsl::ut_check(to_i8(val).failure());
                bsl::ut_check(to_i16(val).failure());
                bsl::ut_check(to_i32(val) == static_cast<bsl::int32>(safe_int32::min()));
                bsl::ut_check(to_i64(val) == static_cast<bsl::int64>(safe_int32::min()));
                bsl::ut_check(to_imax(val) == static_cast<bsl::intmax>(safe_int32::min()));
            };
        };

        bsl::ut_given_at_runtime{} = []() {
            bsl::safe_intmax val{static_cast<bsl::intmax>(bsl::safe_int64::min())};
            bsl::ut_then{} = [&val]() {
                bsl::ut_check(to_i8(val).failure());
                bsl::ut_check(to_i16(val).failure());
                bsl::ut_check(to_i32(val).failure());
                bsl::ut_check(to_i64(val) == static_cast<bsl::int64>(safe_int64::min()));
                bsl::ut_check(to_imax(val) == static_cast<bsl::intmax>(safe_int64::min()));
            };
        };

        bsl::ut_given_at_runtime{} = []() {
            bsl::safe_intmax val{static_cast<bsl::intmax>(bsl::safe_intmax::min())};
            bsl::ut_then{} = [&val]() {
                bsl::ut_check(to_i8(val).failure());
                bsl::ut_check(to_i16(val).failure());
                bsl::ut_check(to_i32(val).failure());
                bsl::ut_check(to_i64(val) == static_cast<bsl::int64>(safe_intmax::min()));
                bsl::ut_check(to_imax(val) == static_cast<bsl::intmax>(safe_intmax::min()));
            };
        };
    };

    bsl::ut_scenario{"down convert unsigned to unsigned"} = []() {
        bsl::ut_given{} = []() {
            bsl::safe_uintmax val{static_cast<bsl::uintmax>(bsl::safe_uint8::max())};
            bsl::ut_then{} = [&val]() {
                bsl::ut_check(to_u8(val) == static_cast<bsl::uint8>(safe_uint8::max()));
                bsl::ut_check(to_u16(val) == static_cast<bsl::uint16>(safe_uint8::max()));
                bsl::ut_check(to_u32(val) == static_cast<bsl::uint32>(safe_uint8::max()));
                bsl::ut_check(to_u64(val) == static_cast<bsl::uint64>(safe_uint8::max()));
                bsl::ut_check(to_umax(val) == static_cast<bsl::uintmax>(safe_uint8::max()));
            };
        };

        bsl::ut_given_at_runtime{} = []() {
            bsl::safe_uintmax val{static_cast<bsl::uintmax>(bsl::safe_uint16::max())};
            bsl::ut_then{} = [&val]() {
                bsl::ut_check(to_u8(val).failure());
                bsl::ut_check(to_u16(val) == static_cast<bsl::uint16>(safe_uint16::max()));
                bsl::ut_check(to_u32(val) == static_cast<bsl::uint32>(safe_uint16::max()));
                bsl::ut_check(to_u64(val) == static_cast<bsl::uint64>(safe_uint16::max()));
                bsl::ut_check(to_umax(val) == static_cast<bsl::uintmax>(safe_uint16::max()));
            };
        };

        bsl::ut_given_at_runtime{} = []() {
            bsl::safe_uintmax val{static_cast<bsl::uintmax>(bsl::safe_uint32::max())};
            bsl::ut_then{} = [&val]() {
                bsl::ut_check(to_u8(val).failure());
                bsl::ut_check(to_u16(val).failure());
                bsl::ut_check(to_u32(val) == static_cast<bsl::uint32>(safe_uint32::max()));
                bsl::ut_check(to_u64(val) == static_cast<bsl::uint64>(safe_uint32::max()));
                bsl::ut_check(to_umax(val) == static_cast<bsl::uintmax>(safe_uint32::max()));
            };
        };

        bsl::ut_given_at_runtime{} = []() {
            bsl::safe_uintmax val{static_cast<bsl::uintmax>(bsl::safe_uint64::max())};
            bsl::ut_then{} = [&val]() {
                bsl::ut_check(to_u8(val).failure());
                bsl::ut_check(to_u16(val).failure());
                bsl::ut_check(to_u32(val).failure());
                bsl::ut_check(to_u64(val) == static_cast<bsl::uint64>(safe_uint64::max()));
                bsl::ut_check(to_umax(val) == static_cast<bsl::uintmax>(safe_uint64::max()));
            };
        };

        bsl::ut_given_at_runtime{} = []() {
            bsl::safe_uintmax val{static_cast<bsl::uintmax>(bsl::safe_uintmax::max())};
            bsl::ut_then{} = [&val]() {
                bsl::ut_check(to_u8(val).failure());
                bsl::ut_check(to_u16(val).failure());
                bsl::ut_check(to_u32(val).failure());
                bsl::ut_check(to_u64(val) == static_cast<bsl::uint64>(safe_uintmax::max()));
                bsl::ut_check(to_umax(val) == static_cast<bsl::uintmax>(safe_uintmax::max()));
            };
        };
    };

    bsl::ut_scenario{"down convert signed to unsigned"} = []() {
        bsl::ut_given{} = []() {
            bsl::safe_intmax val{static_cast<bsl::intmax>(bsl::safe_int8::max())};
            bsl::ut_then{} = [&val]() {
                bsl::ut_check(to_u8(val) == static_cast<bsl::uint8>(safe_int8::max()));
                bsl::ut_check(to_u16(val) == static_cast<bsl::uint16>(safe_int8::max()));
                bsl::ut_check(to_u32(val) == static_cast<bsl::uint32>(safe_int8::max()));
                bsl::ut_check(to_u64(val) == static_cast<bsl::uint64>(safe_int8::max()));
                bsl::ut_check(to_umax(val) == static_cast<bsl::uintmax>(safe_int8::max()));
            };
        };

        bsl::ut_given_at_runtime{} = []() {
            bsl::safe_intmax val{static_cast<bsl::intmax>(bsl::safe_int16::max())};
            bsl::ut_then{} = [&val]() {
                bsl::ut_check(to_u8(val).failure());
                bsl::ut_check(to_u16(val) == static_cast<bsl::uint16>(safe_int16::max()));
                bsl::ut_check(to_u32(val) == static_cast<bsl::uint32>(safe_int16::max()));
                bsl::ut_check(to_u64(val) == static_cast<bsl::uint64>(safe_int16::max()));
                bsl::ut_check(to_umax(val) == static_cast<bsl::uintmax>(safe_int16::max()));
            };
        };

        bsl::ut_given_at_runtime{} = []() {
            bsl::safe_intmax val{static_cast<bsl::intmax>(bsl::safe_int32::max())};
            bsl::ut_then{} = [&val]() {
                bsl::ut_check(to_u8(val).failure());
                bsl::ut_check(to_u16(val).failure());
                bsl::ut_check(to_u32(val) == static_cast<bsl::uint32>(safe_int32::max()));
                bsl::ut_check(to_u64(val) == static_cast<bsl::uint64>(safe_int32::max()));
                bsl::ut_check(to_umax(val) == static_cast<bsl::uintmax>(safe_int32::max()));
            };
        };

        bsl::ut_given_at_runtime{} = []() {
            bsl::safe_intmax val{static_cast<bsl::intmax>(bsl::safe_int64::max())};
            bsl::ut_then{} = [&val]() {
                bsl::ut_check(to_u8(val).failure());
                bsl::ut_check(to_u16(val).failure());
                bsl::ut_check(to_u32(val).failure());
                bsl::ut_check(to_u64(val) == static_cast<bsl::uint64>(safe_int64::max()));
                bsl::ut_check(to_umax(val) == static_cast<bsl::uintmax>(safe_int64::max()));
            };
        };

        bsl::ut_given_at_runtime{} = []() {
            bsl::safe_intmax val{static_cast<bsl::intmax>(bsl::safe_intmax::max())};
            bsl::ut_then{} = [&val]() {
                bsl::ut_check(to_u8(val).failure());
                bsl::ut_check(to_u16(val).failure());
                bsl::ut_check(to_u32(val).failure());
                bsl::ut_check(to_u64(val) == static_cast<bsl::uint64>(safe_intmax::max()));
                bsl::ut_check(to_umax(val) == static_cast<bsl::uintmax>(safe_intmax::max()));
            };
        };

        bsl::ut_given_at_runtime{} = []() {
            bsl::safe_intmax val{static_cast<bsl::intmax>(bsl::safe_int8::min())};
            bsl::ut_then{} = [&val]() {
                bsl::ut_check(to_u8(val).failure());
                bsl::ut_check(to_u16(val).failure());
                bsl::ut_check(to_u32(val).failure());
                bsl::ut_check(to_u64(val).failure());
                bsl::ut_check(to_umax(val).failure());
            };
        };

        bsl::ut_given_at_runtime{} = []() {
            bsl::safe_intmax val{static_cast<bsl::intmax>(bsl::safe_int16::min())};
            bsl::ut_then{} = [&val]() {
                bsl::ut_check(to_u8(val).failure());
                bsl::ut_check(to_u16(val).failure());
                bsl::ut_check(to_u32(val).failure());
                bsl::ut_check(to_u64(val).failure());
                bsl::ut_check(to_umax(val).failure());
            };
        };

        bsl::ut_given_at_runtime{} = []() {
            bsl::safe_intmax val{static_cast<bsl::intmax>(bsl::safe_int32::min())};
            bsl::ut_then{} = [&val]() {
                bsl::ut_check(to_u8(val).failure());
                bsl::ut_check(to_u16(val).failure());
                bsl::ut_check(to_u32(val).failure());
                bsl::ut_check(to_u64(val).failure());
                bsl::ut_check(to_umax(val).failure());
            };
        };

        bsl::ut_given_at_runtime{} = []() {
            bsl::safe_intmax val{static_cast<bsl::intmax>(bsl::safe_int64::min())};
            bsl::ut_then{} = [&val]() {
                bsl::ut_check(to_u8(val).failure());
                bsl::ut_check(to_u16(val).failure());
                bsl::ut_check(to_u32(val).failure());
                bsl::ut_check(to_u64(val).failure());
                bsl::ut_check(to_umax(val).failure());
            };
        };

        bsl::ut_given_at_runtime{} = []() {
            bsl::safe_intmax val{static_cast<bsl::intmax>(bsl::safe_intmax::min())};
            bsl::ut_then{} = [&val]() {
                bsl::ut_check(to_u8(val).failure());
                bsl::ut_check(to_u16(val).failure());
                bsl::ut_check(to_u32(val).failure());
                bsl::ut_check(to_u64(val).failure());
                bsl::ut_check(to_umax(val).failure());
            };
        };
    };

    bsl::ut_scenario{"down convert unsigned to signed"} = []() {
        bsl::ut_given_at_runtime{} = []() {
            bsl::safe_uintmax val{static_cast<bsl::uintmax>(bsl::safe_uint8::max())};
            bsl::ut_then{} = [&val]() {
                bsl::ut_check(to_i8(val).failure());
                bsl::ut_check(to_i16(val) == static_cast<bsl::int16>(safe_uint8::max()));
                bsl::ut_check(to_i32(val) == static_cast<bsl::int32>(safe_uint8::max()));
                bsl::ut_check(to_i64(val) == static_cast<bsl::int64>(safe_uint8::max()));
                bsl::ut_check(to_imax(val) == static_cast<bsl::intmax>(safe_uint8::max()));
            };
        };

        bsl::ut_given_at_runtime{} = []() {
            bsl::safe_uintmax val{static_cast<bsl::uintmax>(bsl::safe_uint16::max())};
            bsl::ut_then{} = [&val]() {
                bsl::ut_check(to_i8(val).failure());
                bsl::ut_check(to_i16(val).failure());
                bsl::ut_check(to_i32(val) == static_cast<bsl::int32>(safe_uint16::max()));
                bsl::ut_check(to_i64(val) == static_cast<bsl::int64>(safe_uint16::max()));
                bsl::ut_check(to_imax(val) == static_cast<bsl::intmax>(safe_uint16::max()));
            };
        };

        bsl::ut_given_at_runtime{} = []() {
            bsl::safe_uintmax val{static_cast<bsl::uintmax>(bsl::safe_uint32::max())};
            bsl::ut_then{} = [&val]() {
                bsl::ut_check(to_i8(val).failure());
                bsl::ut_check(to_i16(val).failure());
                bsl::ut_check(to_i32(val).failure());
                bsl::ut_check(to_i64(val) == static_cast<bsl::int64>(safe_uint32::max()));
                bsl::ut_check(to_imax(val) == static_cast<bsl::intmax>(safe_uint32::max()));
            };
        };

        bsl::ut_given_at_runtime{} = []() {
            bsl::safe_uintmax val{static_cast<bsl::uintmax>(bsl::safe_uint64::max())};
            bsl::ut_then{} = [&val]() {
                bsl::ut_check(to_i8(val).failure());
                bsl::ut_check(to_i16(val).failure());
                bsl::ut_check(to_i32(val).failure());
                bsl::ut_check(to_i64(val).failure());
                bsl::ut_check(to_imax(val).failure());
            };
        };

        bsl::ut_given_at_runtime{} = []() {
            bsl::safe_uintmax val{static_cast<bsl::uintmax>(bsl::safe_uintmax::max())};
            bsl::ut_then{} = [&val]() {
                bsl::ut_check(to_i8(val).failure());
                bsl::ut_check(to_i16(val).failure());
                bsl::ut_check(to_i32(val).failure());
                bsl::ut_check(to_i64(val).failure());
                bsl::ut_check(to_imax(val).failure());
            };
        };
    };

    bsl::ut_scenario{"to functions"} = []() {
        bsl::ut_given{} = []() {
            bsl::safe_int32 val{42};
            bsl::ut_then{} = [&val]() {
                bsl::ut_check(to_i8(val) == static_cast<bsl::int8>(42));
                bsl::ut_check(to_i8(42) == static_cast<bsl::int8>(42));
                bsl::ut_check(to_i16(val) == static_cast<bsl::int16>(42));
                bsl::ut_check(to_i16(42) == static_cast<bsl::int16>(42));
                bsl::ut_check(to_i32(val) == static_cast<bsl::int32>(42));
                bsl::ut_check(to_i32(42) == static_cast<bsl::int32>(42));
                bsl::ut_check(to_i64(val) == static_cast<bsl::int64>(42));
                bsl::ut_check(to_i64(42) == static_cast<bsl::int64>(42));
                bsl::ut_check(to_imax(val) == static_cast<bsl::intmax>(42));
                bsl::ut_check(to_imax(42) == static_cast<bsl::intmax>(42));
            };
        };

        bsl::ut_given{} = []() {
            bsl::safe_uint32 val{42U};
            bsl::ut_then{} = [&val]() {
                bsl::ut_check(to_u8(val) == static_cast<bsl::uint8>(42U));
                bsl::ut_check(to_u8(42U) == static_cast<bsl::uint8>(42U));
                bsl::ut_check(to_u16(val) == static_cast<bsl::uint16>(42U));
                bsl::ut_check(to_u16(42U) == static_cast<bsl::uint16>(42U));
                bsl::ut_check(to_u32(val) == static_cast<bsl::uint32>(42U));
                bsl::ut_check(to_u32(42U) == static_cast<bsl::uint32>(42U));
                bsl::ut_check(to_u64(val) == static_cast<bsl::uint64>(42U));
                bsl::ut_check(to_u64(42U) == static_cast<bsl::uint64>(42U));
                bsl::ut_check(to_umax(val) == static_cast<bsl::uintmax>(42U));
                bsl::ut_check(to_umax(42U) == static_cast<bsl::uintmax>(42U));
            };
        };
    };

    return bsl::ut_success();
}

/// <!-- description -->
///   @brief Main function for this unit test. If a call to ut_check() fails
///     the application will fast fail. If all calls to ut_check() pass, this
///     function will successfully return with bsl::exit_success.
///
/// <!-- inputs/outputs -->
///   @return Always returns bsl::exit_success.
///
bsl::exit_code
main() noexcept
{
    static_assert(tests() == bsl::ut_success());
    return tests();
}
