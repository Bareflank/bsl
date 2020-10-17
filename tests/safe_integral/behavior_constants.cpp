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

#include <bsl/safe_integral.hpp>
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
    static_assert(bsl::ZERO_U8 == static_cast<bsl::uint8>(0));
    static_assert(bsl::ZERO_U16 == static_cast<bsl::uint16>(0));
    static_assert(bsl::ZERO_U32 == static_cast<bsl::uint32>(0));
    static_assert(bsl::ZERO_U64 == static_cast<bsl::uint64>(0));
    static_assert(bsl::ZERO_UMAX == static_cast<bsl::uintmax>(0));

    static_assert(bsl::ZERO_I8 == static_cast<bsl::int8>(0));
    static_assert(bsl::ZERO_I16 == static_cast<bsl::int16>(0));
    static_assert(bsl::ZERO_I32 == static_cast<bsl::int32>(0));
    static_assert(bsl::ZERO_I64 == static_cast<bsl::int64>(0));
    static_assert(bsl::ZERO_IMAX == static_cast<bsl::intmax>(0));

    static_assert(bsl::ONE_U8 == static_cast<bsl::uint8>(1));
    static_assert(bsl::ONE_U16 == static_cast<bsl::uint16>(1));
    static_assert(bsl::ONE_U32 == static_cast<bsl::uint32>(1));
    static_assert(bsl::ONE_U64 == static_cast<bsl::uint64>(1));
    static_assert(bsl::ONE_UMAX == static_cast<bsl::uintmax>(1));

    static_assert(bsl::ONE_I8 == static_cast<bsl::int8>(1));
    static_assert(bsl::ONE_I16 == static_cast<bsl::int16>(1));
    static_assert(bsl::ONE_I32 == static_cast<bsl::int32>(1));
    static_assert(bsl::ONE_I64 == static_cast<bsl::int64>(1));
    static_assert(bsl::ONE_IMAX == static_cast<bsl::intmax>(1));

    return bsl::ut_success();
}
