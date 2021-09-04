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

#include <bsl/cstdint.hpp>
#include <bsl/integer_sequence.hpp>
#include <bsl/ut.hpp>

/// <!-- description -->
///   @brief Main function for this unit test. If a call to ut_check() fails
///     the application will fast fail. If all calls to ut_check() pass, this
///     function will successfully return with bsl::exit_success.
///
/// <!-- inputs/outputs -->
///   @return Always returns bsl::exit_success.
///
[[nodiscard]] auto
main() noexcept -> bsl::exit_code
{
    static_assert(bsl::integer_sequence<bsl::int32>::size() == static_cast<bsl::uintmx>(0));
    static_assert(
        bsl::integer_sequence<bsl::int32, 4, 8, 15, 16, 23, 42>::size() ==
        static_cast<bsl::uintmx>(6));

    static_assert(bsl::integer_sequence<bsl::int32, 4>::min() == 4);
    static_assert(bsl::integer_sequence<bsl::int32, 4, 8>::min() == 4);
    static_assert(bsl::integer_sequence<bsl::int32, 4, 8, 15, 16, 23, 42>::min() == 4);
    static_assert(bsl::integer_sequence<bsl::int32, 15, 8, 4, 42, 23, 16>::min() == 4);

    static_assert(bsl::integer_sequence<bsl::int32, 42>::max() == 42);
    static_assert(bsl::integer_sequence<bsl::int32, 23, 42>::max() == 42);
    static_assert(bsl::integer_sequence<bsl::int32, 4, 8, 15, 16, 23, 42>::max() == 42);
    static_assert(bsl::integer_sequence<bsl::int32, 15, 8, 4, 42, 23, 16>::max() == 42);

    return bsl::ut_success();
}
