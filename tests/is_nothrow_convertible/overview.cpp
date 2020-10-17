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

#include "../class_empty.hpp"
#include "../class_except.hpp"

#include <bsl/is_convertible.hpp>
#include <bsl/is_nothrow_convertible.hpp>
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
    // clang-format off

    static_assert(bsl::is_nothrow_convertible<bool, bool>::value);
    static_assert(bsl::is_nothrow_convertible<bool &, bool>::value);
    static_assert(bsl::is_nothrow_convertible<bool const &, bool>::value);
    static_assert(bsl::is_nothrow_convertible<bool &&, bool>::value);
    static_assert(!bsl::is_nothrow_convertible<bool, bool &>::value);
    static_assert(bsl::is_nothrow_convertible<bool, bool const &>::value);
    static_assert(bsl::is_nothrow_convertible<bool, bool &&>::value);
    static_assert(bsl::is_nothrow_convertible<bool *, bool>::value);
    static_assert(bsl::is_nothrow_convertible<bool *const, bool>::value);
    static_assert(bsl::is_nothrow_convertible<bool const *, bool>::value);
    static_assert(bsl::is_nothrow_convertible<bool const *const, bool>::value);
    static_assert(!bsl::is_nothrow_convertible<bool, bool *>::value);
    static_assert(!bsl::is_nothrow_convertible<bool, bool *const>::value);
    static_assert(!bsl::is_nothrow_convertible<bool, bool const *>::value);
    static_assert(!bsl::is_nothrow_convertible<bool, bool const *const>::value);

    static_assert(bsl::is_nothrow_convertible<test::class_empty, test::class_empty>::value);
    static_assert(bsl::is_nothrow_convertible<test::class_empty &, test::class_empty>::value);
    static_assert(bsl::is_nothrow_convertible<test::class_empty const &, test::class_empty>::value);
    static_assert(bsl::is_nothrow_convertible<test::class_empty &&, test::class_empty>::value);
    static_assert(!bsl::is_nothrow_convertible<test::class_empty, test::class_empty &>::value);
    static_assert(bsl::is_nothrow_convertible<test::class_empty, test::class_empty const &>::value);
    static_assert(bsl::is_nothrow_convertible<test::class_empty, test::class_empty &&>::value);
    static_assert(!bsl::is_nothrow_convertible<test::class_empty *, test::class_empty>::value);
    static_assert(!bsl::is_nothrow_convertible<test::class_empty *const, test::class_empty>::value);
    static_assert(!bsl::is_nothrow_convertible<test::class_empty const *, test::class_empty>::value);
    static_assert(!bsl::is_nothrow_convertible<test::class_empty const *const, test::class_empty>::value);
    static_assert(!bsl::is_nothrow_convertible<test::class_empty, test::class_empty *>::value);
    static_assert(!bsl::is_nothrow_convertible<test::class_empty, test::class_empty *const>::value);
    static_assert(!bsl::is_nothrow_convertible<test::class_empty, test::class_empty const *>::value);
    static_assert(!bsl::is_nothrow_convertible<test::class_empty, test::class_empty const *const>::value);

    static_assert(!bsl::is_nothrow_convertible<test::class_except, test::class_except>::value);
    static_assert(!bsl::is_nothrow_convertible<test::class_except &, test::class_except>::value);
    static_assert(!bsl::is_nothrow_convertible<test::class_except const &, test::class_except>::value);
    static_assert(!bsl::is_nothrow_convertible<test::class_except &&, test::class_except>::value);
    static_assert(!bsl::is_nothrow_convertible<test::class_except, test::class_except &>::value);
    static_assert(bsl::is_nothrow_convertible<test::class_except, test::class_except const &>::value);
    static_assert(bsl::is_nothrow_convertible<test::class_except, test::class_except &&>::value);
    static_assert(!bsl::is_nothrow_convertible<test::class_except *, test::class_except>::value);
    static_assert(!bsl::is_nothrow_convertible<test::class_except *const, test::class_except>::value);
    static_assert(!bsl::is_nothrow_convertible<test::class_except const *, test::class_except>::value);
    static_assert(!bsl::is_nothrow_convertible<test::class_except const *const, test::class_except>::value);
    static_assert(!bsl::is_nothrow_convertible<test::class_except, test::class_except *>::value);
    static_assert(!bsl::is_nothrow_convertible<test::class_except, test::class_except *const>::value);
    static_assert(!bsl::is_nothrow_convertible<test::class_except, test::class_except const *>::value);
    static_assert(!bsl::is_nothrow_convertible<test::class_except, test::class_except const *const>::value);

    return bsl::ut_success();
}
