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

#include <bsl/char_traits.hpp>
#include <bsl/convert.hpp>
#include <bsl/ut.hpp>

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
    using namespace bsl;
    using traits = bsl::char_traits<bsl::char_type>;

    bsl::ut_scenario{"verify noexcept"} = []() {
        static_assert(noexcept(traits::eq('H', 'H')));
        static_assert(noexcept(traits::lt('H', 'H')));
        static_assert(noexcept(traits::compare(nullptr, nullptr, bsl::to_umax(0))));
        static_assert(noexcept(traits::length(nullptr)));
        static_assert(noexcept(traits::find(nullptr, bsl::to_umax(0), 0)));
        static_assert(noexcept(traits::to_char_type(0)));
        static_assert(noexcept(traits::to_int_type(0)));
        static_assert(noexcept(traits::eq_int_type(0, 0)));
        static_assert(noexcept(traits::eof()));
        static_assert(noexcept(traits::not_eof(0)));
    };

    return bsl::ut_success();
}
