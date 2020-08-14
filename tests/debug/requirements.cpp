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

#include <bsl/debug.hpp>
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
    bsl::ut_scenario{"verify noexcept"} = []() {
        bsl::ut_given{} = []() {
            bool val{};
            bsl::ut_then{} = []() {
                static_assert(noexcept(bsl::print() << true));
                static_assert(noexcept(bsl::print() << '*'));
                static_assert(noexcept(bsl::print() << ""));
                static_assert(noexcept(bsl::print() << 42));
                static_assert(noexcept(bsl::print() << nullptr));
                static_assert(noexcept(bsl::print() << &val));
                static_assert(noexcept(bsl::debug() << true));
                static_assert(noexcept(bsl::debug() << '*'));
                static_assert(noexcept(bsl::debug() << ""));
                static_assert(noexcept(bsl::debug() << 42));
                static_assert(noexcept(bsl::debug() << nullptr));
                static_assert(noexcept(bsl::debug() << &val));
                static_assert(noexcept(bsl::alert() << true));
                static_assert(noexcept(bsl::alert() << '*'));
                static_assert(noexcept(bsl::alert() << ""));
                static_assert(noexcept(bsl::alert() << 42));
                static_assert(noexcept(bsl::alert() << nullptr));
                static_assert(noexcept(bsl::alert() << &val));
                static_assert(noexcept(bsl::error() << true));
                static_assert(noexcept(bsl::error() << '*'));
                static_assert(noexcept(bsl::error() << ""));
                static_assert(noexcept(bsl::error() << 42));
                static_assert(noexcept(bsl::error() << nullptr));
                static_assert(noexcept(bsl::error() << &val));
                static_assert(noexcept(bsl::debug<42>() << true));
                static_assert(noexcept(bsl::debug<42>() << '*'));
                static_assert(noexcept(bsl::debug<42>() << ""));
                static_assert(noexcept(bsl::debug<42>() << 42));
                static_assert(noexcept(bsl::debug<42>() << nullptr));
                static_assert(noexcept(bsl::debug<42>() << &val));
                static_assert(noexcept(bsl::alert<42>() << true));
                static_assert(noexcept(bsl::alert<42>() << '*'));
                static_assert(noexcept(bsl::alert<42>() << ""));
                static_assert(noexcept(bsl::alert<42>() << 42));
                static_assert(noexcept(bsl::alert<42>() << nullptr));
                static_assert(noexcept(bsl::alert<42>() << &val));
            };
        };
    };

    return bsl::ut_success();
}
