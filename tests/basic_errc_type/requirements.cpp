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

#include <bsl/basic_errc_type.hpp>
#include <bsl/convert.hpp>
#include <bsl/discard.hpp>
#include <bsl/ut.hpp>

namespace
{
    constinit bsl::basic_errc_type<> const g_verify_constinit{};
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
            bsl::basic_errc_type<> mut_errc1{};
            bsl::basic_errc_type<> mut_errc2{};
            bsl::basic_errc_type<> const errc1{};
            bsl::basic_errc_type<> const errc2{};
            bsl::ut_then{} = []() noexcept {
                static_assert(noexcept(bsl::basic_errc_type<>{}));
                static_assert(noexcept(bsl::basic_errc_type<>{42}));
                static_assert(noexcept(bsl::basic_errc_type<>{bsl::to_i32(42)}));

                static_assert(noexcept(mut_errc1.get()));
                static_assert(noexcept(!!mut_errc1));
                static_assert(noexcept(mut_errc1.success()));
                static_assert(noexcept(mut_errc1.failure()));
                static_assert(noexcept(mut_errc1.is_checked()));
                static_assert(noexcept(mut_errc1.is_unchecked()));
                static_assert(noexcept(mut_errc1 == mut_errc2));
                static_assert(noexcept(mut_errc1 != mut_errc2));

                static_assert(noexcept(errc1.get()));
                static_assert(noexcept(!!errc1));
                static_assert(noexcept(errc1.success()));
                static_assert(noexcept(errc1.failure()));
                static_assert(noexcept(errc1.is_checked()));
                static_assert(noexcept(errc1.is_unchecked()));
                static_assert(noexcept(errc1 == errc2));
                static_assert(noexcept(errc1 != errc2));
            };
        };
    };

    return bsl::ut_success();
}
