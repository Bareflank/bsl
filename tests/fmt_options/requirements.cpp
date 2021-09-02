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
#include <bsl/discard.hpp>
#include <bsl/fmt_align.hpp>
#include <bsl/fmt_sign.hpp>
#include <bsl/fmt_type.hpp>
#include <bsl/ut.hpp>

namespace
{
    constinit bsl::fmt_options const g_verify_constinit{""};
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
            bsl::fmt_options mut_ops{""};
            bsl::fmt_options const ops{""};
            bsl::ut_then{} = []() noexcept {
                static_assert(noexcept(bsl::fmt_options{""}));

                static_assert(noexcept(mut_ops.fill()));
                static_assert(noexcept(mut_ops.set_fill(' ')));
                static_assert(noexcept(mut_ops.align()));
                static_assert(noexcept(mut_ops.set_align(bsl::fmt_align::fmt_align_default)));
                static_assert(noexcept(mut_ops.sign()));
                static_assert(noexcept(mut_ops.set_sign(bsl::fmt_sign::fmt_sign_neg_only)));
                static_assert(noexcept(mut_ops.alternate_form()));
                static_assert(noexcept(mut_ops.set_alternate_form(true)));
                static_assert(noexcept(mut_ops.sign_aware()));
                static_assert(noexcept(mut_ops.set_sign_aware(true)));
                static_assert(noexcept(mut_ops.width()));
                static_assert(noexcept(mut_ops.set_width(bsl::to_umx(10))));
                static_assert(noexcept(mut_ops.type()));
                static_assert(noexcept(mut_ops.set_type(bsl::fmt_type::fmt_type_d)));

                static_assert(noexcept(ops.fill()));
                static_assert(noexcept(ops.align()));
                static_assert(noexcept(ops.sign()));
                static_assert(noexcept(ops.alternate_form()));
                static_assert(noexcept(ops.sign_aware()));
                static_assert(noexcept(ops.width()));
                static_assert(noexcept(ops.type()));
            };
        };
    };

    return bsl::ut_success();
}
