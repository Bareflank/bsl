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

#include <bsl/fmt_options.hpp>
#include <bsl/ut.hpp>

namespace
{
    class fixture_t final
    {
        bsl::fmt_options ops{""};

    public:
        [[nodiscard]] constexpr bool
        test_member_const() const
        {
            bsl::discard(ops.fill());
            bsl::discard(ops.align());
            bsl::discard(ops.sign());
            bsl::discard(ops.alternate_form());
            bsl::discard(ops.sign_aware());
            bsl::discard(ops.width());
            bsl::discard(ops.type());

            return true;
        }

        [[nodiscard]] constexpr bool
        test_member_nonconst()
        {
            bsl::discard(ops.fill());
            ops.set_fill(' ');
            bsl::discard(ops.align());
            ops.set_align(bsl::fmt_align::fmt_align_default);
            bsl::discard(ops.sign());
            ops.set_sign(bsl::fmt_sign::fmt_sign_neg_only);
            bsl::discard(ops.alternate_form());
            ops.set_alternate_form(true);
            bsl::discard(ops.sign_aware());
            ops.set_sign_aware(true);
            bsl::discard(ops.width());
            ops.set_width(bsl::to_umax(10));
            bsl::discard(ops.type());
            ops.set_type(bsl::fmt_type::fmt_type_d);

            return true;
        }
    };

    constexpr fixture_t fixture1{};
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
    bsl::ut_scenario{"verify noexcept"} = []() {
        bsl::ut_given{} = []() {
            bsl::fmt_options ops{""};
            bsl::ut_then{} = []() {
                static_assert(noexcept(bsl::fmt_options{""}));
                static_assert(noexcept(ops.fill()));
                static_assert(noexcept(ops.set_fill(' ')));
                static_assert(noexcept(ops.align()));
                static_assert(noexcept(ops.set_align(bsl::fmt_align::fmt_align_default)));
                static_assert(noexcept(ops.sign()));
                static_assert(noexcept(ops.set_sign(bsl::fmt_sign::fmt_sign_neg_only)));
                static_assert(noexcept(ops.alternate_form()));
                static_assert(noexcept(ops.set_alternate_form(true)));
                static_assert(noexcept(ops.sign_aware()));
                static_assert(noexcept(ops.set_sign_aware(true)));
                static_assert(noexcept(ops.width()));
                static_assert(noexcept(ops.set_width(bsl::to_umax(10))));
                static_assert(noexcept(ops.type()));
                static_assert(noexcept(ops.set_type(bsl::fmt_type::fmt_type_d)));
            };
        };
    };

    bsl::ut_scenario{"verify constness"} = []() {
        bsl::ut_given{} = []() {
            fixture_t fixture2{};
            bsl::ut_then{} = [&fixture2]() {
                static_assert(fixture1.test_member_const());
                bsl::ut_check(fixture2.test_member_nonconst());
            };
        };
    };

    return bsl::ut_success();
}
