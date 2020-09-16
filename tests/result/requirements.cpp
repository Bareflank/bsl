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

#include <bsl/result.hpp>
#include <bsl/discard.hpp>
#include <bsl/ut.hpp>

namespace
{
    // Needed for requirements testing
    // NOLINTNEXTLINE(bsl-user-defined-type-names-match-header-name)
    class fixture_t final
    {
        bsl::result<bool> res{bsl::in_place, true};

    public:
        [[nodiscard]] constexpr auto
        test_member_const() const noexcept -> bool
        {
            bsl::discard(res.get_if());
            bsl::discard(res.errc());
            bsl::discard(!!res);
            bsl::discard(res.success());
            bsl::discard(res.failure());

            return true;
        }

        [[nodiscard]] constexpr auto
        test_member_nonconst() noexcept -> bool
        {
            bsl::discard(res.get_if());
            bsl::discard(res.errc());
            bsl::discard(!!res);
            bsl::discard(res.success());
            bsl::discard(res.failure());

            return true;
        }
    };

    constexpr fixture_t fixture1{};
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
    bsl::ut_scenario{"verify noexcept"} = []() {
        bsl::ut_given{} = []() {
            bool val{};
            bsl::result<bool> res1{true};
            bsl::result<bool> res2{false};
            bsl::errc_type myerror{};
            bsl::ut_then{} = []() {
                static_assert(noexcept(bsl::result<bool>{val}));
                static_assert(noexcept(bsl::result<bool>{bsl::move(val)}));
                static_assert(noexcept(bsl::result<bool>{bsl::in_place, true}));
                static_assert(noexcept(bsl::result<bool>{bsl::errc_failure}));
                static_assert(noexcept(bsl::result<bool>{bsl::move(myerror)}));
                static_assert(noexcept(bsl::result<bool>{res1}));
                static_assert(noexcept(bsl::result<bool>{bsl::move(res1)}));
                static_assert(noexcept(res1 = res2));
                static_assert(noexcept(res1 = bsl::move(res2)));
                static_assert(noexcept(res1.get_if()));
                static_assert(noexcept(res1.errc()));
                static_assert(noexcept(!!res1));
                static_assert(noexcept(res1.success()));
                static_assert(noexcept(res1.failure()));
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
