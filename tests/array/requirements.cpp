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

#include <bsl/array.hpp>
#include <bsl/convert.hpp>
#include <bsl/discard.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/ut.hpp>

namespace
{
    constinit bsl::array const verify_constinit{true, false};

    // Needed for requirements testing
    // NOLINTNEXTLINE(bsl-user-defined-type-names-match-header-name)
    class fixture_t final
    {
        bsl::array<bool, static_cast<bsl::uintmax>(6)> arr{};

    public:
        [[nodiscard]] constexpr auto
        test_member_const() const noexcept -> bool
        {
            bsl::discard(arr.at_if(bsl::to_umax(0)));
            bsl::discard(arr.front());
            bsl::discard(arr.front_if());
            bsl::discard(arr.back());
            bsl::discard(arr.back_if());
            bsl::discard(arr.data());
            bsl::discard(arr.begin());
            bsl::discard(arr.cbegin());
            bsl::discard(arr.iter(bsl::to_umax(0)));
            bsl::discard(arr.citer(bsl::to_umax(0)));
            bsl::discard(arr.end());
            bsl::discard(arr.cend());
            bsl::discard(arr.rbegin());
            bsl::discard(arr.crbegin());
            bsl::discard(arr.riter(bsl::to_umax(0)));
            bsl::discard(arr.criter(bsl::to_umax(0)));
            bsl::discard(arr.rend());
            bsl::discard(arr.crend());
            bsl::discard(arr.empty());
            bsl::discard(!!arr);
            bsl::discard(arr.size());
            bsl::discard(arr.max_size());
            bsl::discard(arr.size_bytes());

            return true;
        }

        [[nodiscard]] constexpr auto
        test_member_nonconst() noexcept -> bool
        {
            bsl::discard(arr.at_if(bsl::to_umax(0)));
            bsl::discard(arr.front());
            bsl::discard(arr.front_if());
            bsl::discard(arr.back());
            bsl::discard(arr.back_if());
            bsl::discard(arr.data());
            bsl::discard(arr.begin());
            bsl::discard(arr.cbegin());
            bsl::discard(arr.iter(bsl::to_umax(0)));
            bsl::discard(arr.citer(bsl::to_umax(0)));
            bsl::discard(arr.end());
            bsl::discard(arr.cend());
            bsl::discard(arr.rbegin());
            bsl::discard(arr.crbegin());
            bsl::discard(arr.riter(bsl::to_umax(0)));
            bsl::discard(arr.criter(bsl::to_umax(0)));
            bsl::discard(arr.rend());
            bsl::discard(arr.crend());
            bsl::discard(arr.empty());
            bsl::discard(!!arr);
            bsl::discard(arr.size());
            bsl::discard(arr.max_size());
            bsl::discard(arr.size_bytes());

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
    bsl::ut_scenario{"verify supports constinit"} = []() {
        bsl::discard(verify_constinit);
    };

    bsl::ut_scenario{"verify noexcept"} = []() {
        bsl::ut_given{} = []() {
            bsl::array arr1{true, false};
            bsl::array arr2{true, false};
            bsl::ut_then{} = []() {
                static_assert(noexcept(arr1.at_if(bsl::to_umax(0))));
                static_assert(noexcept(arr1.front()));
                static_assert(noexcept(arr1.front_if()));
                static_assert(noexcept(arr1.back()));
                static_assert(noexcept(arr1.back_if()));
                static_assert(noexcept(arr1.data()));
                static_assert(noexcept(arr1.begin()));
                static_assert(noexcept(arr1.cbegin()));
                static_assert(noexcept(arr1.iter(bsl::to_umax(0))));
                static_assert(noexcept(arr1.citer(bsl::to_umax(0))));
                static_assert(noexcept(arr1.end()));
                static_assert(noexcept(arr1.cend()));
                static_assert(noexcept(arr1.rbegin()));
                static_assert(noexcept(arr1.crbegin()));
                static_assert(noexcept(arr1.riter(bsl::to_umax(0))));
                static_assert(noexcept(arr1.criter(bsl::to_umax(0))));
                static_assert(noexcept(arr1.rend()));
                static_assert(noexcept(arr1.crend()));
                static_assert(noexcept(arr1.empty()));
                static_assert(noexcept(!!arr1));
                static_assert(noexcept(arr1.size()));
                static_assert(noexcept(arr1.max_size()));
                static_assert(noexcept(arr1.size_bytes()));
                static_assert(noexcept(arr1 == arr2));
                static_assert(noexcept(arr1 != arr2));
                static_assert(noexcept(bsl::print() << arr1));
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
