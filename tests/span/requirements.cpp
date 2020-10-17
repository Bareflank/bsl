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
#include <bsl/discard.hpp>
#include <bsl/span.hpp>
#include <bsl/ut.hpp>

namespace
{
    constinit bsl::span<bool> const verify_constinit{};

    // Needed for requirements testing
    // NOLINTNEXTLINE(bsl-user-defined-type-names-match-header-name)
    class fixture_t final
    {
        bsl::array<bool, static_cast<bsl::uintmax>(5)> arr{};
        bsl::span<bool> spn{arr.data(), arr.size()};

    public:
        [[nodiscard]] constexpr auto
        test_member_const() const noexcept -> bool
        {
            bsl::discard(spn.at_if(bsl::to_umax(0)));
            bsl::discard(spn.front_if());
            bsl::discard(spn.back_if());
            bsl::discard(spn.data());
            bsl::discard(spn.begin());
            bsl::discard(spn.cbegin());
            bsl::discard(spn.iter(bsl::to_umax(0)));
            bsl::discard(spn.citer(bsl::to_umax(0)));
            bsl::discard(spn.end());
            bsl::discard(spn.cend());
            bsl::discard(spn.rbegin());
            bsl::discard(spn.crbegin());
            bsl::discard(spn.riter(bsl::to_umax(0)));
            bsl::discard(spn.criter(bsl::to_umax(0)));
            bsl::discard(spn.rend());
            bsl::discard(spn.crend());
            bsl::discard(spn.empty());
            bsl::discard(!!spn);
            bsl::discard(spn.size());
            bsl::discard(spn.max_size());
            bsl::discard(spn.size_bytes());
            bsl::discard(spn.first());
            bsl::discard(spn.last());
            bsl::discard(spn.subspan(bsl::to_umax(0)));

            return true;
        }

        [[nodiscard]] constexpr auto
        test_member_nonconst() noexcept -> bool
        {
            bsl::discard(spn.at_if(bsl::to_umax(0)));
            bsl::discard(spn.front_if());
            bsl::discard(spn.back_if());
            bsl::discard(spn.data());
            bsl::discard(spn.begin());
            bsl::discard(spn.cbegin());
            bsl::discard(spn.iter(bsl::to_umax(0)));
            bsl::discard(spn.citer(bsl::to_umax(0)));
            bsl::discard(spn.end());
            bsl::discard(spn.cend());
            bsl::discard(spn.rbegin());
            bsl::discard(spn.crbegin());
            bsl::discard(spn.riter(bsl::to_umax(0)));
            bsl::discard(spn.criter(bsl::to_umax(0)));
            bsl::discard(spn.rend());
            bsl::discard(spn.crend());
            bsl::discard(spn.empty());
            bsl::discard(!!spn);
            bsl::discard(spn.size());
            bsl::discard(spn.max_size());
            bsl::discard(spn.size_bytes());
            bsl::discard(spn.first());
            bsl::discard(spn.last());
            bsl::discard(spn.subspan(bsl::to_umax(0)));

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
    bsl::ut_scenario{"verify supports constinit "} = []() {
        bsl::discard(verify_constinit);
    };

    bsl::ut_scenario{"verify noexcept"} = []() {
        bsl::ut_given{} = []() {
            bsl::span<bool> spn1{};
            bsl::span<bool> spn2{};
            bsl::ut_then{} = []() {
                static_assert(noexcept(spn1.at_if(bsl::to_umax(0))));
                static_assert(noexcept(spn1.front_if()));
                static_assert(noexcept(spn1.back_if()));
                static_assert(noexcept(spn1.data()));
                static_assert(noexcept(spn1.begin()));
                static_assert(noexcept(spn1.cbegin()));
                static_assert(noexcept(spn1.iter(bsl::to_umax(0))));
                static_assert(noexcept(spn1.citer(bsl::to_umax(0))));
                static_assert(noexcept(spn1.end()));
                static_assert(noexcept(spn1.cend()));
                static_assert(noexcept(spn1.rbegin()));
                static_assert(noexcept(spn1.crbegin()));
                static_assert(noexcept(spn1.riter(bsl::to_umax(0))));
                static_assert(noexcept(spn1.criter(bsl::to_umax(0))));
                static_assert(noexcept(spn1.rend()));
                static_assert(noexcept(spn1.crend()));
                static_assert(noexcept(spn1.empty()));
                static_assert(noexcept(!!spn1));
                static_assert(noexcept(spn1.size()));
                static_assert(noexcept(spn1.max_size()));
                static_assert(noexcept(spn1.size_bytes()));
                static_assert(noexcept(spn1.size_bytes()));
                static_assert(noexcept(spn1 == spn2));
                static_assert(noexcept(spn1 != spn2));
                static_assert(noexcept(spn1.first()));
                static_assert(noexcept(spn1.last()));
                static_assert(noexcept(spn1.subspan(bsl::to_umax(0))));
                static_assert(noexcept(bsl::as_bytes<bsl::uint8>(nullptr, bsl::to_umax(0))));
                static_assert(noexcept(bsl::as_bytes(bsl::span<bool>{})));
                static_assert(
                    noexcept(bsl::as_writable_bytes<bsl::uint8>(nullptr, bsl::to_umax(0))));

                bsl::span<bool> view{};
                static_assert(noexcept(bsl::as_writable_bytes(view)));
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
