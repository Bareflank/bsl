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

#include <bsl/byte.hpp>
#include <bsl/discard.hpp>
#include <bsl/ut.hpp>

namespace
{
    constinit bsl::byte const verify_constinit{};

    class fixture_t final
    {
        bsl::byte b{};

    public:
        [[nodiscard]] constexpr auto
        test_member_const() const noexcept -> bool
        {
            bsl::discard(b.to_integer());
            return true;
        }

        [[nodiscard]] constexpr auto
        test_member_nonconst() noexcept -> bool
        {
            bsl::discard(b.to_integer());
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
[[nodiscard]] auto
main() noexcept -> bsl::exit_code
{
    using namespace bsl;
    constexpr bsl::uint8 byte42{42};

    bsl::ut_scenario{"verify supports constinit "} = []() {
        bsl::discard(verify_constinit);
    };

    bsl::ut_scenario{"verify noexcept"} = []() {
        bsl::ut_given{} = []() {
            bsl::byte b{};
            bsl::ut_then{} = []() {
                static_assert(noexcept(bsl::byte{}));
                static_assert(noexcept(bsl::byte{byte42}));
                static_assert(noexcept(bsl::byte{}.to_integer()));
                static_assert(noexcept(bsl::byte{} == bsl::byte{}));
                static_assert(noexcept(bsl::byte{} != bsl::byte{}));
                static_assert(noexcept(b <<= 4));
                static_assert(noexcept(b >>= 4));
                static_assert(noexcept(bsl::byte{} << 4));
                static_assert(noexcept(bsl::byte{} >> 4));
                static_assert(noexcept(bsl::byte{} | bsl::byte{}));
                static_assert(noexcept(b |= bsl::byte{}));
                static_assert(noexcept(b &= bsl::byte{}));
                static_assert(noexcept(b ^= bsl::byte{}));
                static_assert(noexcept(bsl::byte{} | bsl::byte{}));
                static_assert(noexcept(bsl::byte{} & bsl::byte{}));
                static_assert(noexcept(bsl::byte{} ^ bsl::byte{}));
                static_assert(noexcept(~bsl::byte{}));
            };
        };
    };

    bsl::ut_scenario{"verify constness"} = []() {
        bsl::ut_given{} = []() {
            fixture_t fixture2{};
            bsl::ut_then{} = [&fixture2]() {
                static_assert(fixture1.test_member_const());
                ut_check(fixture2.test_member_nonconst());
            };
        };
    };

    return bsl::ut_success();
}
