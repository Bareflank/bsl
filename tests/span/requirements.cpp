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

#include <bsl/span.hpp>
#include <bsl/array.hpp>
#include <bsl/discard.hpp>
#include <bsl/ut.hpp>

namespace
{
    class fixture_t final
    {
        bsl::array<bool, 5> arr{};

    public:
        [[nodiscard]] constexpr bool
        test_member_const() const
        {
            bsl::span const spn{arr.data(), arr.size()};
            bsl::discard(spn.at_if(0));
            bsl::discard(spn.front_if());
            bsl::discard(spn.back_if());
            bsl::discard(spn.data());
            bsl::discard(spn.begin());
            bsl::discard(spn.cbegin());
            bsl::discard(spn.end());
            bsl::discard(spn.cend());
            bsl::discard(spn.iter(0));
            bsl::discard(spn.citer(0));
            bsl::discard(spn.rbegin());
            bsl::discard(spn.crbegin());
            bsl::discard(spn.rend());
            bsl::discard(spn.crend());
            bsl::discard(spn.riter(0));
            bsl::discard(spn.criter(0));
            bsl::discard(spn.empty());
            bsl::discard(spn.size());
            bsl::discard(spn.max_size());
            bsl::discard(spn.size_bytes());
            bsl::discard(spn.first());
            bsl::discard(spn.last());
            bsl::discard(spn.subspan(0));

            return true;
        }

        [[nodiscard]] constexpr bool
        test_member_nonconst()
        {
            bsl::span spn{arr.data(), arr.size()};
            bsl::discard(spn.at_if(0));
            bsl::discard(spn.front_if());
            bsl::discard(spn.back_if());
            bsl::discard(spn.data());
            bsl::discard(spn.begin());
            bsl::discard(spn.cbegin());
            bsl::discard(spn.end());
            bsl::discard(spn.cend());
            bsl::discard(spn.iter(0));
            bsl::discard(spn.citer(0));
            bsl::discard(spn.rbegin());
            bsl::discard(spn.crbegin());
            bsl::discard(spn.rend());
            bsl::discard(spn.crend());
            bsl::discard(spn.riter(0));
            bsl::discard(spn.criter(0));
            bsl::discard(spn.empty());
            bsl::discard(spn.size());
            bsl::discard(spn.max_size());
            bsl::discard(spn.size_bytes());
            bsl::discard(spn.first());
            bsl::discard(spn.last());
            bsl::discard(spn.subspan(0));

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
    using namespace bsl;

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
