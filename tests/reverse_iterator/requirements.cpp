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

#include <bsl/reverse_iterator.hpp>
#include <bsl/array.hpp>
#include <bsl/ut.hpp>

namespace
{
    constexpr bsl::array<bsl::safe_int32, 6> arr{
        bsl::to_i32(4),
        bsl::to_i32(8),
        bsl::to_i32(15),
        bsl::to_i32(16),
        bsl::to_i32(23),
        bsl::to_i32(42)};
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

    bsl::ut_scenario{"verify noexcept"} = []() {
        bsl::ut_given{} = []() {
            bsl::reverse_iterator ri1{arr.begin()};
            bsl::reverse_iterator const ri2{arr.begin()};
            bsl::ut_then{} = []() {
                static_assert(noexcept(bsl::reverse_iterator{arr.begin()}));
                static_assert(noexcept(ri1.base()));
                static_assert(noexcept(ri1.data()));
                static_assert(noexcept(ri2.data()));
                static_assert(noexcept(ri1.size()));
                static_assert(noexcept(ri1.index()));
                static_assert(noexcept(ri1.empty()));
                static_assert(noexcept(!!ri1));
                static_assert(noexcept(ri1.is_end()));
                static_assert(noexcept(ri1.get_if()));
                static_assert(noexcept(++ri1));
                static_assert(noexcept(--ri1));
                static_assert(noexcept(ri1 == ri2));
                static_assert(noexcept(ri1 != ri2));
                static_assert(noexcept(ri1 < ri2));
                static_assert(noexcept(ri1 <= ri2));
                static_assert(noexcept(ri1 > ri2));
                static_assert(noexcept(ri1 >= ri2));
            };
        };
    };

    return bsl::ut_success();
}
