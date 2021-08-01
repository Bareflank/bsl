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

#include "../array_init.hpp"

#include <bsl/array.hpp>
#include <bsl/convert.hpp>
#include <bsl/discard.hpp>
#include <bsl/span.hpp>
#include <bsl/ut.hpp>

namespace
{
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
    constinit bsl::span const g_verify_constinit{test::ARRAY_INIT};
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
            bsl::span<bool> mut_spn1{};
            bsl::span<bool> mut_spn2{};
            bsl::span<bool> const spn1{};
            bsl::span<bool> const spn2{};
            bsl::ut_then{} = []() noexcept {
                static_assert(noexcept(bsl::span<bool>{}));
                static_assert(noexcept(bsl::span<bool>{{}, {}}));
                static_assert(noexcept(bsl::span<bool>{test::ARRAY_INIT}));

                static_assert(noexcept(mut_spn1.at_if(bsl::to_idx(0))));
                static_assert(noexcept(mut_spn1.front_if()));
                static_assert(noexcept(mut_spn1.back_if()));
                static_assert(noexcept(mut_spn1.data()));
                static_assert(noexcept(mut_spn1.begin()));
                static_assert(noexcept(mut_spn1.cbegin()));
                static_assert(noexcept(mut_spn1.end()));
                static_assert(noexcept(mut_spn1.cend()));
                static_assert(noexcept(mut_spn1.rbegin()));
                static_assert(noexcept(mut_spn1.crbegin()));
                static_assert(noexcept(mut_spn1.rend()));
                static_assert(noexcept(mut_spn1.crend()));
                static_assert(noexcept(mut_spn1.empty()));
                static_assert(noexcept(mut_spn1.size()));
                static_assert(noexcept(mut_spn1.max_size()));
                static_assert(noexcept(mut_spn1.size_bytes()));
                static_assert(noexcept(mut_spn1.size_bytes()));
                static_assert(noexcept(mut_spn1 == mut_spn2));
                static_assert(noexcept(mut_spn1 != mut_spn2));
                static_assert(noexcept(mut_spn1.first()));
                static_assert(noexcept(mut_spn1.last()));
                static_assert(noexcept(mut_spn1.subspan(bsl::to_idx(0))));

                static_assert(noexcept(spn1.at_if(bsl::to_idx(0))));
                static_assert(noexcept(spn1.front_if()));
                static_assert(noexcept(spn1.back_if()));
                static_assert(noexcept(spn1.data()));
                static_assert(noexcept(spn1.begin()));
                static_assert(noexcept(spn1.cbegin()));
                static_assert(noexcept(spn1.end()));
                static_assert(noexcept(spn1.cend()));
                static_assert(noexcept(spn1.rbegin()));
                static_assert(noexcept(spn1.crbegin()));
                static_assert(noexcept(spn1.rend()));
                static_assert(noexcept(spn1.crend()));
                static_assert(noexcept(spn1.empty()));
                static_assert(noexcept(spn1.size()));
                static_assert(noexcept(spn1.max_size()));
                static_assert(noexcept(spn1.size_bytes()));
                static_assert(noexcept(spn1.size_bytes()));
                static_assert(noexcept(spn1 == spn2));
                static_assert(noexcept(spn1 != spn2));
                static_assert(noexcept(spn1.first()));
                static_assert(noexcept(spn1.last()));
                static_assert(noexcept(spn1.subspan(bsl::to_idx(0))));
            };
        };
    };

    return bsl::ut_success();
}
