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

#include <bsl/basic_string_view.hpp>
#include <bsl/convert.hpp>
#include <bsl/discard.hpp>
#include <bsl/ut.hpp>

namespace
{
    constinit bsl::basic_string_view<bsl::char_type> const g_verify_constinit{"Hello World"};
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
    using bsv_type = bsl::basic_string_view<bsl::char_type>;

    bsl::ut_scenario{"verify supports constinit"} = []() noexcept {
        bsl::discard(g_verify_constinit);
    };

    bsl::ut_scenario{"verify noexcept"} = []() noexcept {
        bsl::ut_given{} = []() noexcept {
            bsv_type mut_msg1{};
            bsv_type mut_msg2{};
            bsv_type const msg1{};
            bsv_type const msg2{};
            bsl::ut_then{} = []() noexcept {
                static_assert(noexcept(bsv_type{}));
                static_assert(noexcept(bsv_type{""}));
                static_assert(noexcept(bsv_type{"", bsl::to_umax(0)}));

                static_assert(noexcept(mut_msg1.at_if(bsl::to_umax(0))));
                static_assert(noexcept(mut_msg1.front_if()));
                static_assert(noexcept(mut_msg1.back_if()));
                static_assert(noexcept(mut_msg1.data()));
                static_assert(noexcept(mut_msg1.begin()));
                static_assert(noexcept(mut_msg1.cbegin()));
                static_assert(noexcept(mut_msg1.iter(bsl::to_umax(0))));
                static_assert(noexcept(mut_msg1.citer(bsl::to_umax(0))));
                static_assert(noexcept(mut_msg1.end()));
                static_assert(noexcept(mut_msg1.cend()));
                static_assert(noexcept(mut_msg1.rbegin()));
                static_assert(noexcept(mut_msg1.crbegin()));
                static_assert(noexcept(mut_msg1.riter(bsl::to_umax(0))));
                static_assert(noexcept(mut_msg1.criter(bsl::to_umax(0))));
                static_assert(noexcept(mut_msg1.rend()));
                static_assert(noexcept(mut_msg1.crend()));
                static_assert(noexcept(mut_msg1.empty()));
                static_assert(noexcept(!!mut_msg1));
                static_assert(noexcept(mut_msg1.size()));
                static_assert(noexcept(mut_msg1.length()));
                static_assert(noexcept(mut_msg1.max_size()));
                static_assert(noexcept(mut_msg1.size_bytes()));
                static_assert(noexcept(mut_msg1.remove_prefix(bsl::to_umax(0))));
                static_assert(noexcept(mut_msg1.remove_suffix(bsl::to_umax(0))));
                static_assert(noexcept(mut_msg1.substr()));
                static_assert(noexcept(mut_msg1.compare(bsv_type{"H"})));
                static_assert(noexcept(mut_msg1.compare({}, {}, bsv_type{"H"})));
                static_assert(noexcept(mut_msg1.compare({}, {}, bsv_type{"H"}, {}, {})));
                static_assert(noexcept(mut_msg1.compare("H")));
                static_assert(noexcept(mut_msg1.compare({}, {}, "H")));
                static_assert(noexcept(mut_msg1.compare({}, {}, "H", {})));
                static_assert(noexcept(mut_msg1.starts_with(bsv_type{})));
                static_assert(noexcept(mut_msg1.starts_with('H')));
                static_assert(noexcept(mut_msg1.starts_with("")));
                static_assert(noexcept(mut_msg1.ends_with(bsv_type{})));
                static_assert(noexcept(mut_msg1.ends_with('H')));
                static_assert(noexcept(mut_msg1.ends_with("")));
                static_assert(noexcept(mut_msg1.find(bsv_type{})));
                static_assert(noexcept(mut_msg1.find('H')));
                static_assert(noexcept(mut_msg1.find("")));
                static_assert(noexcept(mut_msg1 == mut_msg2));
                static_assert(noexcept(mut_msg1 == ""));
                static_assert(noexcept("" == mut_msg2));
                static_assert(noexcept(mut_msg1 != mut_msg2));
                static_assert(noexcept(mut_msg1 != ""));
                static_assert(noexcept("" != mut_msg2));

                static_assert(noexcept(msg1.at_if(bsl::to_umax(0))));
                static_assert(noexcept(msg1.front_if()));
                static_assert(noexcept(msg1.back_if()));
                static_assert(noexcept(msg1.data()));
                static_assert(noexcept(msg1.begin()));
                static_assert(noexcept(msg1.cbegin()));
                static_assert(noexcept(msg1.iter(bsl::to_umax(0))));
                static_assert(noexcept(msg1.citer(bsl::to_umax(0))));
                static_assert(noexcept(msg1.end()));
                static_assert(noexcept(msg1.cend()));
                static_assert(noexcept(msg1.rbegin()));
                static_assert(noexcept(msg1.crbegin()));
                static_assert(noexcept(msg1.riter(bsl::to_umax(0))));
                static_assert(noexcept(msg1.criter(bsl::to_umax(0))));
                static_assert(noexcept(msg1.rend()));
                static_assert(noexcept(msg1.crend()));
                static_assert(noexcept(msg1.empty()));
                static_assert(noexcept(!!msg1));
                static_assert(noexcept(msg1.size()));
                static_assert(noexcept(msg1.length()));
                static_assert(noexcept(msg1.max_size()));
                static_assert(noexcept(msg1.size_bytes()));
                static_assert(noexcept(msg1.substr()));
                static_assert(noexcept(msg1.compare(bsv_type{"H"})));
                static_assert(noexcept(msg1.compare({}, {}, bsv_type{"H"})));
                static_assert(noexcept(msg1.compare({}, {}, bsv_type{"H"}, {}, {})));
                static_assert(noexcept(msg1.compare("H")));
                static_assert(noexcept(msg1.compare({}, {}, "H")));
                static_assert(noexcept(msg1.compare({}, {}, "H", {})));
                static_assert(noexcept(msg1.starts_with(bsv_type{})));
                static_assert(noexcept(msg1.starts_with('H')));
                static_assert(noexcept(msg1.starts_with("")));
                static_assert(noexcept(msg1.ends_with(bsv_type{})));
                static_assert(noexcept(msg1.ends_with('H')));
                static_assert(noexcept(msg1.ends_with("")));
                static_assert(noexcept(msg1.find(bsv_type{})));
                static_assert(noexcept(msg1.find('H')));
                static_assert(noexcept(msg1.find("")));
                static_assert(noexcept(msg1 == msg2));
                static_assert(noexcept(msg1 == ""));
                static_assert(noexcept("" == msg2));
                static_assert(noexcept(msg1 != msg2));
                static_assert(noexcept(msg1 != ""));
                static_assert(noexcept("" != msg2));
            };
        };
    };

    return bsl::ut_success();
}
