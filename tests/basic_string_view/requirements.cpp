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
#include <bsl/is_pod.hpp>
#include <bsl/ut.hpp>

namespace
{
    bsl::basic_string_view<bsl::char_type> pod;

    class fixture_t final
    {
        bsl::basic_string_view<bsl::char_type> msg{"Hello World"};

    public:
        [[nodiscard]] constexpr bool
        test_member_const() const
        {
            bsl::discard(msg.at_if(bsl::to_umax(0)));
            bsl::discard(msg.front_if());
            bsl::discard(msg.back_if());
            bsl::discard(msg.data());
            bsl::discard(msg.begin());
            bsl::discard(msg.cbegin());
            bsl::discard(msg.end());
            bsl::discard(msg.cend());
            bsl::discard(msg.iter(bsl::to_umax(0)));
            bsl::discard(msg.citer(bsl::to_umax(0)));
            bsl::discard(msg.rbegin());
            bsl::discard(msg.crbegin());
            bsl::discard(msg.rend());
            bsl::discard(msg.crend());
            bsl::discard(msg.riter(bsl::to_umax(0)));
            bsl::discard(msg.criter(bsl::to_umax(0)));
            bsl::discard(msg.empty());
            bsl::discard(msg.size());
            bsl::discard(msg.length());
            bsl::discard(msg.max_size());
            bsl::discard(msg.size_bytes());
            bsl::discard(msg.substr());
            bsl::discard(msg.compare(bsl::basic_string_view<bsl::char_type>{}));
            bsl::discard(msg.compare({}, {}, bsl::basic_string_view<bsl::char_type>{}));
            bsl::discard(msg.compare({}, {}, bsl::basic_string_view<bsl::char_type>{}, {}, {}));
            bsl::discard(msg.compare(""));
            bsl::discard(msg.compare({}, {}, ""));
            bsl::discard(msg.compare({}, {}, "", {}));
            bsl::discard(msg.starts_with(bsl::basic_string_view<bsl::char_type>{}));
            bsl::discard(msg.starts_with('H'));
            bsl::discard(msg.starts_with(""));
            bsl::discard(msg.ends_with(bsl::basic_string_view<bsl::char_type>{}));
            bsl::discard(msg.ends_with('H'));
            bsl::discard(msg.ends_with(""));

            return true;
        }

        [[nodiscard]] constexpr bool
        test_member_nonconst()
        {
            bsl::discard(msg.at_if(bsl::to_umax(0)));
            bsl::discard(msg.front_if());
            bsl::discard(msg.back_if());
            bsl::discard(msg.data());
            bsl::discard(msg.begin());
            bsl::discard(msg.cbegin());
            bsl::discard(msg.end());
            bsl::discard(msg.cend());
            bsl::discard(msg.iter(bsl::to_umax(0)));
            bsl::discard(msg.citer(bsl::to_umax(0)));
            bsl::discard(msg.rbegin());
            bsl::discard(msg.crbegin());
            bsl::discard(msg.rend());
            bsl::discard(msg.crend());
            bsl::discard(msg.riter(bsl::to_umax(0)));
            bsl::discard(msg.criter(bsl::to_umax(0)));
            bsl::discard(msg.empty());
            bsl::discard(msg.size());
            bsl::discard(msg.length());
            bsl::discard(msg.max_size());
            bsl::discard(msg.size_bytes());
            bsl::discard(msg.remove_prefix(bsl::to_umax(0)));
            bsl::discard(msg.remove_suffix(bsl::to_umax(0)));
            bsl::discard(msg.substr());
            bsl::discard(msg.compare(bsl::basic_string_view<bsl::char_type>{}));
            bsl::discard(msg.compare({}, {}, bsl::basic_string_view<bsl::char_type>{}));
            bsl::discard(msg.compare({}, {}, bsl::basic_string_view<bsl::char_type>{}, {}, {}));
            bsl::discard(msg.compare(""));
            bsl::discard(msg.compare({}, {}, ""));
            bsl::discard(msg.compare({}, {}, "", {}));
            bsl::discard(msg.starts_with(bsl::basic_string_view<bsl::char_type>{}));
            bsl::discard(msg.starts_with('H'));
            bsl::discard(msg.starts_with(""));
            bsl::discard(msg.ends_with(bsl::basic_string_view<bsl::char_type>{}));
            bsl::discard(msg.ends_with('H'));
            bsl::discard(msg.ends_with(""));

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
    using bsv_type = bsl::basic_string_view<bsl::char_type>;

    bsl::ut_scenario{"verify supports global POD"} = []() {
        bsl::discard(pod);
        static_assert(is_pod<decltype(pod)>::value);
    };

    bsl::ut_scenario{"verify noexcept"} = []() {
        bsl::ut_given{} = []() {
            bsv_type msg1{};
            bsv_type msg2{};
            bsl::ut_then{} = []() {
                static_assert(noexcept(bsv_type{}));
                static_assert(noexcept(bsv_type{""}));
                static_assert(noexcept(msg1.at_if(bsl::to_umax(0))));
                static_assert(noexcept(msg1.front_if()));
                static_assert(noexcept(msg1.back_if()));
                static_assert(noexcept(msg1.data()));
                static_assert(noexcept(msg1.begin()));
                static_assert(noexcept(msg1.cbegin()));
                static_assert(noexcept(msg1.end()));
                static_assert(noexcept(msg1.cend()));
                static_assert(noexcept(msg1.iter(bsl::to_umax(0))));
                static_assert(noexcept(msg1.citer(bsl::to_umax(0))));
                static_assert(noexcept(msg1.rbegin()));
                static_assert(noexcept(msg1.crbegin()));
                static_assert(noexcept(msg1.rend()));
                static_assert(noexcept(msg1.crend()));
                static_assert(noexcept(msg1.riter(bsl::to_umax(0))));
                static_assert(noexcept(msg1.criter(bsl::to_umax(0))));
                static_assert(noexcept(msg1.empty()));
                static_assert(noexcept(msg1.size()));
                static_assert(noexcept(msg1.length()));
                static_assert(noexcept(msg1.max_size()));
                static_assert(noexcept(msg1.size_bytes()));
                static_assert(noexcept(msg1.remove_prefix(bsl::to_umax(0))));
                static_assert(noexcept(msg1.remove_suffix(bsl::to_umax(0))));
                static_assert(noexcept(msg1.substr()));
                static_assert(noexcept(msg1.compare(bsv_type{})));
                static_assert(noexcept(msg1.compare({}, {}, bsv_type{})));
                static_assert(noexcept(msg1.compare({}, {}, bsv_type{}, {}, {})));
                static_assert(noexcept(msg1.compare("")));
                static_assert(noexcept(msg1.compare({}, {}, "")));
                static_assert(noexcept(msg1.compare({}, {}, "", {})));
                static_assert(noexcept(msg1.starts_with(bsv_type{})));
                static_assert(noexcept(msg1.starts_with('H')));
                static_assert(noexcept(msg1.starts_with("")));
                static_assert(noexcept(msg1.ends_with(bsv_type{})));
                static_assert(noexcept(msg1.ends_with('H')));
                static_assert(noexcept(msg1.ends_with("")));
                static_assert(noexcept(msg1 == msg2));    // NOLINT
                static_assert(noexcept(msg1 == ""));      // NOLINT
                static_assert(noexcept("" == msg2));      // NOLINT
                static_assert(noexcept(msg1 != msg2));    // NOLINT
                static_assert(noexcept(msg1 != ""));      // NOLINT
                static_assert(noexcept("" != msg2));      // NOLINT
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
