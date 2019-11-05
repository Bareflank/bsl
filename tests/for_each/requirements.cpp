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

#include <bsl/for_each.hpp>
#include <bsl/discard.hpp>
#include <bsl/string_view.hpp>
#include <bsl/ut.hpp>

namespace
{
    constexpr bsl::string_view msg1{"Hello World"};

    constexpr void
    except_void_e(bsl::char_type const &e)
    {
        bsl::discard(e);
    }

    constexpr void
    except_void_e_i(bsl::char_type const &e, bsl::uintmax i)
    {
        bsl::discard(e);
        bsl::discard(i);
    }

    constexpr bool
    except_bool_e(bsl::char_type const &e)
    {
        bsl::discard(e);
        return bsl::for_each_continue;
    }

    constexpr bool
    except_bool_e_i(bsl::char_type const &e, bsl::uintmax i)
    {
        bsl::discard(e);
        bsl::discard(i);
        return bsl::for_each_continue;
    }

    constexpr void
    noexcept_void_e(bsl::char_type const &e) noexcept
    {
        bsl::discard(e);
    }

    constexpr void
    noexcept_void_e_i(bsl::char_type const &e, bsl::uintmax i) noexcept
    {
        bsl::discard(e);
        bsl::discard(i);
    }

    constexpr bool
    noexcept_bool_e(bsl::char_type const &e) noexcept
    {
        bsl::discard(e);
        return bsl::for_each_continue;
    }

    constexpr bool
    noexcept_bool_e_i(bsl::char_type const &e, bsl::uintmax i) noexcept
    {
        bsl::discard(e);
        bsl::discard(i);
        return bsl::for_each_continue;
    }

    class fixture_t final
    {
        bsl::string_view msg2{"Hello World"};

    public:
        [[nodiscard]] constexpr bool
        test_member_const() const
        {
            for_each(msg2, &except_void_e);
            for_each(msg2, &except_void_e_i);
            for_each(msg2, &except_bool_e);
            for_each(msg2, &except_bool_e_i);

            for_each(msg2.begin(), msg2.end(), &except_void_e);
            for_each(msg2.begin(), msg2.end(), &except_void_e_i);
            for_each(msg2.begin(), msg2.end(), &except_bool_e);
            for_each(msg2.begin(), msg2.end(), &except_bool_e_i);

            return true;
        }

        [[nodiscard]] constexpr bool
        test_member_nonconst()
        {
            for_each(msg2, &except_void_e);
            for_each(msg2, &except_void_e_i);
            for_each(msg2, &except_bool_e);
            for_each(msg2, &except_bool_e_i);

            for_each(msg2.begin(), msg2.end(), &except_void_e);
            for_each(msg2.begin(), msg2.end(), &except_void_e_i);
            for_each(msg2.begin(), msg2.end(), &except_bool_e);
            for_each(msg2.begin(), msg2.end(), &except_bool_e_i);

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

    bsl::ut_scenario{"verify noexcept for view types"} = []() {
        static_assert(!noexcept(for_each(msg1, &except_void_e)));
        static_assert(!noexcept(for_each(msg1, &except_void_e_i)));
        static_assert(!noexcept(for_each(msg1, &except_bool_e)));
        static_assert(!noexcept(for_each(msg1, &except_bool_e_i)));
        static_assert(noexcept(for_each(msg1, &noexcept_void_e)));
        static_assert(noexcept(for_each(msg1, &noexcept_void_e_i)));
        static_assert(noexcept(for_each(msg1, &noexcept_bool_e)));
        static_assert(noexcept(for_each(msg1, &noexcept_bool_e_i)));
    };

    bsl::ut_scenario{"verify noexcept for iterator types"} = []() {
        static_assert(!noexcept(for_each(msg1.begin(), msg1.end(), &except_void_e)));
        static_assert(!noexcept(for_each(msg1.begin(), msg1.end(), &except_void_e_i)));
        static_assert(!noexcept(for_each(msg1.begin(), msg1.end(), &except_bool_e)));
        static_assert(!noexcept(for_each(msg1.begin(), msg1.end(), &except_bool_e_i)));
        static_assert(noexcept(for_each(msg1.begin(), msg1.end(), &noexcept_void_e)));
        static_assert(noexcept(for_each(msg1.begin(), msg1.end(), &noexcept_void_e_i)));
        static_assert(noexcept(for_each(msg1.begin(), msg1.end(), &noexcept_bool_e)));
        static_assert(noexcept(for_each(msg1.begin(), msg1.end(), &noexcept_bool_e_i)));
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
