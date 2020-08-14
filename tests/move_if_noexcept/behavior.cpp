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

#include <bsl/move_if_noexcept.hpp>
#include <bsl/discard.hpp>
#include <bsl/ut.hpp>

namespace
{
    class myclass final
    {
        bool *m_moved;

    public:
        explicit constexpr myclass(bool *moved) noexcept    // --
            : m_moved{moved}
        {}

        constexpr ~myclass() noexcept = default;
        constexpr myclass(myclass const &) noexcept = default;
        [[maybe_unused]] constexpr auto operator=(myclass const &) &noexcept -> myclass & = default;

        constexpr myclass(myclass &&o) noexcept    // --
            : m_moved{nullptr}
        {
            *o.m_moved = true;
        }

        [[maybe_unused]] constexpr auto
        operator=(myclass &&o) &noexcept -> myclass &
        {
            *o.m_moved = true;
            return *this;
        }
    };

    class myclass_except final
    {
        bool *m_moved;

    public:
        explicit constexpr myclass_except(bool *moved) noexcept    // --
            : m_moved{moved}
        {}

        constexpr ~myclass_except() noexcept = default;
        constexpr myclass_except(myclass_except const &) noexcept = default;
        [[maybe_unused]] constexpr auto operator=(myclass_except const &) &noexcept
            -> myclass_except & = default;

        constexpr myclass_except(myclass_except &&o) noexcept(false)    // --
            : m_moved{nullptr}
        {
            *o.m_moved = true;
        }

        [[maybe_unused]] constexpr auto
        operator=(myclass_except &&o) &noexcept(false) -> myclass_except &
        {
            *o.m_moved = true;
            return *this;
        }
    };

    class myclass_nocopy final
    {
        bool *m_moved;

    public:
        explicit constexpr myclass_nocopy(bool *moved) noexcept    // --
            : m_moved{moved}
        {}

        constexpr ~myclass_nocopy() noexcept = default;
        constexpr myclass_nocopy(myclass_nocopy const &) noexcept = delete;
        [[maybe_unused]] constexpr auto operator=(myclass_nocopy const &) &noexcept
            -> myclass_nocopy & = delete;

        constexpr myclass_nocopy(myclass_nocopy &&o) noexcept(false)    // --
            : m_moved{nullptr}
        {
            *o.m_moved = true;
        }

        [[maybe_unused]] constexpr auto
        operator=(myclass_nocopy &&o) &noexcept(false) -> myclass_nocopy &
        {
            *o.m_moved = true;
            return *this;
        }
    };

    /// <!-- description -->
    ///   @brief Used to execute the actual checks. We put the checks in this
    ///     function so that we can validate the tests both at compile-time
    ///     and at run-time. If a bsl::ut_check fails, the tests will either
    ///     fail fast at run-time, or will produce a compile-time error.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Always returns bsl::exit_success.
    ///
    [[nodiscard]] constexpr auto
    tests() noexcept -> bsl::exit_code
    {
        bsl::ut_scenario{"moves"} = []() {
            bsl::ut_given{} = []() {
                bool moved{};
                myclass c1{&moved};
                bsl::ut_when{} = [&c1, &moved]() {
                    myclass c2{bsl::move_if_noexcept(c1)};
                    bsl::discard(c2);
                    bsl::ut_then{} = [&moved]() {
                        bsl::ut_check(moved);
                    };
                };
            };
        };

        bsl::ut_scenario{"copies due to noexcept move constructor"} = []() {
            bsl::ut_given{} = []() {
                bool moved{};
                myclass_except c1{&moved};
                bsl::ut_when{} = [&c1, &moved]() {
                    myclass_except c2{bsl::move_if_noexcept(c1)};
                    bsl::discard(c2);
                    bsl::ut_then{} = [&moved]() {
                        bsl::ut_check(!moved);
                    };
                };
            };
        };

        bsl::ut_scenario{"moves due to missing copy constructor"} = []() {
            bsl::ut_given{} = []() {
                bool moved{};
                myclass_nocopy c1{&moved};
                bsl::ut_when{} = [&c1, &moved]() {
                    myclass_nocopy c2{bsl::move_if_noexcept(c1)};
                    bsl::discard(c2);
                    bsl::ut_then{} = [&moved]() {
                        bsl::ut_check(moved);
                    };
                };
            };
        };

        return bsl::ut_success();
    }
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
    static_assert(tests() == bsl::ut_success());
    return tests();
}
