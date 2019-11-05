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

#include <bsl/swap.hpp>
#include <bsl/ut.hpp>

namespace
{
    class myclass1 final
    {
    public:
        constexpr myclass1() noexcept = default;
        ~myclass1() noexcept = default;
        constexpr myclass1(myclass1 const &) noexcept = default;
        constexpr myclass1 &operator=(myclass1 const &) &noexcept = default;
        constexpr myclass1(myclass1 &&) noexcept = default;
        constexpr myclass1 &operator=(myclass1 &&) &noexcept = default;

        explicit constexpr myclass1(bool val) noexcept : data{val}
        {}

        bool data{};    // NOLINT
    };

    class myclass2 final
    {
    public:
        constexpr myclass2() noexcept = default;
        ~myclass2() noexcept = default;
        constexpr myclass2(myclass2 const &) noexcept = default;
        constexpr myclass2 &operator=(myclass2 const &) &noexcept = default;
        constexpr myclass2(myclass2 &&) noexcept(false) = default;
        constexpr myclass2 &operator=(myclass2 &&) &noexcept = default;

        explicit constexpr myclass2(bool val) noexcept : data{val}
        {}

        bool data{};    // NOLINT
    };

    class myclass3 final
    {
    public:
        constexpr myclass3() noexcept = default;
        ~myclass3() noexcept = default;
        constexpr myclass3(myclass3 const &) noexcept = default;
        constexpr myclass3 &operator=(myclass3 const &) &noexcept = default;
        constexpr myclass3(myclass3 &&) noexcept = default;
        constexpr myclass3 &operator=(myclass3 &&) &noexcept(false) = default;

        explicit constexpr myclass3(bool val) noexcept : data{val}
        {}

        bool data{};    // NOLINT
    };

    class myclass4 final
    {
    public:
        constexpr myclass4() noexcept = default;
        ~myclass4() noexcept = default;
        constexpr myclass4(myclass4 const &) noexcept = default;
        constexpr myclass4 &operator=(myclass4 const &) &noexcept = default;
        constexpr myclass4(myclass4 &&) noexcept(false) = default;
        constexpr myclass4 &operator=(myclass4 &&) &noexcept(false) = default;

        explicit constexpr myclass4(bool val) noexcept : data{val}
        {}

        bool data{};    // NOLINT
    };
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
        myclass1 c1{};
        myclass2 c2{};
        myclass3 c3{};
        myclass4 c4{};
        bsl::ut_given{} = []() {
            bsl::ut_then{} = []() {
                static_assert(noexcept(swap(c1, c1)));
                static_assert(!noexcept(swap(c2, c2)));
                static_assert(!noexcept(swap(c3, c3)));
                static_assert(!noexcept(swap(c4, c4)));
            };
        };
    };

    return bsl::ut_success();
}
