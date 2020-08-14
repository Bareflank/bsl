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

#include <bsl/is_convertible.hpp>
#include <bsl/is_nothrow_convertible.hpp>
#include <bsl/ut.hpp>

namespace
{
    class myclass_copy_noexcept final
    {
    public:
        constexpr myclass_copy_noexcept() noexcept = default;
        constexpr ~myclass_copy_noexcept() noexcept = default;
        constexpr myclass_copy_noexcept(myclass_copy_noexcept const &) noexcept = default;
        [[maybe_unused]] constexpr auto operator=(myclass_copy_noexcept const &) &noexcept
            -> myclass_copy_noexcept & = default;
        constexpr myclass_copy_noexcept(myclass_copy_noexcept &&) noexcept = default;
        [[maybe_unused]] constexpr auto operator=(myclass_copy_noexcept &&) &noexcept
            -> myclass_copy_noexcept & = default;
    };

    class myclass_copy_except final
    {
    public:
        constexpr myclass_copy_except() noexcept(false) = default;
        constexpr ~myclass_copy_except() noexcept(false) = default;
        constexpr myclass_copy_except(myclass_copy_except const &) noexcept(false) = default;
        [[maybe_unused]] constexpr auto operator=(myclass_copy_except const &) &noexcept(false)
            -> myclass_copy_except & = default;
        constexpr myclass_copy_except(myclass_copy_except &&) noexcept(false) = default;
        [[maybe_unused]] constexpr auto operator=(myclass_copy_except &&) &noexcept(false)
            -> myclass_copy_except & = default;
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
[[nodiscard]] auto
main() noexcept -> bsl::exit_code
{
    using namespace bsl;

    // clang-format off

    static_assert(is_nothrow_convertible<bool, bool>::value);
    static_assert(is_nothrow_convertible<bool, bool const>::value);
    static_assert(is_nothrow_convertible<bool, bsl::int32>::value);
    static_assert(is_nothrow_convertible<bsl::int32, bool>::value);

    static_assert(is_nothrow_convertible<bool *, bool *>::value);
    static_assert(is_nothrow_convertible<bool *, bool const *>::value);
    static_assert(is_nothrow_convertible<bool *, void *>::value);
    static_assert(is_nothrow_convertible<bool *, void const *>::value);
    // static_assert(is_nothrow_convertible<bool[42], bool *>::value);
    // static_assert(is_nothrow_convertible<bool[42], bool const *>::value);
    // static_assert(is_nothrow_convertible<bool[42], void *>::value);
    // static_assert(is_nothrow_convertible<bool[42], void const *>::value);
    static_assert(is_nothrow_convertible<bool &, bool>::value);
    static_assert(is_nothrow_convertible<bool &, bool const>::value);
    static_assert(is_nothrow_convertible<bool &, bool &>::value);
    static_assert(is_nothrow_convertible<bool &, bool const &>::value);
    static_assert(is_nothrow_convertible<bool const &, bool>::value);
    static_assert(is_nothrow_convertible<bool const &, bool const>::value);
    static_assert(is_nothrow_convertible<bool const &, bool const &>::value);

    static_assert(is_nothrow_convertible<bool *, bool const *>::value);
    static_assert(!is_nothrow_convertible<bool const *, bool *>::value);
    static_assert(is_nothrow_convertible<bool const *, bool const *>::value);

    static_assert(is_nothrow_convertible<void *, void const *>::value);
    static_assert(!is_nothrow_convertible<void const *, void *>::value);
    static_assert(is_nothrow_convertible<void const *, void const *>::value);

    static_assert(!is_nothrow_convertible<bool, bool *>::value);
    static_assert(!is_nothrow_convertible<bool const, bool const *>::value);

    static_assert(!is_nothrow_convertible<void, void *>::value);
    static_assert(!is_nothrow_convertible<void const, void const *>::value);

    static_assert(is_nothrow_convertible<bool(bool), bool (*)(bool)>::value);
    static_assert(is_nothrow_convertible<bool (&)(bool), bool (*)(bool)>::value);
    static_assert(is_nothrow_convertible<bool(&&)(bool), bool (*)(bool)>::value);

    static_assert(is_nothrow_convertible<bool *, void *>::value);
    static_assert(!is_nothrow_convertible<void *, bool *>::value);

    static_assert(is_convertible<myclass_copy_noexcept, myclass_copy_noexcept>::value);
    static_assert(is_convertible<myclass_copy_noexcept const, myclass_copy_noexcept>::value);
    static_assert(is_convertible<myclass_copy_noexcept const &, myclass_copy_noexcept>::value);

    static_assert(is_nothrow_convertible<myclass_copy_noexcept, myclass_copy_noexcept>::value);
    static_assert(is_nothrow_convertible<myclass_copy_noexcept const, myclass_copy_noexcept>::value);
    static_assert(is_nothrow_convertible<myclass_copy_noexcept const &, myclass_copy_noexcept>::value);

    static_assert(is_convertible<myclass_copy_except, myclass_copy_except>::value);
    static_assert(is_convertible<myclass_copy_except const, myclass_copy_except>::value);
    static_assert(is_convertible<myclass_copy_except const &, myclass_copy_except>::value);

    static_assert(!is_nothrow_convertible<myclass_copy_except, myclass_copy_except>::value);
    static_assert(!is_nothrow_convertible<myclass_copy_except &, myclass_copy_except>::value);
    static_assert(!is_nothrow_convertible<myclass_copy_except const &, myclass_copy_except>::value);

    // clang-format on

    return bsl::ut_success();
}
