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

#include <bsl/common_type.hpp>
#include <bsl/is_same.hpp>

#include <bsl/ut.hpp>

namespace
{
    struct s1_type final
    {};

    struct s2_type final
    {
        // We need the conversions to be implicit to prove that common_type
        // is working properly.
        // NOLINTNEXTLINE(hicpp-explicit-conversions)
        [[nodiscard]] operator void *();
    };

    struct s3_type final
    {
        // We need the conversions to be implicit to prove that common_type
        // is working properly.
        // NOLINTNEXTLINE(hicpp-explicit-conversions)
        [[nodiscard]] operator void *();
    };

    struct s4_type final
    {
        // We need the conversions to be implicit to prove that common_type
        // is working properly.
        // NOLINTNEXTLINE(hicpp-explicit-conversions)
        [[nodiscard]] operator void const *();
    };

    class b1_type
    {};

    class d1_type final : public b1_type
    {};
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

    static_assert(is_same<common_type_t<void>, void>::value);
    static_assert(is_same<common_type_t<void, void>, void>::value);
    static_assert(is_same<common_type_t<void, void, void>, void>::value);
    static_assert(is_same<common_type_t<void, void, void, void>, void>::value);

    static_assert(is_same<common_type_t<void const>, void>::value);
    static_assert(is_same<common_type_t<void, void const>, void>::value);
    static_assert(is_same<common_type_t<void, void, void const>, void>::value);
    static_assert(is_same<common_type_t<void, void, void, void const>, void>::value);

    static_assert(is_same<common_type_t<bool>, bool>::value);
    static_assert(is_same<common_type_t<bool, bool>, bool>::value);
    static_assert(is_same<common_type_t<bool, bool, bool>, bool>::value);
    static_assert(is_same<common_type_t<bool, bool, bool, bool>, bool>::value);

    static_assert(is_same<common_type_t<bool const>, bool>::value);
    static_assert(is_same<common_type_t<bool, bool const>, bool>::value);
    static_assert(is_same<common_type_t<bool, bool, bool const>, bool>::value);
    static_assert(is_same<common_type_t<bool, bool, bool, bool const>, bool>::value);

    static_assert(is_same<common_type_t<bool &>, bool>::value);
    static_assert(is_same<common_type_t<bool &, bool &>, bool>::value);
    static_assert(is_same<common_type_t<bool &, bool &, bool &>, bool>::value);
    static_assert(is_same<common_type_t<bool &, bool &, bool &, bool &>, bool>::value);

    static_assert(is_same<common_type_t<bool const &>, bool>::value);
    static_assert(is_same<common_type_t<bool &, bool const &>, bool>::value);
    static_assert(is_same<common_type_t<bool &, bool &, bool const &>, bool>::value);
    static_assert(is_same<common_type_t<bool &, bool &, bool &, bool const &>, bool>::value);

    static_assert(is_same<common_type_t<bool>, bool>::value);
    static_assert(is_same<common_type_t<bool &, bool>, bool>::value);
    static_assert(is_same<common_type_t<bool &, bool &, bool>, bool>::value);
    static_assert(is_same<common_type_t<bool &, bool &, bool &, bool>, bool>::value);

    static_assert(is_same<common_type_t<bool &&>, bool>::value);
    static_assert(is_same<common_type_t<bool &, bool &&>, bool>::value);
    static_assert(is_same<common_type_t<bool &, bool &, bool &&>, bool>::value);
    static_assert(is_same<common_type_t<bool &, bool &, bool &, bool &&>, bool>::value);

    static_assert(is_same<common_type_t<bool &&>, bool>::value);
    static_assert(is_same<common_type_t<bool &&, bool &&>, bool>::value);
    static_assert(is_same<common_type_t<bool &&, bool &&, bool &&>, bool>::value);
    static_assert(is_same<common_type_t<bool &&, bool &&, bool &&, bool &&>, bool>::value);

    static_assert(is_same<common_type_t<bool const &&>, bool>::value);
    static_assert(is_same<common_type_t<bool &&, bool const &&>, bool>::value);
    static_assert(is_same<common_type_t<bool &&, bool &&, bool const &&>, bool>::value);
    static_assert(is_same<common_type_t<bool &&, bool &&, bool &&, bool const &&>, bool>::value);

    static_assert(is_same<common_type_t<bool>, bool>::value);
    static_assert(is_same<common_type_t<bool &&, bool>, bool>::value);
    static_assert(is_same<common_type_t<bool &&, bool &&, bool>, bool>::value);
    static_assert(is_same<common_type_t<bool &&, bool &&, bool &&, bool>, bool>::value);

    static_assert(is_same<common_type_t<bool &>, bool>::value);
    static_assert(is_same<common_type_t<bool &&, bool &>, bool>::value);
    static_assert(is_same<common_type_t<bool &&, bool &&, bool &>, bool>::value);
    static_assert(is_same<common_type_t<bool &&, bool &&, bool &&, bool &>, bool>::value);

    static_assert(is_same<common_type_t<bool *>, bool *>::value);
    static_assert(is_same<common_type_t<bool *, bool *>, bool *>::value);
    static_assert(is_same<common_type_t<bool *, bool *, bool *>, bool *>::value);
    static_assert(is_same<common_type_t<bool *, bool *, bool *, bool *>, bool *>::value);

    static_assert(is_same<common_type_t<bool const *>, bool const *>::value);
    static_assert(is_same<common_type_t<bool *, bool const *>, bool const *>::value);
    static_assert(is_same<common_type_t<bool *, bool *, bool const *>, bool const *>::value);
    static_assert(is_same<common_type_t<bool *, bool *, bool *, bool const *>, bool const *>::value);

    // static_assert(is_same<common_type_t<bool[42]>, bool *>::value);
    // static_assert(is_same<common_type_t<bool[42], bool[42]>, bool *>::value);
    // static_assert(is_same<common_type_t<bool[42], bool[42], bool[42]>, bool *>::value);
    // static_assert(is_same<common_type_t<bool[42], bool[42], bool[42], bool[42]>, bool *>::value);
    // static_assert(is_same<common_type_t<bool const[42]>, bool const *>::value);
    // static_assert(is_same<common_type_t<bool[42], bool const[42]>, bool const *>::value);
    // static_assert(is_same<common_type_t<bool[42], bool[42], bool const[42]>, bool const *>::value);
    // static_assert(is_same<common_type_t<bool[42], bool[42], bool[42], bool const[42]>, bool const *>::value);
    // static_assert(is_same<common_type_t<bool[23]>, bool *>::value);
    // static_assert(is_same<common_type_t<bool[42], bool[23]>, bool *>::value);
    // static_assert(is_same<common_type_t<bool[42], bool[42], bool[23]>, bool *>::value);
    // static_assert(is_same<common_type_t<bool[42], bool[42], bool[42], bool[23]>, bool *>::value);
    // static_assert(is_same<common_type_t<bool const[23]>, bool const *>::value);
    // static_assert(is_same<common_type_t<bool[42], bool const[23]>, bool const *>::value);
    // static_assert(is_same<common_type_t<bool[42], bool[42], bool const[23]>, bool const *>::value);
    // static_assert(is_same<common_type_t<bool[42], bool[42], bool[42], bool const[23]>, bool const *>::value);

    static_assert(is_same<common_type_t<s1_type, s1_type>, s1_type>::value);
    static_assert(is_same<common_type_t<s2_type, s3_type>, void *>::value);
    static_assert(is_same<common_type_t<s3_type, s2_type>, void *>::value);
    static_assert(is_same<common_type_t<s4_type, s2_type>, void const *>::value);
    static_assert(is_same<common_type_t<s2_type, s4_type>, void const *>::value);

    static_assert(is_same<common_type_t<b1_type, d1_type>, b1_type>::value);
    static_assert(is_same<common_type_t<d1_type, b1_type>, b1_type>::value);

    static_assert(is_same<common_type_t<bool b1_type::*, bool d1_type::*>, bool d1_type::*>::value);
    static_assert(is_same<common_type_t<bool d1_type::*, bool b1_type::*>, bool d1_type::*>::value);
    static_assert(is_same<common_type_t<bool (b1_type::*)(), bool (d1_type::*)()>, bool (d1_type::*)()>::value);
    static_assert(is_same<common_type_t<bool (d1_type::*)(), bool (b1_type::*)()>, bool (d1_type::*)()>::value);
    static_assert(is_same<common_type_t<bool (b1_type::*)() const, bool (d1_type::*)() const>, bool (d1_type::*)() const>::value);
    static_assert(is_same<common_type_t<bool (d1_type::*)() const, bool (b1_type::*)() const>, bool (d1_type::*)() const>::value);

    static_assert(is_same<common_type_t<void(), void()>, void (*)()>::value);
    static_assert(is_same<common_type_t<void (&)(), void (&)()>, void (*)()>::value);
    static_assert(is_same<common_type_t<void (&)(), void(&&)()>, void (*)()>::value);
    static_assert(is_same<common_type_t<void(&&)(), void (&)()>, void (*)()>::value);
    static_assert(is_same<common_type_t<void(&&)(), void(&&)()>, void (*)()>::value);

    static_assert(is_same<common_type_t<decltype(nullptr), void *>, void *>::value);
    static_assert(is_same<common_type_t<decltype(nullptr), bool *>, bool *>::value);

    // clang-format on

    return bsl::ut_success();
}
