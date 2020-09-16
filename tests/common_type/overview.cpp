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

#include "../class_empty.hpp"
#include "../class_convertible_to_void_ptr.hpp"
#include "../class_convertible_to_const_void_ptr.hpp"
#include "../class_base.hpp"
#include "../class_subclass.hpp"

#include <bsl/common_type.hpp>
#include <bsl/is_same.hpp>

#include <bsl/ut.hpp>

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
    // clang-format off

    static_assert(bsl::is_same<bsl::common_type_t<void>, void>::value);
    static_assert(bsl::is_same<bsl::common_type_t<void, void>, void>::value);
    static_assert(bsl::is_same<bsl::common_type_t<void, void, void>, void>::value);
    static_assert(bsl::is_same<bsl::common_type_t<void, void, void, void>, void>::value);

    static_assert(bsl::is_same<bsl::common_type_t<void const>, void>::value);
    static_assert(bsl::is_same<bsl::common_type_t<void, void const>, void>::value);
    static_assert(bsl::is_same<bsl::common_type_t<void, void, void const>, void>::value);
    static_assert(bsl::is_same<bsl::common_type_t<void, void, void, void const>, void>::value);

    static_assert(bsl::is_same<bsl::common_type_t<bool>, bool>::value);
    static_assert(bsl::is_same<bsl::common_type_t<bool, bool>, bool>::value);
    static_assert(bsl::is_same<bsl::common_type_t<bool, bool, bool>, bool>::value);
    static_assert(bsl::is_same<bsl::common_type_t<bool, bool, bool, bool>, bool>::value);

    static_assert(bsl::is_same<bsl::common_type_t<bool const>, bool>::value);
    static_assert(bsl::is_same<bsl::common_type_t<bool, bool const>, bool>::value);
    static_assert(bsl::is_same<bsl::common_type_t<bool, bool, bool const>, bool>::value);
    static_assert(bsl::is_same<bsl::common_type_t<bool, bool, bool, bool const>, bool>::value);

    static_assert(bsl::is_same<bsl::common_type_t<bool &>, bool>::value);
    static_assert(bsl::is_same<bsl::common_type_t<bool &, bool &>, bool>::value);
    static_assert(bsl::is_same<bsl::common_type_t<bool &, bool &, bool &>, bool>::value);
    static_assert(bsl::is_same<bsl::common_type_t<bool &, bool &, bool &, bool &>, bool>::value);

    static_assert(bsl::is_same<bsl::common_type_t<bool const &>, bool>::value);
    static_assert(bsl::is_same<bsl::common_type_t<bool &, bool const &>, bool>::value);
    static_assert(bsl::is_same<bsl::common_type_t<bool &, bool &, bool const &>, bool>::value);
    static_assert(bsl::is_same<bsl::common_type_t<bool &, bool &, bool &, bool const &>, bool>::value);

    static_assert(bsl::is_same<bsl::common_type_t<bool>, bool>::value);
    static_assert(bsl::is_same<bsl::common_type_t<bool &, bool>, bool>::value);
    static_assert(bsl::is_same<bsl::common_type_t<bool &, bool &, bool>, bool>::value);
    static_assert(bsl::is_same<bsl::common_type_t<bool &, bool &, bool &, bool>, bool>::value);

    static_assert(bsl::is_same<bsl::common_type_t<bool &&>, bool>::value);
    static_assert(bsl::is_same<bsl::common_type_t<bool &, bool &&>, bool>::value);
    static_assert(bsl::is_same<bsl::common_type_t<bool &, bool &, bool &&>, bool>::value);
    static_assert(bsl::is_same<bsl::common_type_t<bool &, bool &, bool &, bool &&>, bool>::value);

    static_assert(bsl::is_same<bsl::common_type_t<bool &&>, bool>::value);
    static_assert(bsl::is_same<bsl::common_type_t<bool &&, bool &&>, bool>::value);
    static_assert(bsl::is_same<bsl::common_type_t<bool &&, bool &&, bool &&>, bool>::value);
    static_assert(bsl::is_same<bsl::common_type_t<bool &&, bool &&, bool &&, bool &&>, bool>::value);

    static_assert(bsl::is_same<bsl::common_type_t<bool const &&>, bool>::value);
    static_assert(bsl::is_same<bsl::common_type_t<bool &&, bool const &&>, bool>::value);
    static_assert(bsl::is_same<bsl::common_type_t<bool &&, bool &&, bool const &&>, bool>::value);
    static_assert(bsl::is_same<bsl::common_type_t<bool &&, bool &&, bool &&, bool const &&>, bool>::value);

    static_assert(bsl::is_same<bsl::common_type_t<bool>, bool>::value);
    static_assert(bsl::is_same<bsl::common_type_t<bool &&, bool>, bool>::value);
    static_assert(bsl::is_same<bsl::common_type_t<bool &&, bool &&, bool>, bool>::value);
    static_assert(bsl::is_same<bsl::common_type_t<bool &&, bool &&, bool &&, bool>, bool>::value);

    static_assert(bsl::is_same<bsl::common_type_t<bool &>, bool>::value);
    static_assert(bsl::is_same<bsl::common_type_t<bool &&, bool &>, bool>::value);
    static_assert(bsl::is_same<bsl::common_type_t<bool &&, bool &&, bool &>, bool>::value);
    static_assert(bsl::is_same<bsl::common_type_t<bool &&, bool &&, bool &&, bool &>, bool>::value);

    static_assert(bsl::is_same<bsl::common_type_t<bool *>, bool *>::value);
    static_assert(bsl::is_same<bsl::common_type_t<bool *, bool *>, bool *>::value);
    static_assert(bsl::is_same<bsl::common_type_t<bool *, bool *, bool *>, bool *>::value);
    static_assert(bsl::is_same<bsl::common_type_t<bool *, bool *, bool *, bool *>, bool *>::value);

    static_assert(bsl::is_same<bsl::common_type_t<bool const *>, bool const *>::value);
    static_assert(bsl::is_same<bsl::common_type_t<bool *, bool const *>, bool const *>::value);
    static_assert(bsl::is_same<bsl::common_type_t<bool *, bool *, bool const *>, bool const *>::value);
    static_assert(bsl::is_same<bsl::common_type_t<bool *, bool *, bool *, bool const *>, bool const *>::value);

    // NOLINTNEXTLINE(cppcoreguidelines-avoid-c-arrays, hicpp-avoid-c-arrays, modernize-avoid-c-arrays)
    static_assert(bsl::is_same<bsl::common_type_t<bool[42]>, bool *>::value);
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-c-arrays, hicpp-avoid-c-arrays, modernize-avoid-c-arrays)
    static_assert(bsl::is_same<bsl::common_type_t<bool[42], bool[42]>, bool *>::value);
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-c-arrays, hicpp-avoid-c-arrays, modernize-avoid-c-arrays)
    static_assert(bsl::is_same<bsl::common_type_t<bool[42], bool[42], bool[42]>, bool *>::value);
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-c-arrays, hicpp-avoid-c-arrays, modernize-avoid-c-arrays)
    static_assert(bsl::is_same<bsl::common_type_t<bool[42], bool[42], bool[42], bool[42]>, bool *>::value);
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-c-arrays, hicpp-avoid-c-arrays, modernize-avoid-c-arrays)
    static_assert(bsl::is_same<bsl::common_type_t<bool const[42]>, bool const *>::value);
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-c-arrays, hicpp-avoid-c-arrays, modernize-avoid-c-arrays)
    static_assert(bsl::is_same<bsl::common_type_t<bool[42], bool const[42]>, bool const *>::value);
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-c-arrays, hicpp-avoid-c-arrays, modernize-avoid-c-arrays)
    static_assert(bsl::is_same<bsl::common_type_t<bool[42], bool[42], bool const[42]>, bool const *>::value);
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-c-arrays, hicpp-avoid-c-arrays, modernize-avoid-c-arrays)
    static_assert(bsl::is_same<bsl::common_type_t<bool[42], bool[42], bool[42], bool const[42]>, bool const *>::value);
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-c-arrays, hicpp-avoid-c-arrays, modernize-avoid-c-arrays)
    static_assert(bsl::is_same<bsl::common_type_t<bool[23]>, bool *>::value);
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-c-arrays, hicpp-avoid-c-arrays, modernize-avoid-c-arrays)
    static_assert(bsl::is_same<bsl::common_type_t<bool[42], bool[23]>, bool *>::value);
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-c-arrays, hicpp-avoid-c-arrays, modernize-avoid-c-arrays)
    static_assert(bsl::is_same<bsl::common_type_t<bool[42], bool[42], bool[23]>, bool *>::value);
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-c-arrays, hicpp-avoid-c-arrays, modernize-avoid-c-arrays)
    static_assert(bsl::is_same<bsl::common_type_t<bool[42], bool[42], bool[42], bool[23]>, bool *>::value);
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-c-arrays, hicpp-avoid-c-arrays, modernize-avoid-c-arrays)
    static_assert(bsl::is_same<bsl::common_type_t<bool const[23]>, bool const *>::value);
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-c-arrays, hicpp-avoid-c-arrays, modernize-avoid-c-arrays)
    static_assert(bsl::is_same<bsl::common_type_t<bool[42], bool const[23]>, bool const *>::value);
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-c-arrays, hicpp-avoid-c-arrays, modernize-avoid-c-arrays)
    static_assert(bsl::is_same<bsl::common_type_t<bool[42], bool[42], bool const[23]>, bool const *>::value);
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-c-arrays, hicpp-avoid-c-arrays, modernize-avoid-c-arrays)
    static_assert(bsl::is_same<bsl::common_type_t<bool[42], bool[42], bool[42], bool const[23]>, bool const *>::value);

    static_assert(bsl::is_same<bsl::common_type_t<test::class_empty, test::class_empty>, test::class_empty>::value);
    static_assert(bsl::is_same<bsl::common_type_t<test::class_convertible_to_void_ptr, void *>, void *>::value);
    static_assert(bsl::is_same<bsl::common_type_t<void *, test::class_convertible_to_void_ptr>, void *>::value);
    static_assert(bsl::is_same<bsl::common_type_t<test::class_convertible_to_const_void_ptr, test::class_convertible_to_void_ptr>, void const *>::value);
    static_assert(bsl::is_same<bsl::common_type_t<test::class_convertible_to_void_ptr, test::class_convertible_to_const_void_ptr>, void const *>::value);

    static_assert(bsl::is_same<bsl::common_type_t<test::class_base, test::class_subclass>, test::class_base>::value);
    static_assert(bsl::is_same<bsl::common_type_t<test::class_subclass, test::class_base>, test::class_base>::value);

    static_assert(bsl::is_same<bsl::common_type_t<bool test::class_base::*, bool test::class_subclass::*>, bool test::class_subclass::*>::value);
    static_assert(bsl::is_same<bsl::common_type_t<bool test::class_subclass::*, bool test::class_base::*>, bool test::class_subclass::*>::value);
    static_assert(bsl::is_same<bsl::common_type_t<bool (test::class_base::*)(), bool (test::class_subclass::*)()>, bool (test::class_subclass::*)()>::value);
    static_assert(bsl::is_same<bsl::common_type_t<bool (test::class_subclass::*)(), bool (test::class_base::*)()>, bool (test::class_subclass::*)()>::value);
    static_assert(bsl::is_same<bsl::common_type_t<bool (test::class_base::*)() const, bool (test::class_subclass::*)() const>, bool (test::class_subclass::*)() const>::value);
    static_assert(bsl::is_same<bsl::common_type_t<bool (test::class_subclass::*)() const, bool (test::class_base::*)() const>, bool (test::class_subclass::*)() const>::value);

    static_assert(bsl::is_same<bsl::common_type_t<void(), void()>, void (*)()>::value);
    static_assert(bsl::is_same<bsl::common_type_t<void (&)(), void (&)()>, void (*)()>::value);
    static_assert(bsl::is_same<bsl::common_type_t<void (&)(), void(&&)()>, void (*)()>::value);
    static_assert(bsl::is_same<bsl::common_type_t<void(&&)(), void (&)()>, void (*)()>::value);
    static_assert(bsl::is_same<bsl::common_type_t<void(&&)(), void(&&)()>, void (*)()>::value);

    static_assert(bsl::is_same<bsl::common_type_t<decltype(nullptr), void *>, void *>::value);
    static_assert(bsl::is_same<bsl::common_type_t<decltype(nullptr), bool *>, bool *>::value);

    return bsl::ut_success();
}
