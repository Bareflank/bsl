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

#include <bsl/is_empty.hpp>
#include <bsl/ut.hpp>

#include <bsl/cstddef.hpp>
#include <bsl/cstdint.hpp>
#include <bsl/reference_wrapper.hpp>

#include "../class_abstract.hpp"
#include "../class_base.hpp"
#include "../class_deleted.hpp"
#include "../class_empty.hpp"
#include "../class_except.hpp"
#include "../class_nodefault.hpp"
#include "../class_pod.hpp"
#include "../class_subclass.hpp"
#include "../enum_empty.hpp"
#include "../struct_empty.hpp"
#include "../union_empty.hpp"

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
    static_assert(!bsl::is_empty<bsl::nullptr_t>::value);
    static_assert(!bsl::is_empty<void>::value);
    static_assert(!bsl::is_empty<bool>::value);
    static_assert(!bsl::is_empty<bool const>::value);
    static_assert(!bsl::is_empty<bsl::int32>::value);
    static_assert(!bsl::is_empty<bsl::uint32>::value);
    static_assert(!bsl::is_empty<bool &>::value);
    static_assert(!bsl::is_empty<bool const &>::value);
    static_assert(!bsl::is_empty<bool &&>::value);
    static_assert(!bsl::is_empty<bool *>::value);
    static_assert(!bsl::is_empty<bool *const>::value);
    static_assert(!bsl::is_empty<bool const *>::value);
    static_assert(!bsl::is_empty<bool const *const>::value);
    static_assert(!bsl::is_empty<bool(bool)>::value);
    static_assert(!bsl::is_empty<bool (*)(bool)>::value);
    static_assert(!bsl::is_empty<bool test::class_base::*>::value);
    static_assert(!bsl::is_empty<bool (test::class_base::*)()>::value);
    static_assert(!bsl::is_empty<bsl::reference_wrapper<bool>>::value);

    static_assert(!bsl::is_empty<test::class_abstract>::value);
    static_assert(!bsl::is_empty<test::class_base>::value);
    static_assert(bsl::is_empty<test::class_deleted>::value);
    static_assert(bsl::is_empty<test::class_empty>::value);
    static_assert(bsl::is_empty<test::class_except>::value);
    static_assert(bsl::is_empty<test::class_nodefault>::value);
    static_assert(!bsl::is_empty<test::class_pod>::value);
    static_assert(!bsl::is_empty<test::class_subclass>::value);
    static_assert(!bsl::is_empty<test::enum_empty>::value);
    static_assert(bsl::is_empty<test::struct_empty>::value);
    static_assert(!bsl::is_empty<test::union_empty>::value);

    // NOLINTNEXTLINE(cppcoreguidelines-avoid-c-arrays, hicpp-avoid-c-arrays, modernize-avoid-c-arrays)
    static_assert(!bsl::is_empty<bool[]>::value);
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-c-arrays, hicpp-avoid-c-arrays, modernize-avoid-c-arrays)
    static_assert(!bsl::is_empty<bool[1]>::value);

    return bsl::ut_success();
}
