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

#include "../class_base.hpp"
#include "../class_pod.hpp"
#include "../class_subclass.hpp"

#include <bsl/is_nothrow_invocable_r.hpp>
#include <bsl/reference_wrapper.hpp>
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

    // (1.1) If std::is_base_of<T, std::decay_t<decltype(t1)>>::value
    //       is true, then INVOKE(f, t1, t2, ..., tN) is equivalent to
    //       (t1.*f)(t2, ..., tN)
    static_assert(!bsl::is_nothrow_invocable_r<bool(), bool (test::class_base::*)(), test::class_base>::value);
    static_assert(!bsl::is_nothrow_invocable_r<bool(), bool (test::class_base::*)(), test::class_subclass>::value);
    static_assert(bsl::is_nothrow_invocable_r<bool(), bool (test::class_subclass::*)() noexcept, test::class_subclass>::value);

    // (1.2) If std::decay_t<decltype(t1)> is a specialization of
    //       std::reference_wrapper, then INVOKE(f, t1, t2, ..., tN) is
    //       equivalent to (t1.get().*f)(t2, ..., tN)
    static_assert(!bsl::is_nothrow_invocable_r<bool(), bool (test::class_base::*)(), bsl::reference_wrapper<test::class_base>>::value);
    static_assert(!bsl::is_nothrow_invocable_r<bool(), bool (test::class_base::*)(), bsl::reference_wrapper<test::class_subclass>>::value);
    static_assert(bsl::is_nothrow_invocable_r<bool(), bool (test::class_subclass::*)() noexcept, bsl::reference_wrapper<test::class_subclass>>::value);

    // (1.3) If t1 does not satisfy the previous items, then
    //       INVOKE(f, t1, t2, ..., tN) is equivalent to
    //       ((*t1).*f)(t2, ..., tN)
    static_assert(!bsl::is_nothrow_invocable_r<bool(), bool (test::class_base::*)(), test::class_base *>::value);
    static_assert(!bsl::is_nothrow_invocable_r<bool(), bool (test::class_base::*)(), test::class_subclass *>::value);
    static_assert(bsl::is_nothrow_invocable_r<bool(), bool (test::class_subclass::*)() noexcept, test::class_subclass *>::value);

    // (2.1) If std::is_base_of<T, std::decay_t<decltype(t1)>>::value is true,
    //       then INVOKE(f, t1) is equivalent to t1.*f
    static_assert(bsl::is_nothrow_invocable_r<bool &&, decltype(&test::class_pod::val1), test::class_pod>::value);

    // (2.2) If std::decay_t<decltype(t1)> is a specialization of
    //       std::reference_wrapper, then INVOKE(f, t1) is
    //       equivalent to t1.get().*f
    static_assert(bsl::is_nothrow_invocable_r<bool &, decltype(&test::class_pod::val1), bsl::reference_wrapper<test::class_pod>>::value);

    // (2.3) If t1 does not satisfy the previous items, then INVOKE(f, t1)
    //       is equivalent to (*t1).*f
    static_assert(bsl::is_nothrow_invocable_r<bool &, decltype(&test::class_pod::val1), test::class_pod *>::value);

    // (3.1) Otherwise, INVOKE(f, t1, t2, ..., tN) is equivalent to
    //       f(t1, t2, ..., tN)
    static_assert(!bsl::is_nothrow_invocable_r<bool (), bool ()>::value);
    static_assert(bsl::is_nothrow_invocable_r<bool (), bool () noexcept>::value);

    return bsl::ut_success();
}
