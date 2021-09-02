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

#ifndef BSL_ASSERT_HPP
#define BSL_ASSERT_HPP

#include "bsl/cstr_type.hpp"
#include "bsl/details/out_char.hpp"
#include "bsl/details/out_cstr.hpp"
#include "bsl/details/out_line.hpp"
#include "bsl/discard.hpp"
#include "bsl/source_location.hpp"

#include <bsl/cstdlib.hpp>

#pragma clang diagnostic ignored "-Wmissing-noreturn"

/// NOTE:
/// - The use of assert, expects and ensures defines the difference between
///   a narrow contract and a wide contract.
///   - narrow contract: a narrow contract states that inputs to a function can
///     ONLY be a specific set of valid inputs. Any other inputs lead to
///     undefined behavior (and therefore corruption).
///   - wide contract: a wide contract states that most if not all inputs to
///     a function will be handled. In a lot of cases, these would lead to
///     an error being returned, or the fuction might take an alternative
///     approach when invalid inputs are provided.
///
/// - Most public functions, APIs, ABIs, ext. should use wide contracts.
///   Imagine if you could syscall a kernel with input that would lead to
///   UB for example. Most private functions should use narrow contracts.
///   Imagine having to do something with an ID as input to a function that
///   is 5 functions deep in a set of nested calls that is called in a loop
///   in the critical path of an operation. All 5 functions would have to
///   check the validity of the ID if all 5 functions needed to use this ID
///   for something, and this would happen on every iteration. This overuse
///   of a wide contract would also mean that every function also needs to
///   handle the error case including cleanup which leads to a massive amount
///   of code that must be unit tested and verified. The issue is the first
///   function will have verified that the ID is valid, and so the rest of
///   the code that must be added and unit tested, and capable of handling
///   cleanup will NEVER be executed. In otherwords, wide contracts in
///   private functions lead to a massive amounts of useless code.
///
/// - AUTOSAR doesn't really talk about contracts. It simply talks about the
///   difference between checked and unchecked exceptions and how fast failing
///   is not allowed. We don't use exceptions, so none of the exceptions specifc
///   language applies. Fast failing, is, however the question at hand. AUTOSAR
///   doesn't talk about the use of assert(), which is what we really
///   care about here. All of the examples are release mode style error logic
///   meaning the code examples are always present. AUTOSAR and MISRA both
///   base their fast failing rules on the following:
///   SEI CERT rule:
///   https://wiki.sei.cmu.edu/confluence/display/cplusplus/ERR50-CPP.+Do+not+abruptly+terminate+the+program
///
///   The above rule DOES address assert(), stating that it is allowed by
///   exception (feel free to read more above to better understand why).
///   Based on the fact that assert(), or debug mode based fast failing is
///   not defined in AUTOSAR, and the only examples include code that would
///   exist in a release mode build that would call std::terminate() in a
///   deployed version of software, we can safely assume that so long as a
///   release builds do not contain fast failing, there are no issues.
///
/// - What this this means is that assert(), expects() and ensures() should
///   all be used to define narrow contracts. Code should either implement a
///   wide contract, and handle all inputs, or it should define narrow
///   contracts using assert(), expects() and ensures(). These narrow contracts
///   will be validated at runtime in debug releases to ensure the narrow
///   contract is never violated and will fast fail if a violation occurs.
///   In release mode, these fast fails are all removed, and thus, AUTOSAR
///   rules are not violated. Future versions of the BSL could also add the
///   ability (like the GSL) to throw instead of fast fail in cases where
///   exceptions are possible.
///

namespace bsl
{
#if BSL_RELEASE_MODE
    constexpr void
#else
#if BSL_ASSERT_FAST_FAILS
    [[noreturn]] constexpr void
#else
    constexpr void
#endif
#endif
    /// <!-- description -->
    ///   @brief Outputs a raw error string to stderr if debugging is
    ///     turned on, along with the location of the assert. If
    ///     BSL_ASSERT_FAST_FAILS is enabled, the assert will fast fail.
    ///     In release mode, this function does nothing.
    ///   @include example_assert_overview.hpp
    ///
    /// <!-- inputs/outputs -->
    ///   @param str a string to output to stderr
    ///   @param sloc the location of the assert
    ///
    assert(cstr_type const str, source_location const &sloc) noexcept
    {
        if constexpr (BSL_RELEASE_MODE) {
            bsl::discard(str);
            bsl::discard(sloc);
        }
        else {
            if constexpr (ENABLE_COLOR) {
                details::out_cstr("\033[1;91m");
            }

            details::out_cstr("ASSERT: ");

            if constexpr (ENABLE_COLOR) {
                details::out_cstr("\033[0m");
            }

            details::out_cstr(str);
            details::out_cstr("\n  --> ");

            if constexpr (ENABLE_COLOR) {
                details::out_cstr("\033[0;93m");
            }

            details::out_cstr(sloc.file_name());

            if constexpr (ENABLE_COLOR) {
                details::out_cstr("\033[0;96m");
            }

            details::out_cstr(" [");
            details::out_line(sloc.line());
            details::out_char(']');

            if constexpr (ENABLE_COLOR) {
                details::out_cstr("\033[0m");
            }

            details::out_cstr(": ");
            details::out_cstr(sloc.function_name());
            details::out_cstr("\n\n");

            if constexpr (BSL_ASSERT_FAST_FAILS) {
                stdlib_fast_fail();    // GRCOV_EXCLUDE
            }
        }
    }
}

#endif
