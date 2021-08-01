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
///
/// @file ensures.hpp
///

#ifndef BSL_ENSURES_HPP
#define BSL_ENSURES_HPP

#include "errc_type.hpp"
#include "source_location.hpp"
#include "touch.hpp"
#include "unlikely.hpp"

#include <bsl/assert.hpp>

namespace bsl
{
    /// <!-- description -->
    ///   @brief Used to tell the user during compile-time that a
    ///     contact violation has occurred.
    ///
    inline void
    ensures_contract_violation() noexcept
    {}

    /// <!-- description -->
    ///   @brief If test is false, a contract violation has occurred. This
    ///     should be used to assert postconditions that if not meet, would
    ///     result in undefined behavior. These should not be tested by a
    ///     unit test, meaning they are contract violations. These asserts
    ///     are simply there as a sanity check during a debug build.
    ///   @include example_ensures_overview.hpp
    ///
    /// <!-- inputs/outputs -->
    ///   @param test the contract to check
    ///   @param sloc the location that ensures was called.
    ///
    constexpr void
    ensures(bool const test, source_location const &sloc = here()) noexcept
    {
        if constexpr (BSL_RELEASE_MODE) {
            return;
        }

        if (unlikely(!test)) {
            ensures_contract_violation();
            assert("ensures contract violation", sloc);
        }
        else {
            bsl::touch();
        }
    }

    /// <!-- description -->
    ///   @brief If test is a failure, a contract violation has occurred. This
    ///     should be used to assert postconditions that if not meet, would
    ///     result in undefined behavior. These should not be tested by a
    ///     unit test, meaning they are contract violations. These asserts
    ///     are simply there as a sanity check during a debug build.
    ///   @include example_ensures_overview.hpp
    ///
    /// <!-- inputs/outputs -->
    ///   @param test the contract to check
    ///   @param sloc the location that ensures was called.
    ///
    constexpr void
    ensures(errc_type const test, source_location const &sloc = here()) noexcept
    {
        if constexpr (BSL_RELEASE_MODE) {
            return;
        }

        if (unlikely(!test)) {
            ensures_contract_violation();
            assert("ensures contract violation", sloc);
        }
        else {
            bsl::touch();
        }
    }
}

#endif
