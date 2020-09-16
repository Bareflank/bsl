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
/// @file ut_given_at_runtime.hpp
///

#ifndef BSL_UT_GIVEN_AT_RUNTIME_HPP
#define BSL_UT_GIVEN_AT_RUNTIME_HPP

#include "is_constant_evaluated.hpp"
#include "touch.hpp"

namespace bsl
{
    /// @class bsl::ut_given_at_runtime
    ///
    /// <!-- description -->
    ///   @brief Defines the initial state of a unit test scenario including
    ///     the creation of any objects that might participate in the
    ///     unit test. Note that this version will only execute at run-time.
    ///
    class ut_given_at_runtime final
    {
    public:
        /// <!-- description -->
        ///   @brief Default constructor
        ///
        constexpr ut_given_at_runtime() noexcept = default;

        /// <!-- description -->
        ///   @brief Executes a lambda function as the body of the
        ///     "given" portion of the scenario.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam FUNC_T the type of lambda being executed
        ///   @param func the lambda being executed
        ///   @return Returns a reference to the ut_given_at_runtime.
        ///
        template<typename FUNC_T>
        [[maybe_unused]] constexpr auto
        operator=(FUNC_T &&func) &&noexcept -> ut_given_at_runtime &
        {
            if (!is_constant_evaluated()) {
                func();
            }
            else {
                bsl::touch();
            }

            return *this;
        }

        /// @brief the l-value version of this function is not supported
        template<typename FUNC_T>
        [[maybe_unused]] constexpr auto operator=(FUNC_T &&func) const &noexcept
            -> ut_given_at_runtime & = delete;

        /// <!-- description -->
        ///   @brief Destroyes a previously created bsl::ut_given_at_runtime
        ///
        constexpr ~ut_given_at_runtime() noexcept = default;

        /// <!-- description -->
        ///   @brief copy constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///
        constexpr ut_given_at_runtime(ut_given_at_runtime const &o) noexcept = default;

        /// <!-- description -->
        ///   @brief move constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being moved
        ///
        constexpr ut_given_at_runtime(ut_given_at_runtime &&o) noexcept = default;

        /// <!-- description -->
        ///   @brief copy assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr auto operator=(ut_given_at_runtime const &o) &noexcept
            -> ut_given_at_runtime & = default;

        /// <!-- description -->
        ///   @brief move assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being moved
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr auto operator=(ut_given_at_runtime &&o) &noexcept
            -> ut_given_at_runtime & = default;
    };
}

#endif
