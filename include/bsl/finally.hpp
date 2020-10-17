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
/// @file finally.hpp
///

#ifndef BSL_FINALLY_HPP
#define BSL_FINALLY_HPP

#include "is_nothrow_invocable.hpp"
#include "move.hpp"
#include "touch.hpp"

namespace bsl
{
    /// @class bsl::finally
    ///
    /// <!-- description -->
    ///   @brief Executes a provided function on destruction. This class is
    ///     useful for providing general cleanup code that is common with
    ///     each step of a process. It should be noted that this should never
    ///     be used global, and instead is only intended to be used from the
    ///     scope of a function.
    ///   @include example_finally_overview.hpp
    ///
    /// <!-- template parameters -->
    ///   @tparam FUNC the type of function to call
    ///
    template<typename FUNC>
    class finally final
    {
        static_assert(is_nothrow_invocable<FUNC>::value);

        /// @brief stores the function invoke on destruction
        FUNC m_func;
        /// @brief stores whether or not the function was invoked
        bool m_invoked;

    public:
        /// <!-- description -->
        ///   @brief Creates a bsl::finally given the function to call
        ///     on destruction.
        ///   @include example_finally_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param func the function to call on destruction
        ///
        explicit constexpr finally(FUNC &&func) noexcept    // --
            : m_func{bsl::move(func)}, m_invoked{}
        {}

        /// <!-- description -->
        ///   @brief Destroyes a previously created bsl::finally, calling
        ///     the provided function if ignore() was never called
        ///
        constexpr ~finally() noexcept
        {
            if (!m_invoked) {
                m_func();
            }
            else {
                bsl::touch();
            }
        }

        /// <!-- description -->
        ///   @brief copy constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///
        constexpr finally(finally const &o) noexcept = delete;

        /// <!-- description -->
        ///   @brief move constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being moved
        ///
        constexpr finally(finally &&o) noexcept = delete;

        /// <!-- description -->
        ///   @brief copy assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr auto operator=(finally const &o) &noexcept -> finally & = delete;

        /// <!-- description -->
        ///   @brief move assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being moved
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr auto operator=(finally &&o) &noexcept -> finally & = delete;

        /// <!-- description -->
        ///   @brief Set the invoked status to true, preventing the provided
        ///     function from being called on destruction.
        ///   @include example_finally_overview.hpp
        ///
        constexpr void
        ignore() noexcept
        {
            m_invoked = true;
        }
    };
}

#endif
