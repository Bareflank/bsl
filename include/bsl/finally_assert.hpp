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
/// @file finally_assert.hpp
///

#ifndef BSL_FINALLY_ASSERT_HPP
#define BSL_FINALLY_ASSERT_HPP

#include "discard.hpp"
#include "dormant_t.hpp"
#include "is_nothrow_invocable.hpp"
#include "move.hpp"
#include "touch.hpp"

namespace bsl
{
    /// @class bsl::finally_assert
    ///
    /// <!-- description -->
    ///   @brief Executes a provided function on destruction. This class is
    ///     useful for providing general cleanup code that is common with
    ///     each step of a process. It should be noted that this should never
    ///     be used global, and instead is only intended to be used from the
    ///     scope of a function.
    ///   @include example_finally_assert_overview.hpp
    ///
    /// <!-- template parameters -->
    ///   @tparam FUNC_T the type of function to call
    ///
    template<typename FUNC_T>
    class finally_assert final
    {
        static_assert(is_nothrow_invocable<FUNC_T>::value);

        /// @brief stores the function invoke on destruction
        FUNC_T m_func;
        /// @brief stores whether or not the function was invoked
        bool m_invoked;

    public:
        /// <!-- description -->
        ///   @brief Creates a bsl::finally_assert given the function to call
        ///     on destruction.
        ///   @include example_finally_assert_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_func the function to call on destruction
        ///
        explicit constexpr finally_assert(FUNC_T &&mut_func) noexcept    // --
            : m_func{bsl::move(mut_func)}, m_invoked{}
        {}

        /// <!-- description -->
        ///   @brief Creates a bsl::finally_assert given the function to call
        ///     on destruction only if activated.
        ///   @include example_finally_assert_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param d ignored
        ///   @param mut_func the function to call on destruction
        ///
        explicit constexpr finally_assert(
            bsl::dormant_t const &d, FUNC_T &&mut_func) noexcept    // --
            : m_func{bsl::move(mut_func)}, m_invoked{true}
        {
            bsl::discard(d);
        }

        /// <!-- description -->
        ///   @brief Destroyes a previously created bsl::finally_assert, calling
        ///     the provided function if ignore() was never called
        ///
        constexpr ~finally_assert() noexcept
        {
            if constexpr (!BSL_RELEASE_MODE) {
                if (!m_invoked) {
                    m_func();
                }
                else {
                    bsl::touch();
                }
            }
        }

        /// <!-- description -->
        ///   @brief copy constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///
        constexpr finally_assert(finally_assert const &o) noexcept = delete;

        /// <!-- description -->
        ///   @brief move constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_o the object being moved
        ///
        constexpr finally_assert(finally_assert &&mut_o) noexcept = delete;

        /// <!-- description -->
        ///   @brief copy assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr auto operator=(finally_assert const &o) &noexcept
            -> finally_assert & = delete;

        /// <!-- description -->
        ///   @brief move assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_o the object being moved
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr auto operator=(finally_assert &&mut_o) &noexcept
            -> finally_assert & = delete;

        /// <!-- description -->
        ///   @brief Set the invoked status to true, preventing the provided
        ///     function from being called on destruction.
        ///   @include example_finally_assert_overview.hpp
        ///
        constexpr void
        ignore() noexcept
        {
            if constexpr (!BSL_RELEASE_MODE) {
                m_invoked = true;
            }
        }

        /// <!-- description -->
        ///   @brief Set the invoked status to false, causing the provided
        ///     function to be called on destruction.
        ///   @include example_finally_assert_overview.hpp
        ///
        constexpr void
        activate() noexcept
        {
            if constexpr (!BSL_RELEASE_MODE) {
                m_invoked = false;
            }
        }
    };
}

#endif
