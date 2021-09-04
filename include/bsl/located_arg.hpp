/// @copyright
/// Copyright (C) 2019 Assured Information Security, Inc.
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

#ifndef BSL_LOCATED_ARG_HPP
#define BSL_LOCATED_ARG_HPP

#include "bsl/enable_if.hpp"
#include "bsl/is_same.hpp"
#include "bsl/source_location.hpp"    // IWYU pragma: export

namespace bsl
{
    /// @class located_arg
    ///
    /// <!-- description -->
    ///   @brief Implicitly captures a reference to any argument it is
    ///     provided along with the location of that argument. All credit
    ///     goes to the following for this mad yet brilliant idea:
    ///     https://www.reddit.com/r/cpp/comments/pbzol3/source_location_with_operator_overloads/
    ///
    /// <!-- template parameters -->
    ///   @tparam T the type of argument to capture
    ///
    template<typename T>
    class located_arg final
    {
        /// @brief stores a reference to the implicit argument being captured
        T const &m_val;
        /// @brief stores the location of the implicit argument being captured
        source_location m_sloc;

    public:
        /// <!-- description -->
        ///   @brief Default value constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam U Used to ensure the provided integer is the same as
        ///     T, effectively preventing implicit conversions from being
        ///     allowed.
        ///   @param val the value being captured.
        ///   @param loc the location of the call site
        ///
        template<typename U, enable_if_t<is_same<T, U>::value, bool> = true>
        // NOLINTNEXTLINE(hicpp-explicit-conversions)
        constexpr located_arg(U const &val, source_location const &loc = here()) noexcept    // --
            : m_val{val}, m_sloc{loc}
        {}

        /// <!-- description -->
        ///   @brief Destroyes a previously created bsl::located_arg
        ///
        constexpr ~located_arg() noexcept = default;

        /// <!-- description -->
        ///   @brief copy constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///
        constexpr located_arg(located_arg const &o) noexcept = default;

        /// <!-- description -->
        ///   @brief move constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_o the object being moved
        ///
        constexpr located_arg(located_arg &&mut_o) noexcept = default;

        /// <!-- description -->
        ///   @brief copy assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr auto operator=(located_arg const &o) &noexcept
            -> located_arg & = default;

        /// <!-- description -->
        ///   @brief move assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_o the object being moved
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr auto operator=(located_arg &&mut_o) &noexcept
            -> located_arg & = default;

        /// <!-- description -->
        ///   @brief Returns a reference to the captured argument.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a reference to the captured argument.
        ///
        [[nodiscard]] constexpr auto
        get() const noexcept -> T const &
        {
            return m_val;
        }

        /// <!-- description -->
        ///   @brief Returns the location of the captured argument.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the location of the captured argument.
        ///
        [[nodiscard]] constexpr auto
        sloc() const noexcept -> source_location const &
        {
            return m_sloc;
        }
    };
}

#endif
