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
/// @file basic_errc_type.hpp
///

#ifndef BSL_BASIC_ERRC_TYPE_HPP
#define BSL_BASIC_ERRC_TYPE_HPP

#include "bsl/cstdint.hpp"

namespace bsl
{
    /// @class bsl::basic_errc_type
    ///
    /// <!-- description -->
    ///   @brief Defines an error code. We do not use the same pattern as the
    ///     standard library. The goal is to ensure an error code can consume
    ///     a single register to ensure maximum compatibility with different
    ///     CPU architectures that only have a 32bit return register. We also do
    ///     not use an enum to ensure custom error codes can be created. This
    ///     also means there are no error code categories. Instead, an error
    ///     code is checked if it is negative, and unchecked if it is positive
    ///     to align with AUTOSAR. Finally, we provide the ability to change
    ///     the type that an error code uses under the hood which allows you
    ///     to use a "long" type, or some other integer type depending on your
    ///     requirements (i.e., NTSTATUS).
    ///   @include example_basic_errc_type_overview.hpp
    ///
    /// <!-- template parameters -->
    ///   @tparam T the type to use to store the error code. Defaults to
    ///     a bsl::int32.
    ///
    template<typename T = bsl::int32>
    class basic_errc_type final
    {
    public:
        /// @brief alias for: T
        using value_type = T;
        /// @brief alias for: T &
        using reference_type = T &;
        /// @brief alias for: T const &
        using const_reference_type = T const &;

        /// <!-- description -->
        ///   @brief Default constructor.
        ///   @include basic_errc_type/example_basic_errc_type_default_constructor.hpp
        ///
        constexpr basic_errc_type() noexcept = default;

        /// <!-- description -->
        ///   @brief Value initialization constructor
        ///   @include basic_errc_type/example_basic_errc_type_constructor_t.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param val the error code to store
        ///
        explicit constexpr basic_errc_type(value_type const &val) noexcept    // --
            : m_errc{val}
        {}

        /// <!-- description -->
        ///   @brief Destroyes a previously created bsl::basic_errc_type
        ///
        constexpr ~basic_errc_type() noexcept = default;

        /// <!-- description -->
        ///   @brief copy constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///
        constexpr basic_errc_type(basic_errc_type const &o) noexcept = default;

        /// <!-- description -->
        ///   @brief move constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_o the object being moved
        ///
        constexpr basic_errc_type(basic_errc_type &&mut_o) noexcept = default;

        /// <!-- description -->
        ///   @brief copy assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr auto operator=(basic_errc_type const &o) &noexcept
            -> basic_errc_type & = default;

        /// <!-- description -->
        ///   @brief move assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_o the object being moved
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr auto operator=(basic_errc_type &&mut_o) &noexcept
            -> basic_errc_type & = default;

        /// <!-- description -->
        ///   @brief Returns the integer value that represents the error code.
        ///   @include basic_errc_type/example_basic_errc_type_get.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the integer value that represents the error code.
        ///
        [[nodiscard]] constexpr auto
        get() const &noexcept -> const_reference_type
        {
            return m_errc;
        }

        /// <!-- description -->
        ///   @brief Returns success()
        ///   @include basic_errc_type/example_basic_errc_type_operator_bool.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns success()
        ///
        [[nodiscard]] explicit constexpr operator bool() const noexcept
        {
            return this->success();
        }

        /// <!-- description -->
        ///   @brief Returns true if the error code contains T{},
        ///     otherwise, if the error code contains an error code,
        ///     returns false.
        ///   @include basic_errc_type/example_basic_errc_type_success.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if the error code contains T{},
        ///     otherwise, if the error code contains an error code,
        ///     returns false.
        ///
        [[nodiscard]] constexpr auto
        success() const noexcept -> bool
        {
            return T{} <= m_errc;
        }

        /// <!-- description -->
        ///   @brief Returns true if the error code contains an error code,
        ///     otherwise, if the error code contains T{},
        ///     returns false.
        ///   @include basic_errc_type/example_basic_errc_type_failure.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if the error code contains an error code,
        ///     otherwise, if the error code contains T{},
        ///     returns false.
        ///
        [[nodiscard]] constexpr auto
        failure() const noexcept -> bool
        {
            return T{} > m_errc;
        }

    private:
        /// @brief stores the error code
        T m_errc;
    };

    /// <!-- description -->
    ///   @brief Returns lhs.get() == rhs.get()
    ///   @include basic_errc_type/example_basic_errc_type_equals.hpp
    ///   @related bsl::basic_errc_type
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type to use to store the error code.
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns lhs.get() == rhs.get()
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    operator==(basic_errc_type<T> const &lhs, basic_errc_type<T> const &rhs) noexcept -> bool
    {
        return lhs.get() == rhs.get();
    }

    /// <!-- description -->
    ///   @brief Returns !(lhs == rhs).
    ///   @include basic_errc_type/example_basic_errc_type_not_equals.hpp
    ///   @related bsl::basic_errc_type
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type to use to store the error code.
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns !(lhs == rhs).
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    operator!=(basic_errc_type<T> const &lhs, basic_errc_type<T> const &rhs) noexcept -> bool
    {
        return !(lhs == rhs);
    }
}

#endif
