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

#include "cstdint.hpp"
#include "safe_integral.hpp"

namespace bsl
{
    /// @class bsl::basic_errc_type
    ///
    /// <!-- description -->
    ///   @brief Defines an error code. We do not use the same pattern as the
    ///     standard library. The goal is to ensure an error code can consume
    ///     a single register to ensure maximum compatibility with different
    ///     CPU archiectures that only have a 32bit return register. We also do
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
        constexpr basic_errc_type() noexcept    // --
            : m_errc{}
        {}

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
        ///   @brief Value initialization constructor
        ///   @include basic_errc_type/example_basic_errc_type_constructor_t_safe_int.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param val the error code to store
        ///
        explicit constexpr basic_errc_type(safe_integral<value_type> const &val) noexcept    // --
            : basic_errc_type{val.get()}
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
        ///   @param o the object being moved
        ///
        constexpr basic_errc_type(basic_errc_type &&o) noexcept = default;

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
        ///   @param o the object being moved
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr auto operator=(basic_errc_type &&o) &noexcept
            -> basic_errc_type & = default;

        /// <!-- description -->
        ///   @brief Returns the integer value that represents the error code.
        ///     Normally, this function should not be used, and instead, you
        ///     should use the other functions like ==, !=, operator bool(),
        ///     is_checked() and is_unchecked().
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
        [[nodiscard]] constexpr explicit operator bool() const noexcept
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
            return m_errc == T{};
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
            return m_errc != T{};
        }

        /// <!-- description -->
        ///   @brief Returns true if the error code is a checked error (i.e.,
        ///     that is the error code is negative), false otherwise. If this
        ///     error code is bsl::errc_success, returns false.
        ///   @include basic_errc_type/example_basic_errc_type_is_checked.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if the error code is a checked error (i.e.,
        ///     that is the error code is negative), false otherwise. If this
        ///     error code is bsl::errc_success, returns false.
        ///
        [[nodiscard]] constexpr auto
        is_checked() const noexcept -> bool
        {
            return m_errc < T{};
        }

        /// <!-- description -->
        ///   @brief Returns true if the error code is an unchecked error
        ///     (i.e., that is the error code is positive), false otherwise.
        ///     If this error code is bsl::errc_success, returns false.
        ///   @include basic_errc_type/example_basic_errc_type_is_unchecked.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if the error code is an unchecked error
        ///     (i.e., that is the error code is positive), false otherwise.
        ///     If this error code is bsl::errc_success, returns false.
        ///
        [[nodiscard]] constexpr auto
        is_unchecked() const noexcept -> bool
        {
            return m_errc > T{};
        }

    private:
        /// @brief stores the error code
        T m_errc;
    };

    /// <!-- description -->
    ///   @brief Returns true if the lhs is equal to the rhs, false otherwise
    ///   @include basic_errc_type/example_basic_errc_type_equals.hpp
    ///   @related bsl::basic_errc_type
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type to use to store the error code.
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns true if the lhs is equal to the rhs, false otherwise
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    operator==(basic_errc_type<T> const &lhs, basic_errc_type<T> const &rhs) noexcept -> bool
    {
        return lhs.get() == rhs.get();
    }

    /// <!-- description -->
    ///   @brief Returns false if the lhs is equal to the rhs, true otherwise
    ///   @include basic_errc_type/example_basic_errc_type_not_equals.hpp
    ///   @related bsl::basic_errc_type
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type to use to store the error code.
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns false if the lhs is equal to the rhs, true otherwise
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    operator!=(basic_errc_type<T> const &lhs, basic_errc_type<T> const &rhs) noexcept -> bool
    {
        return !(lhs == rhs);
    }
}

// -----------------------------------------------------------------------------
// Pre-defined Error Codes
// -----------------------------------------------------------------------------

namespace bsl
{
    /// @brief Defines the "no error" case
    // We want our implementation to mimic C++ here.
    // NOLINTNEXTLINE(bsl-name-case)
    constexpr basic_errc_type<> errc_success{0};
    /// @brief Defines the general unchecked error case
    // We want our implementation to mimic C++ here.
    // NOLINTNEXTLINE(bsl-name-case)
    constexpr basic_errc_type<> errc_failure{1};
    /// @brief Defines the general precondition error case
    // We want our implementation to mimic C++ here.
    // NOLINTNEXTLINE(bsl-name-case)
    constexpr basic_errc_type<> errc_precondition{2};
    /// @brief Defines the general postcondition error case
    // We want our implementation to mimic C++ here.
    // NOLINTNEXTLINE(bsl-name-case)
    constexpr basic_errc_type<> errc_postcondition{3};
    /// @brief Defines the general assertion error case
    // We want our implementation to mimic C++ here.
    // NOLINTNEXTLINE(bsl-name-case)
    constexpr basic_errc_type<> errc_assetion{4};

    /// @brief Defines an invalid argument error code
    // We want our implementation to mimic C++ here.
    // NOLINTNEXTLINE(bsl-name-case)
    constexpr basic_errc_type<> errc_invalid_argument{10};
    /// @brief Defines an out of bounds error code
    // We want our implementation to mimic C++ here.
    // NOLINTNEXTLINE(bsl-name-case)
    constexpr basic_errc_type<> errc_index_out_of_bounds{11};

    /// @brief Defines an unsigned wrap error
    // We want our implementation to mimic C++ here.
    // NOLINTNEXTLINE(bsl-name-case)
    constexpr basic_errc_type<> errc_unsigned_wrap{30};
    /// @brief Defines a narrow overflow error
    // We want our implementation to mimic C++ here.
    // NOLINTNEXTLINE(bsl-name-case)
    constexpr basic_errc_type<> errc_narrow_overflow{31};
    /// @brief Defines a signed overflow error
    // We want our implementation to mimic C++ here.
    // NOLINTNEXTLINE(bsl-name-case)
    constexpr basic_errc_type<> errc_signed_overflow{32};
    /// @brief Defines a divide by zero error
    // We want our implementation to mimic C++ here.
    // NOLINTNEXTLINE(bsl-name-case)
    constexpr basic_errc_type<> errc_divide_by_zero{33};
    /// @brief Defines an out of bounds error code
    // We want our implementation to mimic C++ here.
    // NOLINTNEXTLINE(bsl-name-case)
    constexpr basic_errc_type<> errc_nullptr_dereference{34};
    /// @brief Defines when a resource is busy
    // We want our implementation to mimic C++ here.
    // NOLINTNEXTLINE(bsl-name-case)
    constexpr basic_errc_type<> errc_busy{50};
    /// @brief Defines when a resource already_exists
    // We want our implementation to mimic C++ here.
    // NOLINTNEXTLINE(bsl-name-case)
    constexpr basic_errc_type<> errc_already_exists{51};
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

namespace bsl
{
    /// <!-- description -->
    ///   @brief Returns true if the provided error code is equal to
    ///     bsl::errc_success or bsl::errc_precondition. Returns false
    ///     otherwise.
    ///
    /// <!-- inputs/outputs -->
    ///   @param ec the error code to query
    ///   @return Returns true if the provided error code is equal to
    ///     bsl::errc_success or bsl::errc_precondition. Returns false
    ///     otherwise.
    ///
    [[nodiscard]] constexpr auto
    success_or_precondition(basic_errc_type<> const ec) noexcept -> bool
    {
        if (bsl::errc_success == ec) {
            return true;
        }

        if (bsl::errc_precondition == ec) {
            return true;
        }

        return false;
    }
}

#endif
