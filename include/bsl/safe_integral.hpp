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
///
/// @file safe_integral.hpp
///

#ifndef BSL_SAFE_INTEGRAL_HPP
#define BSL_SAFE_INTEGRAL_HPP

#include "always_false.hpp"
#include "cstdint.hpp"
#include "enable_if.hpp"
#include "is_constant_evaluated.hpp"
#include "is_integral.hpp"
#include "is_same.hpp"
#include "is_signed.hpp"
#include "is_unsigned.hpp"
#include "numeric_limits.hpp"
#include "touch.hpp"
#include "unlikely.hpp"

namespace bsl
{
    /// <!-- description -->
    ///   @brief Used to tell the user during compile-time that an
    ///     error has occurred during an add, sub or mul operation
    ///     from a bsl::safe_integral.
    ///
    inline void
    integral_overflow_underflow_wrap_error() noexcept
    {}

    /// <!-- description -->
    ///   @brief Used to tell the user during compile-time that an
    ///     operation was taking place with a safe integral that
    ///     has it's error bit set.
    ///
    inline void
    illegal_use_of_invalid_safe_integral() noexcept
    {}

    /// <!-- description -->
    ///   @brief Returns __builtin_add_overflow(x, y, res)
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of values to add
    ///   @param lhs the left hand side of the operation
    ///   @param rhs the right hand side of the operation
    ///   @param pmut_cst_res the result of the operation
    ///   @return Returns __builtin_add_overflow(x, y, res)
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    builtin_add_overflow(T const lhs, T const rhs, T *const pmut_cst_res) noexcept -> bool
    {
        // This is how Clang presents the builtins, which we are required
        // top use.
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg, hicpp-vararg)
        if (unlikely(__builtin_add_overflow(lhs, rhs, pmut_cst_res))) {
            integral_overflow_underflow_wrap_error();
            return true;
        }

        return false;
    }

    /// <!-- description -->
    ///   @brief Returns __builtin_sub_overflow(x, y, res)
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of values to subtract
    ///   @param lhs the left hand side of the operation
    ///   @param rhs the right hand side of the operation
    ///   @param pmut_cst_res the result of the operation
    ///   @return Returns __builtin_sub_overflow(x, y, res)
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    builtin_sub_overflow(T const lhs, T const rhs, T *const pmut_cst_res) noexcept -> bool
    {
        // This is how Clang presents the builtins, which we are required
        // top use.
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg, hicpp-vararg)
        if (unlikely(__builtin_sub_overflow(lhs, rhs, pmut_cst_res))) {
            integral_overflow_underflow_wrap_error();
            return true;
        }

        return false;
    }

    /// <!-- description -->
    ///   @brief Returns __builtin_mul_overflow(x, y, res)
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of values to multiply
    ///   @param lhs the left hand side of the operation
    ///   @param rhs the right hand side of the operation
    ///   @param pmut_cst_res the result of the operation
    ///   @return Returns __builtin_mul_overflow(x, y, res)
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    builtin_mul_overflow(T const lhs, T const rhs, T *const pmut_cst_res) noexcept -> bool
    {
        // This is how Clang presents the builtins, which we are required
        // top use.
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg, hicpp-vararg)
        if (unlikely(__builtin_mul_overflow(lhs, rhs, pmut_cst_res))) {
            integral_overflow_underflow_wrap_error();
            return true;
        }

        return false;
    }

    /// <!-- description -->
    ///   @brief If no overflow, underflow, wrap occurs, sets *res to
    ///     lhs / rhs and returns false. Otherwise returns true.
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of values to divide
    ///   @param lhs the left hand side of the operation
    ///   @param rhs the right hand side of the operation
    ///   @param pmut_cst_res the result of the operation
    ///   @return If no overflow, underflow, wrap occurs, sets *res to
    ///     lhs / rhs and returns false. Otherwise returns true
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    builtin_div_overflow(T const lhs, T const rhs, T *const pmut_cst_res) noexcept -> bool
    {
        constexpr bsl::intmax neg_one{static_cast<bsl::intmax>(-1)};

        if (unlikely(static_cast<bsl::uintmax>(T{}) == static_cast<bsl::uintmax>(rhs))) {
            integral_overflow_underflow_wrap_error();
            return true;
        }

        if constexpr (is_signed<T>::value) {
            if (static_cast<bsl::intmax>(numeric_limits<T>::min()) ==
                static_cast<bsl::intmax>(lhs)) {
                if (unlikely(neg_one == static_cast<bsl::intmax>(rhs))) {
                    integral_overflow_underflow_wrap_error();
                    return true;
                }

                bsl::touch();
            }
            else {
                bsl::touch();
            }
        }

        if constexpr (is_signed<T>::value) {
            *pmut_cst_res =
                static_cast<T>(static_cast<bsl::intmax>(lhs) / static_cast<bsl::intmax>(rhs));
        }
        else {
            *pmut_cst_res =
                static_cast<T>(static_cast<bsl::uintmax>(lhs) / static_cast<bsl::uintmax>(rhs));
        }

        return false;
    }

    /// <!-- description -->
    ///   @brief If no overflow, underflow, wrap occurs, sets *res to
    ///     lhs % rhs and returns false. Otherwise returns true.
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of values to mod
    ///   @param lhs the left hand side of the operation
    ///   @param rhs the right hand side of the operation
    ///   @param pmut_cst_res the result of the operation
    ///   @return If no overflow, underflow, wrap occurs, sets *res to
    ///     lhs % rhs and returns false. Otherwise returns true
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    builtin_mod_overflow(T const lhs, T const rhs, T *const pmut_cst_res) noexcept -> bool
    {
        constexpr bsl::intmax neg_one{static_cast<bsl::intmax>(-1)};

        if (unlikely(static_cast<bsl::uintmax>(T{}) == static_cast<bsl::uintmax>(rhs))) {
            integral_overflow_underflow_wrap_error();
            return true;
        }

        if constexpr (is_signed<T>::value) {
            if (static_cast<bsl::intmax>(numeric_limits<T>::min()) ==
                static_cast<bsl::intmax>(lhs)) {
                if (unlikely(neg_one == static_cast<bsl::intmax>(rhs))) {
                    integral_overflow_underflow_wrap_error();
                    return true;
                }

                bsl::touch();
            }
            else {
                bsl::touch();
            }
        }

        if constexpr (is_signed<T>::value) {
            *pmut_cst_res =
                static_cast<T>(static_cast<bsl::intmax>(lhs) % static_cast<bsl::intmax>(rhs));
        }
        else {
            *pmut_cst_res =
                static_cast<T>(static_cast<bsl::uintmax>(lhs) % static_cast<bsl::uintmax>(rhs));
        }

        return false;
    }

    /// @class bsl::safe_integral
    ///
    /// <!-- description -->
    ///   @brief Provides a safe implementation of an integral type that
    ///     adheres to AUTOSAR's requirement that an integral shall not
    ///     overflow, wrap, divide by zero, etc.
    ///   @include example_safe_integral_overview.hpp
    ///
    /// <!-- template parameters -->
    ///   @tparam T the integral type to encapsulate.
    ///
    template<typename T>
    class safe_integral final
    {
        static_assert(bsl::is_integral<T>::value, "only integral types are supported");

        /// @brief stores the value of the integral
        T m_val;
        /// @brief stores whether or not the integral has resulted in an error.
        bool m_error;

    public:
        /// @brief alias for: T
        using value_type = T;
        /// @brief alias for: T &
        using pointer_type = T *;
        /// @brief alias for: T const
        using const_pointer_type = T const *;
        /// @brief alias for: T &
        using reference_type = T &;
        /// @brief alias for: T const
        using const_reference_type = T const &;

        /// <!-- description -->
        ///   @brief Default constructor that creates a safe_integral with
        ///     get() == 0.
        ///   @include safe_integral/example_safe_integral_default_constructor.hpp
        ///
        constexpr safe_integral() noexcept    // --
            : m_val{}, m_error{}
        {}

        /// <!-- description -->
        ///   @brief Creates a bsl::safe_integral given a BSL fixed width
        ///     type.
        ///   @include safe_integral/example_safe_integral_constructor_t.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam U Used to ensure the provided integer is the same as
        ///     T, effectively preventing implicit conversions from being
        ///     allowed.
        ///   @param val the value to set the bsl::safe_integral to
        ///
        template<typename U, enable_if_t<is_same<T, U>::value, bool> = true>
        explicit constexpr safe_integral(U const val) noexcept    // --
            : m_val{val}, m_error{}
        {}

        /// <!-- description -->
        ///   @brief Creates a bsl::safe_integral given a BSL fixed width
        ///     type.
        ///   @include safe_integral/example_safe_integral_constructor_t_error.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param val the value to set the bsl::safe_integral to
        ///   @param err used to create a safe_integer that has already
        ///     resulted in an error.
        ///
        constexpr safe_integral(safe_integral const &val, bool const err) noexcept    // --
            : m_val{val.get()}, m_error{err}
        {}

        /// <!-- description -->
        ///   @brief Creates a bsl::safe_integral given a BSL fixed width
        ///     type.
        ///   @include safe_integral/example_safe_integral_constructor_t_error.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam U Used to ensure the provided integer is the same as
        ///     T, effectively preventing implicit conversions from being
        ///     allowed.
        ///   @param val the value to set the bsl::safe_integral to
        ///   @param err used to create a safe_integer that has already
        ///     resulted in an error.
        ///
        template<typename U, enable_if_t<is_same<T, U>::value, bool> = true>
        constexpr safe_integral(U const val, bool const err) noexcept    // --
            : m_val{val}, m_error{err}
        {}

        /// <!-- description -->
        ///   @brief Destroyes a previously created bsl::safe_integral
        ///
        constexpr ~safe_integral() noexcept = default;

        /// <!-- description -->
        ///   @brief copy constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///
        constexpr safe_integral(safe_integral const &o) noexcept = default;

        /// <!-- description -->
        ///   @brief move constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_o the object being moved
        ///
        constexpr safe_integral(safe_integral &&mut_o) noexcept = default;

        /// <!-- description -->
        ///   @brief copy assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr auto operator=(safe_integral const &o) &noexcept
            -> safe_integral & = default;

        /// <!-- description -->
        ///   @brief move assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_o the object being moved
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr auto operator=(safe_integral &&mut_o) &noexcept
            -> safe_integral & = default;

        /// <!-- description -->
        ///   @brief Creates a bsl::safe_integral given a BSL fixed width
        ///     type. Note that this will clear the integral's error flag,
        ///     starting with a fresh value.
        ///   @include safe_integral/example_safe_integral_assignment_t.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam U Used to ensure the provided integer is the same as
        ///     T, effectively preventing implicit conversions from being
        ///     allowed.
        ///   @param val the value to set the bsl::safe_integral to
        ///   @return Returns *this
        ///
        template<typename U, enable_if_t<is_same<T, U>::value, bool> = true>
        [[maybe_unused]] constexpr auto
        operator=(U const val) &noexcept -> safe_integral<value_type> &
        {
            *this = safe_integral<value_type>{val};
            return *this;
        }

        /// <!-- description -->
        ///   @brief The r-value version of this function is not supported
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam U n/a
        ///   @param val n/a
        ///   @return n/a
        ///
        template<typename U, enable_if_t<is_same<T, U>::value, bool> = true>
        [[maybe_unused]] constexpr auto operator=(U const val) const &&noexcept
            -> safe_integral<value_type> & = delete;

        /// <!-- description -->
        ///   @brief Returns the value stored by the bsl::safe_integral. If an
        ///     error has occurred, this function will always return 0.
        ///   @include safe_integral/example_safe_integral_get.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value stored by the bsl::safe_integral. If an
        ///     error has occurred, this function will always return 0.
        ///
        [[nodiscard]] constexpr auto
        get() const noexcept -> value_type
        {
            if (unlikely(m_error)) {
                illegal_use_of_invalid_safe_integral();
                return static_cast<value_type>(0);
            }

            return m_val;
        }

        /// <!-- description -->
        ///   @brief Returns a pointer to the internal integral being managed
        ///     by this class, providing a means to directly read/write the
        ///     integral's value.
        ///   @include safe_integral/example_safe_integral_get.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a pointer to the internal integral being managed
        ///     by this class, providing a means to directly read/write the
        ///     integral's value.
        ///
        [[nodiscard]] constexpr auto
        data() noexcept -> pointer_type
        {
            if (unlikely(m_error)) {
                illegal_use_of_invalid_safe_integral();
            }
            else {
                bsl::touch();
            }

            return &m_val;
        }

        /// <!-- description -->
        ///   @brief Returns a pointer to the internal integral being managed
        ///     by this class, providing a means to directly read/write the
        ///     integral's value.
        ///   @include safe_integral/example_safe_integral_get.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a pointer to the internal integral being managed
        ///     by this class, providing a means to directly read/write the
        ///     integral's value.
        ///
        [[nodiscard]] constexpr auto
        data() const noexcept -> const_pointer_type
        {
            if (unlikely(m_error)) {
                illegal_use_of_invalid_safe_integral();
            }
            else {
                bsl::touch();
            }

            return &m_val;
        }

        /// <!-- description -->
        ///   @brief Returns safe_integral<value_type>{0, true}
        ///   @include safe_integral/example_safe_integral_failure.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns safe_integral<value_type>{0, true}
        ///
        [[nodiscard]] static constexpr auto
        failure() noexcept -> safe_integral<value_type>
        {
            return safe_integral<value_type>{static_cast<value_type>(0), true};
        }

        /// <!-- description -->
        ///   @brief Returns the max value the bsl::safe_integral can store.
        ///   @include safe_integral/example_safe_integral_max.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the max value the bsl::safe_integral can store.
        ///
        [[nodiscard]] static constexpr auto
        max() noexcept -> safe_integral<value_type>
        {
            return safe_integral<value_type>{numeric_limits<value_type>::max()};
        }

        /// <!-- description -->
        ///   @brief Returns the max value between *this and other. If an
        ///     error has previously been encountered, this function returns
        ///     0 with an error.
        ///   @include safe_integral/example_safe_integral_max.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param other the other value to compare with *this
        ///   @return Returns the max value between *this and other. If an
        ///     error has previously been encountered, this function returns
        ///     0 with an error.
        ///
        [[nodiscard]] constexpr auto
        max(safe_integral<value_type> const &other) const noexcept -> safe_integral<value_type>
        {
            if (unlikely(this->invalid())) {
                illegal_use_of_invalid_safe_integral();
                return safe_integral<value_type>::failure();
            }

            if (unlikely(other.invalid())) {
                illegal_use_of_invalid_safe_integral();
                return safe_integral<value_type>::failure();
            }

            if constexpr (is_signed<T>::value) {
                if (static_cast<bsl::intmax>(m_val) < static_cast<bsl::intmax>(other.m_val)) {
                    return other;
                }

                return *this;
            }
            else {
                if (static_cast<bsl::uintmax>(m_val) < static_cast<bsl::uintmax>(other.m_val)) {
                    return other;
                }

                return *this;
            }
        }

        /// <!-- description -->
        ///   @brief Returns the max value between *this and other. If an
        ///     error has previously been encountered, this function returns
        ///     0 with an error.
        ///   @include safe_integral/example_safe_integral_max.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam U Used to ensure the provided integer is the same as
        ///     T, effectively preventing implicit conversions from being
        ///     allowed.
        ///   @param other the other value to compare with *this
        ///   @return Returns the max value between *this and other. If an
        ///     error has previously been encountered, this function returns
        ///     0 with an error.
        ///
        template<typename U, enable_if_t<is_same<value_type, U>::value, bool> = true>
        [[nodiscard]] constexpr auto
        max(U const other) const noexcept -> safe_integral<value_type>
        {
            if (unlikely(this->invalid())) {
                illegal_use_of_invalid_safe_integral();
                return safe_integral<value_type>::failure();
            }

            if constexpr (is_signed<T>::value) {
                if (static_cast<bsl::intmax>(m_val) < static_cast<bsl::intmax>(other)) {
                    return safe_integral<value_type>{other};
                }

                return *this;
            }
            else {
                if (static_cast<bsl::uintmax>(m_val) < static_cast<bsl::uintmax>(other)) {
                    return safe_integral<value_type>{other};
                }

                return *this;
            }
        }

        /// <!-- description -->
        ///   @brief Returns the min value the bsl::safe_integral can store.
        ///   @include safe_integral/example_safe_integral_min.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the min value the bsl::safe_integral can store.
        ///
        [[nodiscard]] static constexpr auto
        min() noexcept -> safe_integral<value_type>
        {
            return safe_integral<value_type>{numeric_limits<value_type>::min()};
        }

        /// <!-- description -->
        ///   @brief Returns the min value between *this and other. If an
        ///     error has previously been encountered, this function returns
        ///     0 with an error.
        ///   @include safe_integral/example_safe_integral_min.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param other the other value to compare with *this
        ///   @return Returns the min value between *this and other. If an
        ///     error has previously been encountered, this function returns
        ///     0 with an error.
        ///
        [[nodiscard]] constexpr auto
        min(safe_integral<value_type> const &other) const noexcept -> safe_integral<value_type>
        {
            if (unlikely(this->invalid())) {
                illegal_use_of_invalid_safe_integral();
                return safe_integral<value_type>::failure();
            }

            if (unlikely(other.invalid())) {
                illegal_use_of_invalid_safe_integral();
                return safe_integral<value_type>::failure();
            }

            if constexpr (is_signed<T>::value) {
                if (static_cast<bsl::intmax>(m_val) < static_cast<bsl::intmax>(other.m_val)) {
                    return *this;
                }

                return other;
            }
            else {
                if (static_cast<bsl::uintmax>(m_val) < static_cast<bsl::uintmax>(other.m_val)) {
                    return *this;
                }

                return other;
            }
        }

        /// <!-- description -->
        ///   @brief Returns the min value between *this and other. If an
        ///     error has previously been encountered, this function returns
        ///     0 with an error.
        ///   @include safe_integral/example_safe_integral_min.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam U Used to ensure the provided integer is the same as
        ///     T, effectively preventing implicit conversions from being
        ///     allowed.
        ///   @param other the other value to compare with *this
        ///   @return Returns the min value between *this and other. If an
        ///     error has previously been encountered, this function returns
        ///     0 with an error.
        ///
        template<typename U, enable_if_t<is_same<value_type, U>::value, bool> = true>
        [[nodiscard]] constexpr auto
        min(U const other) const noexcept -> safe_integral<value_type>
        {
            if (unlikely(this->invalid())) {
                illegal_use_of_invalid_safe_integral();
                return safe_integral<value_type>::failure();
            }

            if constexpr (is_signed<T>::value) {
                if (static_cast<bsl::intmax>(m_val) < static_cast<bsl::intmax>(other)) {
                    return *this;
                }

                return safe_integral<value_type>{other};
            }
            else {
                if (static_cast<bsl::uintmax>(m_val) < static_cast<bsl::uintmax>(other)) {
                    return *this;
                }

                return safe_integral<value_type>{other};
            }
        }

        /// <!-- description -->
        ///   @brief Returns true if the safe_integral is positive. Will
        ///     always return false if an error has been encountered.
        ///   @include safe_integral/example_safe_integral_is_pos.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if the safe_integral is positive
        ///
        [[nodiscard]] constexpr auto
        is_pos() const noexcept -> bool
        {
            constexpr safe_integral<value_type> zero{static_cast<value_type>(0)};
            return zero < *this;
        }

        /// <!-- description -->
        ///   @brief Returns true if the safe_integral is negative. Will
        ///     always return false if an error has been encountered.
        ///   @include safe_integral/example_safe_integral_is_neg.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if the safe_integral is negative
        ///
        [[nodiscard]] constexpr auto
        is_neg() const noexcept -> bool
        {
            /// NOTE:
            /// - Unsigned integrals cannot be negative. If you are running
            ///   into this error at compile-time, you need to make better use
            ///   of type traits and if constexpr () statements to ensure at
            ///   runtime, you are not executing code that will never happen.
            /// - In this case, you should wrap a call to this in a constexpr
            ///   if statement checking to see if your type if signed. Any
            ///   type that is unsigned will always return false, and therefore
            ///   that branch does not actually need to be there.
            /// - More importantly, it would be impossible to get 100% branch
            ///   coverage if you don't add these types of optimizations as
            ///   there would be no way to convince a unit test to execute
            ///   code that triggered on is_neg() for unsigned values.
            /// - Finally, a review of your existing code for other instances
            ///   of this type of problem would be a good idea.
            ///

            if constexpr (is_unsigned<value_type>::value) {
                illegal_use_of_invalid_safe_integral();
                return false;
            }

            constexpr safe_integral<value_type> zero{static_cast<value_type>(0)};
            return zero > *this;
        }

        /// <!-- description -->
        ///   @brief Returns true if the safe_integral is 0. Will
        ///     always return false if an error has been encountered.
        ///   @include safe_integral/example_safe_integral_is_zero.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if the safe_integral is 0
        ///
        [[nodiscard]] constexpr auto
        is_zero() const noexcept -> bool
        {
            constexpr safe_integral<value_type> zero{static_cast<value_type>(0)};
            return zero == *this;
        }

        /// <!-- description -->
        ///   @brief Returns true if the safe_integral is 0. Will
        ///     always return true if an error has been encountered.
        ///   @include safe_integral/example_safe_integral_is_zero.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if the safe_integral is 0
        ///
        [[nodiscard]] constexpr auto
        is_zero_or_invalid() const noexcept -> bool
        {
            if (m_error) {
                return true;
            }

            constexpr safe_integral<value_type> zero{static_cast<value_type>(0)};
            return zero == *this;
        }

        /// <!-- description -->
        ///   @brief Returns true if the safe_integral has encountered and
        ///     error, false otherwise.
        ///   @include safe_integral/example_safe_integral_invalid.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if the safe_integral is 0
        ///
        [[nodiscard]] constexpr auto
        invalid() const noexcept -> bool
        {
            return m_error;
        }

        /// <!-- description -->
        ///   @brief Returns true if the safe_integral has never experienced
        ///     a wrap, overflow, underflow, divide by 0, etc.
        ///   @include safe_integral/example_safe_integral_operator_bool.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if the safe_integral has never experienced
        ///     a wrap, overflow, underflow, divide by 0, etc.
        ///
        [[nodiscard]] explicit constexpr operator bool() const noexcept
        {
            return !m_error;
        }

        /// <!-- description -->
        ///   @brief Returns *this += rhs. If this operation results in
        ///     an error (e.g., overflow, wrapping, etc.), the result of
        ///     this operation is undefined, and get() will always return 0.
        ///   @include safe_integral/example_safe_integral_assign_add.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param rhs the value to add to *this
        ///   @return Returns *this += rhs. If this operation results in
        ///     an error (e.g., overflow, wrapping, etc.), the result of
        ///     this operation is undefined, and get() will always return 0.
        ///
        [[maybe_unused]] constexpr auto
        operator+=(safe_integral<value_type> const &rhs) &noexcept -> safe_integral<value_type> &
        {
            bool const e{builtin_add_overflow(m_val, rhs.m_val, &m_val)};

            if (unlikely(this->invalid())) {
                illegal_use_of_invalid_safe_integral();
                m_error = true;
                return *this;
            }

            if (unlikely(rhs.invalid())) {
                illegal_use_of_invalid_safe_integral();
                m_error = true;
                return *this;
            }

            if (e) {
                m_error = true;
                return *this;
            }

            m_error = false;
            return *this;
        }

        /// <!-- description -->
        ///   @brief The r-value version of this function is not supported
        ///
        /// <!-- inputs/outputs -->
        ///   @param rhs n/a
        ///   @return n/a
        ///
        [[maybe_unused]] constexpr auto
        operator+=(safe_integral<value_type> const &rhs) const &&noexcept
            -> safe_integral<value_type> & = delete;

        /// <!-- description -->
        ///   @brief Returns *this += rhs. If this operation results in
        ///     an error (e.g., overflow, wrapping, etc.), the result of
        ///     this operation is undefined, and get() will always return 0.
        ///   @include safe_integral/example_safe_integral_assign_add.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam U Used to ensure the provided integer is the same as
        ///     T, effectively preventing implicit conversions from being
        ///     allowed.
        ///   @param rhs the value to add to *this
        ///   @return Returns *this += rhs. If this operation results in
        ///     an error (e.g., overflow, wrapping, etc.), the result of
        ///     this operation is undefined, and get() will always return 0.
        ///
        template<typename U, enable_if_t<is_same<T, U>::value, bool> = true>
        [[maybe_unused]] constexpr auto
        operator+=(U const rhs) &noexcept -> safe_integral<value_type> &
        {
            bool const e{builtin_add_overflow(m_val, rhs, &m_val)};

            if (unlikely(this->invalid())) {
                illegal_use_of_invalid_safe_integral();
                m_error = true;
                return *this;
            }

            if (e) {
                m_error = true;
                return *this;
            }

            m_error = false;
            return *this;
        }

        /// <!-- description -->
        ///   @brief The r-value version of this function is not supported
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam U n/a
        ///   @param rhs n/a
        ///   @return n/a
        ///
        template<typename U, enable_if_t<is_same<T, U>::value, bool> = true>
        [[maybe_unused]] constexpr auto operator+=(U const rhs) const &&noexcept
            -> safe_integral<value_type> & = delete;

        /// <!-- description -->
        ///   @brief Returns *this -= rhs. If this operation results in
        ///     an error (e.g., overflow, wrapping, etc.), the result of
        ///     this operation is undefined, and get() will always return 0.
        ///   @include safe_integral/example_safe_integral_assign_sub.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param rhs the value to sub from *this
        ///   @return Returns *this -= rhs. If this operation results in
        ///     an error (e.g., overflow, wrapping, etc.), the result of
        ///     this operation is undefined, and get() will always return 0.
        ///
        [[maybe_unused]] constexpr auto
        operator-=(safe_integral<value_type> const &rhs) &noexcept -> safe_integral<value_type> &
        {
            bool const e{builtin_sub_overflow(m_val, rhs.m_val, &m_val)};

            if (unlikely(this->invalid())) {
                illegal_use_of_invalid_safe_integral();
                m_error = true;
                return *this;
            }

            if (unlikely(rhs.invalid())) {
                illegal_use_of_invalid_safe_integral();
                m_error = true;
                return *this;
            }

            if (e) {
                m_error = true;
                return *this;
            }

            m_error = false;
            return *this;
        }

        /// <!-- description -->
        ///   @brief The r-value version of this function is not supported
        ///
        /// <!-- inputs/outputs -->
        ///   @param rhs n/a
        ///   @return n/a
        ///
        [[maybe_unused]] constexpr auto
        operator-=(safe_integral<value_type> const &rhs) const &&noexcept
            -> safe_integral<value_type> & = delete;

        /// <!-- description -->
        ///   @brief Returns *this -= rhs. If this operation results in
        ///     an error (e.g., overflow, wrapping, etc.), the result of
        ///     this operation is undefined, and get() will always return 0.
        ///   @include safe_integral/example_safe_integral_assign_sub.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam U Used to ensure the provided integer is the same as
        ///     T, effectively preventing implicit conversions from being
        ///     allowed.
        ///   @param rhs the value to sub from *this
        ///   @return Returns *this -= rhs. If this operation results in
        ///     an error (e.g., overflow, wrapping, etc.), the result of
        ///     this operation is undefined, and get() will always return 0.
        ///
        template<typename U, enable_if_t<is_same<T, U>::value, bool> = true>
        [[maybe_unused]] constexpr auto
        operator-=(U const rhs) &noexcept -> safe_integral<value_type> &
        {
            bool const e{builtin_sub_overflow(m_val, rhs, &m_val)};

            if (unlikely(this->invalid())) {
                illegal_use_of_invalid_safe_integral();
                m_error = true;
                return *this;
            }

            if (e) {
                m_error = true;
                return *this;
            }

            m_error = false;
            return *this;
        }

        /// <!-- description -->
        ///   @brief The r-value version of this function is not supported
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam U n/a
        ///   @param rhs n/a
        ///   @return n/a
        ///
        template<typename U, enable_if_t<is_same<T, U>::value, bool> = true>
        [[maybe_unused]] constexpr auto operator-=(U const rhs) const &&noexcept
            -> safe_integral<value_type> & = delete;

        /// <!-- description -->
        ///   @brief Returns *this *= rhs. If this operation results in
        ///     an error (e.g., overflow, wrapping, etc.), the result of
        ///     this operation is undefined, and get() will always return 0.
        ///   @include safe_integral/example_safe_integral_assign_mul.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param rhs the value to multiply *this by
        ///   @return Returns *this *= rhs. If this operation results in
        ///     an error (e.g., overflow, wrapping, etc.), the result of
        ///     this operation is undefined, and get() will always return 0.
        ///
        [[maybe_unused]] constexpr auto
        operator*=(safe_integral<value_type> const &rhs) &noexcept -> safe_integral<value_type> &
        {
            bool const e{builtin_mul_overflow(m_val, rhs.m_val, &m_val)};

            if (unlikely(this->invalid())) {
                illegal_use_of_invalid_safe_integral();
                m_error = true;
                return *this;
            }

            if (unlikely(rhs.invalid())) {
                illegal_use_of_invalid_safe_integral();
                m_error = true;
                return *this;
            }

            if (e) {
                m_error = true;
                return *this;
            }

            m_error = false;
            return *this;
        }

        /// <!-- description -->
        ///   @brief The r-value version of this function is not supported
        ///
        /// <!-- inputs/outputs -->
        ///   @param rhs n/a
        ///   @return n/a
        ///
        [[maybe_unused]] constexpr auto
        operator*=(safe_integral<value_type> const &rhs) const &&noexcept
            -> safe_integral<value_type> & = delete;

        /// <!-- description -->
        ///   @brief Returns *this *= rhs. If this operation results in
        ///     an error (e.g., overflow, wrapping, etc.), the result of
        ///     this operation is undefined, and get() will always return 0.
        ///   @include safe_integral/example_safe_integral_assign_mul.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam U Used to ensure the provided integer is the same as
        ///     T, effectively preventing implicit conversions from being
        ///     allowed.
        ///   @param rhs the value to multiply *this by
        ///   @return Returns *this *= rhs. If this operation results in
        ///     an error (e.g., overflow, wrapping, etc.), the result of
        ///     this operation is undefined, and get() will always return 0.
        ///
        template<typename U, enable_if_t<is_same<T, U>::value, bool> = true>
        [[maybe_unused]] constexpr auto
        operator*=(U const rhs) &noexcept -> safe_integral<value_type> &
        {
            bool const e{builtin_mul_overflow(m_val, rhs, &m_val)};

            if (unlikely(this->invalid())) {
                illegal_use_of_invalid_safe_integral();
                m_error = true;
                return *this;
            }

            if (e) {
                m_error = true;
                return *this;
            }

            m_error = false;
            return *this;
        }

        /// <!-- description -->
        ///   @brief The r-value version of this function is not supported
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam U n/a
        ///   @param rhs n/a
        ///   @return n/a
        ///
        template<typename U, enable_if_t<is_same<T, U>::value, bool> = true>
        [[maybe_unused]] constexpr auto operator*=(U const rhs) const &&noexcept
            -> safe_integral<value_type> & = delete;

        /// <!-- description -->
        ///   @brief Returns *this /= rhs. If this operation results in
        ///     an error (e.g., overflow, wrapping, etc.), the result of
        ///     this operation is undefined, and get() will always return 0.
        ///   @include safe_integral/example_safe_integral_assign_div.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param rhs the value to divide *this by
        ///   @return Returns *this /= rhs. If this operation results in
        ///     an error (e.g., overflow, wrapping, etc.), the result of
        ///     this operation is undefined, and get() will always return 0.
        ///
        [[maybe_unused]] constexpr auto
        operator/=(safe_integral<value_type> const &rhs) &noexcept -> safe_integral<value_type> &
        {
            bool const e{builtin_div_overflow(m_val, rhs.m_val, &m_val)};

            if (unlikely(this->invalid())) {
                illegal_use_of_invalid_safe_integral();
                m_error = true;
                return *this;
            }

            if (unlikely(rhs.invalid())) {
                illegal_use_of_invalid_safe_integral();
                m_error = true;
                return *this;
            }

            if (e) {
                m_error = true;
                return *this;
            }

            m_error = false;
            return *this;
        }

        /// <!-- description -->
        ///   @brief The r-value version of this function is not supported
        ///
        /// <!-- inputs/outputs -->
        ///   @param rhs n/a
        ///   @return n/a
        ///
        [[maybe_unused]] constexpr auto
        operator/=(safe_integral<value_type> const &rhs) const &&noexcept
            -> safe_integral<value_type> & = delete;

        /// <!-- description -->
        ///   @brief Returns *this /= rhs. If this operation results in
        ///     an error (e.g., overflow, wrapping, etc.), the result of
        ///     this operation is undefined, and get() will always return 0.
        ///   @include safe_integral/example_safe_integral_assign_div.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam U Used to ensure the provided integer is the same as
        ///     T, effectively preventing implicit conversions from being
        ///     allowed.
        ///   @param rhs the value to divide *this by
        ///   @return Returns *this /= rhs. If this operation results in
        ///     an error (e.g., overflow, wrapping, etc.), the result of
        ///     this operation is undefined, and get() will always return 0.
        ///
        template<typename U, enable_if_t<is_same<T, U>::value, bool> = true>
        [[maybe_unused]] constexpr auto
        operator/=(U const rhs) &noexcept -> safe_integral<value_type> &
        {
            bool const e{builtin_div_overflow(m_val, rhs, &m_val)};

            if (unlikely(this->invalid())) {
                illegal_use_of_invalid_safe_integral();
                m_error = true;
                return *this;
            }

            if (e) {
                m_error = true;
                return *this;
            }

            m_error = false;
            return *this;
        }

        /// <!-- description -->
        ///   @brief The r-value version of this function is not supported
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam U n/a
        ///   @param rhs n/a
        ///   @return n/a
        ///
        template<typename U, enable_if_t<is_same<T, U>::value, bool> = true>
        [[maybe_unused]] constexpr auto operator/=(U const rhs) const &&noexcept
            -> safe_integral<value_type> & = delete;

        /// <!-- description -->
        ///   @brief Returns *this %= rhs. If this operation results in
        ///     an error (e.g., overflow, wrapping, etc.), the result of
        ///     this operation is undefined, and get() will always return 0.
        ///   @include safe_integral/example_safe_integral_assign_mod.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param rhs the value to modulo *this by
        ///   @return Returns *this %= rhs. If this operation results in
        ///     an error (e.g., overflow, wrapping, etc.), the result of
        ///     this operation is undefined, and get() will always return 0.
        ///
        [[maybe_unused]] constexpr auto
        operator%=(safe_integral<value_type> const &rhs) &noexcept -> safe_integral<value_type> &
        {
            bool const e{builtin_mod_overflow(m_val, rhs.m_val, &m_val)};

            if (unlikely(this->invalid())) {
                illegal_use_of_invalid_safe_integral();
                m_error = true;
                return *this;
            }

            if (unlikely(rhs.invalid())) {
                illegal_use_of_invalid_safe_integral();
                m_error = true;
                return *this;
            }

            if (e) {
                m_error = true;
                return *this;
            }

            m_error = false;
            return *this;
        }

        /// <!-- description -->
        ///   @brief The r-value version of this function is not supported
        ///
        /// <!-- inputs/outputs -->
        ///   @param rhs n/a
        ///   @return n/a
        ///
        [[maybe_unused]] constexpr auto
        operator%=(safe_integral<value_type> const &rhs) const &&noexcept
            -> safe_integral<value_type> & = delete;

        /// <!-- description -->
        ///   @brief Returns *this %= rhs. If this operation results in
        ///     an error (e.g., overflow, wrapping, etc.), the result of
        ///     this operation is undefined, and get() will always return 0.
        ///   @include safe_integral/example_safe_integral_assign_mod.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam U Used to ensure the provided integer is the same as
        ///     T, effectively preventing implicit conversions from being
        ///     allowed.
        ///   @param rhs the value to modulo *this by
        ///   @return Returns *this %= rhs. If this operation results in
        ///     an error (e.g., overflow, wrapping, etc.), the result of
        ///     this operation is undefined, and get() will always return 0.
        ///
        template<typename U, enable_if_t<is_same<T, U>::value, bool> = true>
        [[maybe_unused]] constexpr auto
        operator%=(U const rhs) &noexcept -> safe_integral<value_type> &
        {
            bool const e{builtin_mod_overflow(m_val, rhs, &m_val)};

            if (unlikely(this->invalid())) {
                illegal_use_of_invalid_safe_integral();
                m_error = true;
                return *this;
            }

            if (e) {
                m_error = true;
                return *this;
            }

            m_error = false;
            return *this;
        }

        /// <!-- description -->
        ///   @brief The r-value version of this function is not supported
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam U n/a
        ///   @param rhs n/a
        ///   @return n/a
        ///
        template<typename U, enable_if_t<is_same<T, U>::value, bool> = true>
        [[maybe_unused]] constexpr auto operator%=(U const rhs) const &&noexcept
            -> safe_integral<value_type> & = delete;

        /// <!-- description -->
        ///   @brief Returns *this <<= rhs.
        ///   @include safe_integral/example_safe_integral_assign_lshift.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param rhs the value to shift *this by
        ///   @return Returns *this <<= rhs.
        ///
        [[maybe_unused]] constexpr auto
        operator<<=(safe_integral<value_type> const &rhs) &noexcept -> safe_integral<value_type> &
        {
            if constexpr (is_signed<value_type>::value) {
                static_assert(always_false<value_type>(), "signed shift not supported");
            }
            else {
                // NOLINTNEXTLINE(bsl-implicit-conversions-forbidden)
                m_val <<= rhs.get();

                if (unlikely(this->invalid())) {
                    illegal_use_of_invalid_safe_integral();
                    m_error = true;
                    return *this;
                }

                if (unlikely(rhs.invalid())) {
                    illegal_use_of_invalid_safe_integral();
                    m_error = true;
                    return *this;
                }

                m_error = false;
                return *this;
            }
        }

        /// <!-- description -->
        ///   @brief The r-value version of this function is not supported
        ///
        /// <!-- inputs/outputs -->
        ///   @param rhs n/a
        ///   @return n/a
        ///
        [[maybe_unused]] constexpr auto
        operator<<=(safe_integral<value_type> const &rhs) const &&noexcept
            -> safe_integral<value_type> & = delete;

        /// <!-- description -->
        ///   @brief Returns *this <<= rhs.
        ///   @include safe_integral/example_safe_integral_assign_lshift.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam U Used to ensure the provided integer is the same as
        ///     T, effectively preventing implicit conversions from being
        ///     allowed.
        ///   @param rhs the value to shift *this by
        ///   @return Returns *this <<= rhs.
        ///
        template<typename U, enable_if_t<is_same<T, U>::value, bool> = true>
        [[maybe_unused]] constexpr auto
        operator<<=(U const rhs) &noexcept -> safe_integral<value_type> &
        {
            if constexpr (is_signed<value_type>::value) {
                static_assert(always_false<value_type>(), "signed shift not supported");
            }
            else {
                // NOLINTNEXTLINE(bsl-implicit-conversions-forbidden)
                m_val <<= rhs;

                if (unlikely(this->invalid())) {
                    illegal_use_of_invalid_safe_integral();
                    m_error = true;
                    return *this;
                }

                m_error = false;
                return *this;
            }
        }

        /// <!-- description -->
        ///   @brief The r-value version of this function is not supported
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam U n/a
        ///   @param rhs n/a
        ///   @return n/a
        ///
        template<typename U, enable_if_t<is_same<T, U>::value, bool> = true>
        [[maybe_unused]] constexpr auto operator<<=(U const rhs) const &&noexcept
            -> safe_integral<value_type> & = delete;

        /// <!-- description -->
        ///   @brief Returns *this >>= rhs.
        ///   @include safe_integral/example_safe_integral_assign_rshift.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param rhs the value to shift *this by
        ///   @return Returns *this >>= rhs.
        ///
        [[maybe_unused]] constexpr auto
        operator>>=(safe_integral<value_type> const &rhs) &noexcept -> safe_integral<value_type> &
        {
            if constexpr (is_signed<value_type>::value) {
                static_assert(always_false<value_type>(), "signed shift not supported");
            }
            else {
                // NOLINTNEXTLINE(bsl-implicit-conversions-forbidden)
                m_val >>= rhs.get();

                if (unlikely(this->invalid())) {
                    illegal_use_of_invalid_safe_integral();
                    m_error = true;
                    return *this;
                }

                if (unlikely(rhs.invalid())) {
                    illegal_use_of_invalid_safe_integral();
                    m_error = true;
                    return *this;
                }

                m_error = false;
                return *this;
            }
        }

        /// <!-- description -->
        ///   @brief The r-value version of this function is not supported
        ///
        /// <!-- inputs/outputs -->
        ///   @param rhs n/a
        ///   @return n/a
        ///
        [[maybe_unused]] constexpr auto
        operator>>=(safe_integral<value_type> const &rhs) const &&noexcept
            -> safe_integral<value_type> & = delete;

        /// <!-- description -->
        ///   @brief Returns *this >>= rhs.
        ///   @include safe_integral/example_safe_integral_assign_rshift.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam U Used to ensure the provided integer is the same as
        ///     T, effectively preventing implicit conversions from being
        ///     allowed.
        ///   @param rhs the value to shift *this by
        ///   @return Returns *this >>= rhs.
        ///
        template<typename U, enable_if_t<is_same<T, U>::value, bool> = true>
        [[maybe_unused]] constexpr auto
        operator>>=(U const rhs) &noexcept -> safe_integral<value_type> &
        {
            if constexpr (is_signed<value_type>::value) {
                static_assert(always_false<value_type>(), "signed shift not supported");
            }
            else {
                // NOLINTNEXTLINE(bsl-implicit-conversions-forbidden)
                m_val >>= rhs;

                if (unlikely(this->invalid())) {
                    illegal_use_of_invalid_safe_integral();
                    m_error = true;
                    return *this;
                }

                m_error = false;
                return *this;
            }
        }

        /// <!-- description -->
        ///   @brief The r-value version of this function is not supported
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam U n/a
        ///   @param rhs n/a
        ///   @return n/a
        ///
        template<typename U, enable_if_t<is_same<T, U>::value, bool> = true>
        [[maybe_unused]] constexpr auto operator>>=(U const rhs) const &&noexcept
            -> safe_integral<value_type> & = delete;

        /// <!-- description -->
        ///   @brief Returns *this &= rhs.
        ///   @include safe_integral/example_safe_integral_assign_and.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param rhs the value to and *this by
        ///   @return Returns *this &= rhs.
        ///
        [[maybe_unused]] constexpr auto
        operator&=(safe_integral<value_type> const &rhs) &noexcept -> safe_integral<value_type> &
        {
            if constexpr (is_signed<value_type>::value) {
                static_assert(always_false<value_type>(), "signed and not supported");
            }
            else {
                // NOLINTNEXTLINE(bsl-implicit-conversions-forbidden)
                m_val &= rhs.get();

                if (unlikely(this->invalid())) {
                    illegal_use_of_invalid_safe_integral();
                    m_error = true;
                    return *this;
                }

                if (unlikely(rhs.invalid())) {
                    illegal_use_of_invalid_safe_integral();
                    m_error = true;
                    return *this;
                }

                m_error = false;
                return *this;
            }
        }

        /// <!-- description -->
        ///   @brief The r-value version of this function is not supported
        ///
        /// <!-- inputs/outputs -->
        ///   @param rhs n/a
        ///   @return n/a
        ///
        [[maybe_unused]] constexpr auto
        operator&=(safe_integral<value_type> const &rhs) const &&noexcept
            -> safe_integral<value_type> & = delete;

        /// <!-- description -->
        ///   @brief Returns *this &= rhs.
        ///   @include safe_integral/example_safe_integral_assign_and.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam U Used to ensure the provided integer is the same as
        ///     T, effectively preventing implicit conversions from being
        ///     allowed.
        ///   @param rhs the value to and *this by
        ///   @return Returns *this &= rhs.
        ///
        template<typename U, enable_if_t<is_same<T, U>::value, bool> = true>
        [[maybe_unused]] constexpr auto
        operator&=(U const rhs) &noexcept -> safe_integral<value_type> &
        {
            if constexpr (is_signed<value_type>::value) {
                static_assert(always_false<value_type>(), "signed and not supported");
            }
            else {
                // NOLINTNEXTLINE(bsl-implicit-conversions-forbidden)
                m_val &= rhs;

                if (unlikely(this->invalid())) {
                    illegal_use_of_invalid_safe_integral();
                    m_error = true;
                    return *this;
                }

                m_error = false;
                return *this;
            }
        }

        /// <!-- description -->
        ///   @brief The r-value version of this function is not supported
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam U n/a
        ///   @param rhs n/a
        ///   @return n/a
        ///
        template<typename U, enable_if_t<is_same<T, U>::value, bool> = true>
        [[maybe_unused]] constexpr auto operator&=(U const rhs) const &&noexcept
            -> safe_integral<value_type> & = delete;

        /// <!-- description -->
        ///   @brief Returns *this |= rhs.
        ///   @include safe_integral/example_safe_integral_assign_or.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param rhs the value to or *this by
        ///   @return Returns *this |= rhs.
        ///
        [[maybe_unused]] constexpr auto
        operator|=(safe_integral<value_type> const &rhs) &noexcept -> safe_integral<value_type> &
        {
            if constexpr (is_signed<value_type>::value) {
                static_assert(always_false<value_type>(), "signed or not supported");
            }
            else {
                // NOLINTNEXTLINE(bsl-implicit-conversions-forbidden)
                m_val |= rhs.get();

                if (unlikely(this->invalid())) {
                    illegal_use_of_invalid_safe_integral();
                    m_error = true;
                    return *this;
                }

                if (unlikely(rhs.invalid())) {
                    illegal_use_of_invalid_safe_integral();
                    m_error = true;
                    return *this;
                }

                m_error = false;
                return *this;
            }
        }

        /// <!-- description -->
        ///   @brief The r-value version of this function is not supported
        ///
        /// <!-- inputs/outputs -->
        ///   @param rhs n/a
        ///   @return n/a
        ///
        [[maybe_unused]] constexpr auto
        operator|=(safe_integral<value_type> const &rhs) const &&noexcept
            -> safe_integral<value_type> & = delete;

        /// <!-- description -->
        ///   @brief Returns *this |= rhs.
        ///   @include safe_integral/example_safe_integral_assign_or.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam U Used to ensure the provided integer is the same as
        ///     T, effectively preventing implicit conversions from being
        ///     allowed.
        ///   @param rhs the value to or *this by
        ///   @return Returns *this |= rhs.
        ///
        template<typename U, enable_if_t<is_same<T, U>::value, bool> = true>
        [[maybe_unused]] constexpr auto
        operator|=(U const rhs) &noexcept -> safe_integral<value_type> &
        {
            if constexpr (is_signed<value_type>::value) {
                static_assert(always_false<value_type>(), "signed or not supported");
            }
            else {
                // NOLINTNEXTLINE(bsl-implicit-conversions-forbidden)
                m_val |= rhs;

                if (unlikely(this->invalid())) {
                    illegal_use_of_invalid_safe_integral();
                    m_error = true;
                    return *this;
                }

                m_error = false;
                return *this;
            }
        }

        /// <!-- description -->
        ///   @brief The r-value version of this function is not supported
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam U n/a
        ///   @param rhs n/a
        ///   @return n/a
        ///
        template<typename U, enable_if_t<is_same<T, U>::value, bool> = true>
        [[maybe_unused]] constexpr auto operator|=(U const rhs) const &&noexcept
            -> safe_integral<value_type> & = delete;

        /// <!-- description -->
        ///   @brief Returns *this ^= rhs.
        ///   @include safe_integral/example_safe_integral_assign_xor.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param rhs the value to xor *this by
        ///   @return Returns *this ^= rhs.
        ///
        [[maybe_unused]] constexpr auto
        operator^=(safe_integral<value_type> const &rhs) &noexcept -> safe_integral<value_type> &
        {
            if constexpr (is_signed<value_type>::value) {
                static_assert(always_false<value_type>(), "signed xor not supported");
            }
            else {
                // NOLINTNEXTLINE(bsl-implicit-conversions-forbidden)
                m_val ^= rhs.get();

                if (unlikely(this->invalid())) {
                    illegal_use_of_invalid_safe_integral();
                    m_error = true;
                    return *this;
                }

                if (unlikely(rhs.invalid())) {
                    illegal_use_of_invalid_safe_integral();
                    m_error = true;
                    return *this;
                }

                m_error = false;
                return *this;
            }
        }

        /// <!-- description -->
        ///   @brief The r-value version of this function is not supported
        ///
        /// <!-- inputs/outputs -->
        ///   @param rhs n/a
        ///   @return n/a
        ///
        [[maybe_unused]] constexpr auto
        operator^=(safe_integral<value_type> const &rhs) const &&noexcept
            -> safe_integral<value_type> & = delete;

        /// <!-- description -->
        ///   @brief Returns *this ^= rhs.
        ///   @include safe_integral/example_safe_integral_assign_xor.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam U Used to ensure the provided integer is the same as
        ///     T, effectively preventing implicit conversions from being
        ///     allowed.
        ///   @param rhs the value to xor *this by
        ///   @return Returns *this ^= rhs.
        ///
        template<typename U, enable_if_t<is_same<T, U>::value, bool> = true>
        [[maybe_unused]] constexpr auto
        operator^=(U const rhs) &noexcept -> safe_integral<value_type> &
        {
            if constexpr (is_signed<value_type>::value) {
                static_assert(always_false<value_type>(), "signed xor not supported");
            }
            else {
                // NOLINTNEXTLINE(bsl-implicit-conversions-forbidden)
                m_val ^= rhs;

                if (unlikely(this->invalid())) {
                    illegal_use_of_invalid_safe_integral();
                    m_error = true;
                    return *this;
                }

                m_error = false;
                return *this;
            }
        }

        /// <!-- description -->
        ///   @brief The r-value version of this function is not supported
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam U n/a
        ///   @param rhs n/a
        ///   @return n/a
        ///
        template<typename U, enable_if_t<is_same<T, U>::value, bool> = true>
        [[maybe_unused]] constexpr auto operator^=(U const rhs) const &&noexcept
            -> safe_integral<value_type> & = delete;

        /// <!-- description -->
        ///   @brief Returns ++(*this). If this operation results in
        ///     an error (e.g., overflow, wrapping, etc.), the result of
        ///     this operation is undefined, and get() will always return 0.
        ///   @include safe_integral/example_safe_integral_inc.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns ++(*this). If this operation results in
        ///     an error (e.g., overflow, wrapping, etc.), the result of
        ///     this operation is undefined, and get() will always return 0.
        ///
        [[maybe_unused]] constexpr auto
        operator++() &noexcept -> safe_integral<value_type> &
        {
            constexpr safe_integral<value_type> one{static_cast<value_type>(1)};
            return *this += one;
        }

        /// <!-- description -->
        ///   @brief The r-value version of this function is not supported
        ///
        /// <!-- inputs/outputs -->
        ///   @return n/a
        ///
        [[maybe_unused]] constexpr auto operator++() const &&noexcept
            -> safe_integral<value_type> & = delete;

        /// <!-- description -->
        ///   @brief Returns --(*this). If this operation results in
        ///     an error (e.g., overflow, wrapping, etc.), the result of
        ///     this operation is undefined, and get() will always return 0.
        ///   @include safe_integral/example_safe_integral_dec.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns --(*this). If this operation results in
        ///     an error (e.g., overflow, wrapping, etc.), the result of
        ///     this operation is undefined, and get() will always return 0.
        ///
        [[maybe_unused]] constexpr auto
        operator--() &noexcept -> safe_integral<value_type> &
        {
            constexpr safe_integral<value_type> one{static_cast<value_type>(1)};
            return *this -= one;
        }

        /// <!-- description -->
        ///   @brief The r-value version of this function is not supported
        ///
        /// <!-- inputs/outputs -->
        ///   @return n/a
        ///
        [[maybe_unused]] constexpr auto operator--() const &&noexcept
            -> safe_integral<value_type> & = delete;
    };

    // -------------------------------------------------------------------------
    // safe_integral rational operators
    // -------------------------------------------------------------------------

    /// <!-- description -->
    ///   @brief Returns lhs.get() == rhs.get(). Will always return false,
    ///     even when comparing to 0 if the safe_integral parameters have
    ///     encountered an error.
    ///   @include safe_integral/example_safe_integral_equals.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the integral type to encapsulate.
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns lhs.get() == rhs.get()
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    operator==(safe_integral<T> const &lhs, safe_integral<T> const &rhs) noexcept -> bool
    {
        if (unlikely(lhs.invalid())) {
            illegal_use_of_invalid_safe_integral();
            return false;
        }

        if (unlikely(rhs.invalid())) {
            illegal_use_of_invalid_safe_integral();
            return false;
        }

        if constexpr (is_signed<T>::value) {
            return static_cast<bsl::intmax>(lhs.get()) == static_cast<bsl::intmax>(rhs.get());
        }
        else {
            return static_cast<bsl::uintmax>(lhs.get()) == static_cast<bsl::uintmax>(rhs.get());
        }
    }

    /// <!-- description -->
    ///   @brief Returns lhs.get() == rhs. Will always return false,
    ///     even when comparing to 0 if the safe_integral parameters have
    ///     encountered an error.
    ///   @include safe_integral/example_safe_integral_equals.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the integral type to encapsulate.
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns lhs.get() == rhs
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    operator==(safe_integral<T> const &lhs, T const rhs) noexcept -> bool
    {
        if (unlikely(lhs.invalid())) {
            illegal_use_of_invalid_safe_integral();
            return false;
        }

        if constexpr (is_signed<T>::value) {
            return static_cast<bsl::intmax>(lhs.get()) == static_cast<bsl::intmax>(rhs);
        }
        else {
            return static_cast<bsl::uintmax>(lhs.get()) == static_cast<bsl::uintmax>(rhs);
        }
    }

    /// <!-- description -->
    ///   @brief Returns lhs == rhs.get(). Will always return false,
    ///     even when comparing to 0 if the safe_integral parameters have
    ///     encountered an error.
    ///   @include safe_integral/example_safe_integral_equals.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the integral type to encapsulate.
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns lhs == rhs.get()
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    operator==(T const lhs, safe_integral<T> const &rhs) noexcept -> bool
    {
        if (unlikely(rhs.invalid())) {
            illegal_use_of_invalid_safe_integral();
            return false;
        }

        if constexpr (is_signed<T>::value) {
            return static_cast<bsl::intmax>(lhs) == static_cast<bsl::intmax>(rhs.get());
        }
        else {
            return static_cast<bsl::uintmax>(lhs) == static_cast<bsl::uintmax>(rhs.get());
        }
    }

    /// <!-- description -->
    ///   @brief Returns lhs.get() != rhs.get(). Will always return true,
    ///     even when comparing to 0 if the safe_integral parameters have
    ///     encountered an error.
    ///   @include safe_integral/example_safe_integral_not_equals.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the integral type to encapsulate.
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns lhs.get() != rhs.get()
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    operator!=(safe_integral<T> const &lhs, safe_integral<T> const &rhs) noexcept -> bool
    {
        return !(lhs == rhs);
    }

    /// <!-- description -->
    ///   @brief Returns lhs.get() != rhs. Will always return true,
    ///     even when comparing to 0 if the safe_integral parameters have
    ///     encountered an error.
    ///   @include safe_integral/example_safe_integral_not_equals.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the integral type to encapsulate.
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns lhs.get() != rhs
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    operator!=(safe_integral<T> const &lhs, T const rhs) noexcept -> bool
    {
        return !(lhs == rhs);
    }

    /// <!-- description -->
    ///   @brief Returns lhs != rhs.get(). Will always return true,
    ///     even when comparing to 0 if the safe_integral parameters have
    ///     encountered an error.
    ///   @include safe_integral/example_safe_integral_not_equals.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the integral type to encapsulate.
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns lhs != rhs.get()
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    operator!=(T const lhs, safe_integral<T> const &rhs) noexcept -> bool
    {
        return !(lhs == rhs);
    }

    /// <!-- description -->
    ///   @brief Returns lhs.get() < rhs.get(). Will always return false,
    ///     even when comparing to 0 if the safe_integral parameters have
    ///     encountered an error.
    ///   @include safe_integral/example_safe_integral_lt.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the integral type to encapsulate.
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns lhs.get() < rhs.get()
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    operator<(safe_integral<T> const &lhs, safe_integral<T> const &rhs) noexcept -> bool
    {
        if (unlikely(lhs.invalid())) {
            illegal_use_of_invalid_safe_integral();
            return false;
        }

        if (unlikely(rhs.invalid())) {
            illegal_use_of_invalid_safe_integral();
            return false;
        }

        if constexpr (is_signed<T>::value) {
            return static_cast<bsl::intmax>(lhs.get()) < static_cast<bsl::intmax>(rhs.get());
        }
        else {
            return static_cast<bsl::uintmax>(lhs.get()) < static_cast<bsl::uintmax>(rhs.get());
        }
    }

    /// <!-- description -->
    ///   @brief Returns lhs.get() < rhs. Will always return false,
    ///     even when comparing to 0 if the safe_integral parameters have
    ///     encountered an error.
    ///   @include safe_integral/example_safe_integral_lt.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the integral type to encapsulate.
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns lhs.get() < rhs
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    operator<(safe_integral<T> const &lhs, T const rhs) noexcept -> bool
    {
        if (unlikely(lhs.invalid())) {
            illegal_use_of_invalid_safe_integral();
            return false;
        }

        if constexpr (is_signed<T>::value) {
            return static_cast<bsl::intmax>(lhs.get()) < static_cast<bsl::intmax>(rhs);
        }
        else {
            return static_cast<bsl::uintmax>(lhs.get()) < static_cast<bsl::uintmax>(rhs);
        }
    }

    /// <!-- description -->
    ///   @brief Returns lhs < rhs.get(). Will always return false,
    ///     even when comparing to 0 if the safe_integral parameters have
    ///     encountered an error.
    ///   @include safe_integral/example_safe_integral_lt.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the integral type to encapsulate.
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns lhs < rhs.get()
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    operator<(T const lhs, safe_integral<T> const &rhs) noexcept -> bool
    {
        if (unlikely(rhs.invalid())) {
            illegal_use_of_invalid_safe_integral();
            return false;
        }

        if constexpr (is_signed<T>::value) {
            return static_cast<bsl::intmax>(lhs) < static_cast<bsl::intmax>(rhs.get());
        }
        else {
            return static_cast<bsl::uintmax>(lhs) < static_cast<bsl::uintmax>(rhs.get());
        }
    }

    /// <!-- description -->
    ///   @brief Returns lhs.get() > rhs.get(). Will always return false,
    ///     even when comparing to 0 if the safe_integral parameters have
    ///     encountered an error.
    ///   @include safe_integral/example_safe_integral_gt.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the integral type to encapsulate.
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns lhs.get() > rhs.get()
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    operator>(safe_integral<T> const &lhs, safe_integral<T> const &rhs) noexcept -> bool
    {
        if (unlikely(lhs.invalid())) {
            illegal_use_of_invalid_safe_integral();
            return false;
        }

        if (unlikely(rhs.invalid())) {
            illegal_use_of_invalid_safe_integral();
            return false;
        }

        if constexpr (is_signed<T>::value) {
            return static_cast<bsl::intmax>(lhs.get()) > static_cast<bsl::intmax>(rhs.get());
        }
        else {
            return static_cast<bsl::uintmax>(lhs.get()) > static_cast<bsl::uintmax>(rhs.get());
        }
    }

    /// <!-- description -->
    ///   @brief Returns lhs.get() > rhs. Will always return false,
    ///     even when comparing to 0 if the safe_integral parameters have
    ///     encountered an error.
    ///   @include safe_integral/example_safe_integral_gt.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the integral type to encapsulate.
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns lhs.get() > rhs
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    operator>(safe_integral<T> const &lhs, T const rhs) noexcept -> bool
    {
        if (unlikely(lhs.invalid())) {
            illegal_use_of_invalid_safe_integral();
            return false;
        }

        if constexpr (is_signed<T>::value) {
            return static_cast<bsl::intmax>(lhs.get()) > static_cast<bsl::intmax>(rhs);
        }
        else {
            return static_cast<bsl::uintmax>(lhs.get()) > static_cast<bsl::uintmax>(rhs);
        }
    }

    /// <!-- description -->
    ///   @brief Returns lhs > rhs.get(). Will always return false,
    ///     even when comparing to 0 if the safe_integral parameters have
    ///     encountered an error.
    ///   @include safe_integral/example_safe_integral_gt.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the integral type to encapsulate.
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns lhs > rhs.get()
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    operator>(T const lhs, safe_integral<T> const &rhs) noexcept -> bool
    {
        if (unlikely(rhs.invalid())) {
            illegal_use_of_invalid_safe_integral();
            return false;
        }

        if constexpr (is_signed<T>::value) {
            return static_cast<bsl::intmax>(lhs) > static_cast<bsl::intmax>(rhs.get());
        }
        else {
            return static_cast<bsl::uintmax>(lhs) > static_cast<bsl::uintmax>(rhs.get());
        }
    }

    /// <!-- description -->
    ///   @brief Returns lhs.get() < rhs.get(). Will always return false,
    ///     even when comparing to 0 if the safe_integral parameters have
    ///     encountered an error.
    ///   @include safe_integral/example_safe_integral_lt.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the integral type to encapsulate.
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns lhs.get() < rhs.get()
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    operator<=(safe_integral<T> const &lhs, safe_integral<T> const &rhs) noexcept -> bool
    {
        if (unlikely(lhs.invalid())) {
            illegal_use_of_invalid_safe_integral();
            return false;
        }

        if (unlikely(rhs.invalid())) {
            illegal_use_of_invalid_safe_integral();
            return false;
        }

        if constexpr (is_signed<T>::value) {
            return static_cast<bsl::intmax>(lhs.get()) <= static_cast<bsl::intmax>(rhs.get());
        }
        else {
            return static_cast<bsl::uintmax>(lhs.get()) <= static_cast<bsl::uintmax>(rhs.get());
        }
    }

    /// <!-- description -->
    ///   @brief Returns lhs.get() < rhs. Will always return false,
    ///     even when comparing to 0 if the safe_integral parameters have
    ///     encountered an error.
    ///   @include safe_integral/example_safe_integral_lt.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the integral type to encapsulate.
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns lhs.get() < rhs
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    operator<=(safe_integral<T> const &lhs, T const rhs) noexcept -> bool
    {
        if (unlikely(lhs.invalid())) {
            illegal_use_of_invalid_safe_integral();
            return false;
        }

        if constexpr (is_signed<T>::value) {
            return static_cast<bsl::intmax>(lhs.get()) <= static_cast<bsl::intmax>(rhs);
        }
        else {
            return static_cast<bsl::uintmax>(lhs.get()) <= static_cast<bsl::uintmax>(rhs);
        }
    }

    /// <!-- description -->
    ///   @brief Returns lhs < rhs.get(). Will always return false,
    ///     even when comparing to 0 if the safe_integral parameters have
    ///     encountered an error.
    ///   @include safe_integral/example_safe_integral_lt.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the integral type to encapsulate.
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns lhs < rhs.get()
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    operator<=(T const lhs, safe_integral<T> const &rhs) noexcept -> bool
    {
        if (unlikely(rhs.invalid())) {
            illegal_use_of_invalid_safe_integral();
            return false;
        }

        if constexpr (is_signed<T>::value) {
            return static_cast<bsl::intmax>(lhs) <= static_cast<bsl::intmax>(rhs.get());
        }
        else {
            return static_cast<bsl::uintmax>(lhs) <= static_cast<bsl::uintmax>(rhs.get());
        }
    }

    /// <!-- description -->
    ///   @brief Returns lhs.get() > rhs.get(). Will always return false,
    ///     even when comparing to 0 if the safe_integral parameters have
    ///     encountered an error.
    ///   @include safe_integral/example_safe_integral_gt.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the integral type to encapsulate.
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns lhs.get() > rhs.get()
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    operator>=(safe_integral<T> const &lhs, safe_integral<T> const &rhs) noexcept -> bool
    {
        if (unlikely(lhs.invalid())) {
            illegal_use_of_invalid_safe_integral();
            return false;
        }

        if (unlikely(rhs.invalid())) {
            illegal_use_of_invalid_safe_integral();
            return false;
        }

        if constexpr (is_signed<T>::value) {
            return static_cast<bsl::intmax>(lhs.get()) >= static_cast<bsl::intmax>(rhs.get());
        }
        else {
            return static_cast<bsl::uintmax>(lhs.get()) >= static_cast<bsl::uintmax>(rhs.get());
        }
    }

    /// <!-- description -->
    ///   @brief Returns lhs.get() > rhs. Will always return false,
    ///     even when comparing to 0 if the safe_integral parameters have
    ///     encountered an error.
    ///   @include safe_integral/example_safe_integral_gt.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the integral type to encapsulate.
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns lhs.get() > rhs
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    operator>=(safe_integral<T> const &lhs, T const rhs) noexcept -> bool
    {
        if (unlikely(lhs.invalid())) {
            illegal_use_of_invalid_safe_integral();
            return false;
        }

        if constexpr (is_signed<T>::value) {
            return static_cast<bsl::intmax>(lhs.get()) >= static_cast<bsl::intmax>(rhs);
        }
        else {
            return static_cast<bsl::uintmax>(lhs.get()) >= static_cast<bsl::uintmax>(rhs);
        }
    }

    /// <!-- description -->
    ///   @brief Returns lhs > rhs.get(). Will always return false,
    ///     even when comparing to 0 if the safe_integral parameters have
    ///     encountered an error.
    ///   @include safe_integral/example_safe_integral_gt.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the integral type to encapsulate.
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns lhs > rhs.get()
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    operator>=(T const lhs, safe_integral<T> const &rhs) noexcept -> bool
    {
        if (unlikely(rhs.invalid())) {
            illegal_use_of_invalid_safe_integral();
            return false;
        }

        if constexpr (is_signed<T>::value) {
            return static_cast<bsl::intmax>(lhs) >= static_cast<bsl::intmax>(rhs.get());
        }
        else {
            return static_cast<bsl::uintmax>(lhs) >= static_cast<bsl::uintmax>(rhs.get());
        }
    }

    // -------------------------------------------------------------------------
    // safe_integral arithmetic operators
    // -------------------------------------------------------------------------

    /// <!-- description -->
    ///   @brief Returns safe_integral<T>{lhs} += rhs
    ///   @include safe_integral/example_safe_integral_add.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the integral type to encapsulate.
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns safe_integral<T>{lhs} += rhs
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    operator+(safe_integral<T> const &lhs, safe_integral<T> const &rhs) noexcept -> safe_integral<T>
    {
        safe_integral<T> mut_tmp{lhs};
        return mut_tmp += rhs;
    }

    /// <!-- description -->
    ///   @brief Returns lhs + safe_integral<T>{rhs}
    ///   @include safe_integral/example_safe_integral_add.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the integral type to encapsulate.
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns lhs + safe_integral<T>{rhs}
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    operator+(safe_integral<T> const &lhs, T const rhs) noexcept -> safe_integral<T>
    {
        return lhs + safe_integral<T>{rhs};
    }

    /// <!-- description -->
    ///   @brief Returns safe_integral<T>{lhs} + rhs
    ///   @include safe_integral/example_safe_integral_add.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the integral type to encapsulate.
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns safe_integral<T>{lhs} + rhs
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    operator+(T const lhs, safe_integral<T> const &rhs) noexcept -> safe_integral<T>
    {
        return safe_integral<T>{lhs} + rhs;
    }

    /// <!-- description -->
    ///   @brief Returns safe_integral<T>{lhs} -= rhs
    ///   @include safe_integral/example_safe_integral_sub.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the integral type to encapsulate.
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns safe_integral<T>{lhs} -= rhs
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    operator-(safe_integral<T> const &lhs, safe_integral<T> const &rhs) noexcept -> safe_integral<T>
    {
        safe_integral<T> mut_tmp{lhs};
        return mut_tmp -= rhs;
    }

    /// <!-- description -->
    ///   @brief Returns lhs - safe_integral<T>{rhs}
    ///   @include safe_integral/example_safe_integral_sub.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the integral type to encapsulate.
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns lhs - safe_integral<T>{rhs}
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    operator-(safe_integral<T> const &lhs, T const rhs) noexcept -> safe_integral<T>
    {
        return lhs - safe_integral<T>{rhs};
    }

    /// <!-- description -->
    ///   @brief Returns safe_integral<T>{lhs} - rhs
    ///   @include safe_integral/example_safe_integral_sub.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the integral type to encapsulate.
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns safe_integral<T>{lhs} - rhs
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    operator-(T const lhs, safe_integral<T> const &rhs) noexcept -> safe_integral<T>
    {
        return safe_integral<T>{lhs} - rhs;
    }

    /// <!-- description -->
    ///   @brief Returns safe_integral<T>{lhs} *= rhs
    ///   @include safe_integral/example_safe_integral_mul.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the integral type to encapsulate.
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns safe_integral<T>{lhs} *= rhs
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    operator*(safe_integral<T> const &lhs, safe_integral<T> const &rhs) noexcept -> safe_integral<T>
    {
        safe_integral<T> mut_tmp{lhs};
        return mut_tmp *= rhs;
    }

    /// <!-- description -->
    ///   @brief Returns lhs * safe_integral<T>{rhs}
    ///   @include safe_integral/example_safe_integral_mul.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the integral type to encapsulate.
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns lhs * safe_integral<T>{rhs}
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    operator*(safe_integral<T> const &lhs, T const rhs) noexcept -> safe_integral<T>
    {
        return lhs * safe_integral<T>{rhs};
    }

    /// <!-- description -->
    ///   @brief Returns safe_integral<T>{lhs} * rhs
    ///   @include safe_integral/example_safe_integral_mul.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the integral type to encapsulate.
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns safe_integral<T>{lhs} * rhs
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    operator*(T const lhs, safe_integral<T> const &rhs) noexcept -> safe_integral<T>
    {
        return safe_integral<T>{lhs} * rhs;
    }

    /// <!-- description -->
    ///   @brief Returns safe_integral<T>{lhs} /= rhs
    ///   @include safe_integral/example_safe_integral_div.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the integral type to encapsulate.
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns safe_integral<T>{lhs} /= rhs
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    operator/(safe_integral<T> const &lhs, safe_integral<T> const &rhs) noexcept -> safe_integral<T>
    {
        safe_integral<T> mut_tmp{lhs};
        return mut_tmp /= rhs;
    }

    /// <!-- description -->
    ///   @brief Returns lhs / safe_integral<T>{rhs}
    ///   @include safe_integral/example_safe_integral_div.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the integral type to encapsulate.
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns lhs / safe_integral<T>{rhs}
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    operator/(safe_integral<T> const &lhs, T const rhs) noexcept -> safe_integral<T>
    {
        return lhs / safe_integral<T>{rhs};
    }

    /// <!-- description -->
    ///   @brief Returns safe_integral<T>{lhs} / rhs
    ///   @include safe_integral/example_safe_integral_div.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the integral type to encapsulate.
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns safe_integral<T>{lhs} / rhs
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    operator/(T const lhs, safe_integral<T> const &rhs) noexcept -> safe_integral<T>
    {
        return safe_integral<T>{lhs} / rhs;
    }

    /// <!-- description -->
    ///   @brief Returns safe_integral<T>{lhs} %= rhs
    ///   @include safe_integral/example_safe_integral_mod.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the integral type to encapsulate.
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns safe_integral<T>{lhs} %= rhs
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    operator%(safe_integral<T> const &lhs, safe_integral<T> const &rhs) noexcept -> safe_integral<T>
    {
        safe_integral<T> mut_tmp{lhs};
        return mut_tmp %= rhs;
    }

    /// <!-- description -->
    ///   @brief Returns lhs % safe_integral<T>{rhs}
    ///   @include safe_integral/example_safe_integral_mod.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the integral type to encapsulate.
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns lhs % safe_integral<T>{rhs}
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    operator%(safe_integral<T> const &lhs, T const rhs) noexcept -> safe_integral<T>
    {
        return lhs % safe_integral<T>{rhs};
    }

    /// <!-- description -->
    ///   @brief Returns safe_integral<T>{lhs} % rhs
    ///   @include safe_integral/example_safe_integral_mod.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the integral type to encapsulate.
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns safe_integral<T>{lhs} % rhs
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    operator%(T const lhs, safe_integral<T> const &rhs) noexcept -> safe_integral<T>
    {
        return safe_integral<T>{lhs} % rhs;
    }

    // -------------------------------------------------------------------------
    // shift operators
    // -------------------------------------------------------------------------

    /// <!-- description -->
    ///   @brief Returns safe_integral<T>{lhs} <<= rhs
    ///   @include safe_integral/example_safe_integral_lshift.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the integral type to encapsulate.
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns safe_integral<T>{lhs} <<= rhs
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    operator<<(safe_integral<T> const &lhs, safe_integral<T> const &rhs) noexcept
        -> safe_integral<T>
    {
        safe_integral<T> mut_tmp{lhs};
        return mut_tmp <<= rhs;
    }

    /// <!-- description -->
    ///   @brief Returns lhs << safe_integral<T>{rhs}
    ///   @include safe_integral/example_safe_integral_lshift.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the integral type to encapsulate.
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns lhs << safe_integral<T>{rhs}
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    operator<<(safe_integral<T> const &lhs, T const rhs) noexcept -> safe_integral<T>
    {
        return lhs << safe_integral<T>{rhs};
    }

    /// <!-- description -->
    ///   @brief Returns safe_integral<T>{lhs} << rhs
    ///   @include safe_integral/example_safe_integral_lshift.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the integral type to encapsulate.
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns safe_integral<T>{lhs} << rhs
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    operator<<(T const lhs, safe_integral<T> const &rhs) noexcept -> safe_integral<T>
    {
        return safe_integral<T>{lhs} << rhs;
    }

    /// <!-- description -->
    ///   @brief Returns safe_integral<T>{lhs} >>= rhs
    ///   @include safe_integral/example_safe_integral_rshift.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the integral type to encapsulate.
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns safe_integral<T>{lhs} >>= rhs
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    operator>>(safe_integral<T> const &lhs, safe_integral<T> const &rhs) noexcept
        -> safe_integral<T>
    {
        safe_integral<T> mut_tmp{lhs};
        return mut_tmp >>= rhs;
    }

    /// <!-- description -->
    ///   @brief Returns lhs >> safe_integral<T>{rhs}
    ///   @include safe_integral/example_safe_integral_rshift.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the integral type to encapsulate.
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns lhs >> safe_integral<T>{rhs}
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    operator>>(safe_integral<T> const &lhs, T const rhs) noexcept -> safe_integral<T>
    {
        return lhs >> safe_integral<T>{rhs};
    }

    /// <!-- description -->
    ///   @brief Returns safe_integral<T>{lhs} >> rhs
    ///   @include safe_integral/example_safe_integral_rshift.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the integral type to encapsulate.
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns safe_integral<T>{lhs} >> rhs
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    operator>>(T const lhs, safe_integral<T> const &rhs) noexcept -> safe_integral<T>
    {
        return safe_integral<T>{lhs} >> rhs;
    }

    // -------------------------------------------------------------------------
    // bitwise operators
    // -------------------------------------------------------------------------

    /// <!-- description -->
    ///   @brief Returns safe_integral<T>{lhs} &= rhs
    ///   @include safe_integral/example_safe_integral_and.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the integral type to encapsulate.
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns safe_integral<T>{lhs} &= rhs
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    operator&(safe_integral<T> const &lhs, safe_integral<T> const &rhs) noexcept -> safe_integral<T>
    {
        safe_integral<T> mut_tmp{lhs};
        return mut_tmp &= rhs;
    }

    /// <!-- description -->
    ///   @brief Returns lhs & safe_integral<T>{rhs}
    ///   @include safe_integral/example_safe_integral_and.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the integral type to encapsulate.
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns lhs & safe_integral<T>{rhs}
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    operator&(safe_integral<T> const &lhs, T const rhs) noexcept -> safe_integral<T>
    {
        return lhs & safe_integral<T>{rhs};
    }

    /// <!-- description -->
    ///   @brief Returns safe_integral<T>{lhs} & rhs
    ///   @include safe_integral/example_safe_integral_and.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the integral type to encapsulate.
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns safe_integral<T>{lhs} & rhs
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    operator&(T const lhs, safe_integral<T> const &rhs) noexcept -> safe_integral<T>
    {
        return safe_integral<T>{lhs} & rhs;
    }

    /// <!-- description -->
    ///   @brief Returns safe_integral<T>{lhs} |= rhs
    ///   @include safe_integral/example_safe_integral_or.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the integral type to encapsulate.
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns safe_integral<T>{lhs} |= rhs
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    operator|(safe_integral<T> const &lhs, safe_integral<T> const &rhs) noexcept -> safe_integral<T>
    {
        safe_integral<T> mut_tmp{lhs};
        return mut_tmp |= rhs;
    }

    /// <!-- description -->
    ///   @brief Returns lhs | safe_integral<T>{rhs}
    ///   @include safe_integral/example_safe_integral_or.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the integral type to encapsulate.
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns lhs | safe_integral<T>{rhs}
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    operator|(safe_integral<T> const &lhs, T const rhs) noexcept -> safe_integral<T>
    {
        return lhs | safe_integral<T>{rhs};
    }

    /// <!-- description -->
    ///   @brief Returns safe_integral<T>{lhs} | rhs
    ///   @include safe_integral/example_safe_integral_or.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the integral type to encapsulate.
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns safe_integral<T>{lhs} | rhs
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    operator|(T const lhs, safe_integral<T> const &rhs) noexcept -> safe_integral<T>
    {
        return safe_integral<T>{lhs} | rhs;
    }

    /// <!-- description -->
    ///   @brief Returns safe_integral<T>{lhs} ^= rhs
    ///   @include safe_integral/example_safe_integral_xor.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the integral type to encapsulate.
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns safe_integral<T>{lhs} ^= rhs
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    operator^(safe_integral<T> const &lhs, safe_integral<T> const &rhs) noexcept -> safe_integral<T>
    {
        safe_integral<T> mut_tmp{lhs};
        return mut_tmp ^= rhs;
    }

    /// <!-- description -->
    ///   @brief Returns lhs ^ safe_integral<T>{rhs}
    ///   @include safe_integral/example_safe_integral_xor.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the integral type to encapsulate.
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns lhs ^ safe_integral<T>{rhs}
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    operator^(safe_integral<T> const &lhs, T const rhs) noexcept -> safe_integral<T>
    {
        return lhs ^ safe_integral<T>{rhs};
    }

    /// <!-- description -->
    ///   @brief Returns safe_integral<T>{lhs} ^ rhs
    ///   @include safe_integral/example_safe_integral_xor.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the integral type to encapsulate.
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns safe_integral<T>{lhs} ^ rhs
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    operator^(T const lhs, safe_integral<T> const &rhs) noexcept -> safe_integral<T>
    {
        return safe_integral<T>{lhs} ^ rhs;
    }

    /// <!-- description -->
    ///   @brief Returns ~rhs.
    ///   @include safe_integral/example_safe_integral_complement.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the integral type to encapsulate.
    ///   @param rhs the right hand side of the operator
    ///   @return Returns ~rhs.
    ///
    template<typename T, enable_if_t<is_unsigned<T>::value, bool> = true>
    [[nodiscard]] constexpr auto
    operator~(safe_integral<T> const &rhs) noexcept -> safe_integral<T>
    {
        return safe_integral<T>::max() ^ rhs;
    }

    // -------------------------------------------------------------------------
    // unary operators
    // -------------------------------------------------------------------------

    /// <!-- description -->
    ///   @brief Returns -rhs.
    ///   @include safe_integral/example_safe_integral_unary.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the integral type to encapsulate.
    ///   @param rhs the right hand side of the operator
    ///   @return Returns -rhs.
    ///
    template<typename T, enable_if_t<is_signed<T>::value, bool> = true>
    [[nodiscard]] constexpr auto
    operator-(safe_integral<T> const &rhs) noexcept -> safe_integral<T>
    {
        constexpr safe_integral<T> zero{static_cast<T>(0)};
        return zero - rhs;
    }

    // -------------------------------------------------------------------------
    // helpers
    // -------------------------------------------------------------------------

    /// <!-- description -->
    ///   @brief Returns safe_integral<T>{val}
    ///   @include safe_integral/example_safe_integral_make_safe.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the integral type to make safe.
    ///   @param val the integral to make safe
    ///   @return Returns safe_integral<T>{val}
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    make_safe(T const &val) noexcept -> safe_integral<T>
    {
        return safe_integral<T>{val};
    }

    // -------------------------------------------------------------------------
    // supported safe_integral types
    // -------------------------------------------------------------------------

    /// @brief provides the bsl::safe_integral version of bsl::int8
    using safe_int8 = safe_integral<bsl::int8>;
    /// @brief provides the bsl::safe_integral version of bsl::int16
    using safe_int16 = safe_integral<bsl::int16>;
    /// @brief provides the bsl::safe_integral version of bsl::int32
    using safe_int32 = safe_integral<bsl::int32>;
    /// @brief provides the bsl::safe_integral version of bsl::int64
    using safe_int64 = safe_integral<bsl::int64>;
    /// @brief provides the bsl::safe_integral version of bsl::int_fast8
    using safe_int_fast8 = safe_integral<bsl::int_fast8>;
    /// @brief provides the bsl::safe_integral version of bsl::int_fast16
    using safe_int_fast16 = safe_integral<bsl::int_fast16>;
    /// @brief provides the bsl::safe_integral version of bsl::int_fast32
    using safe_int_fast32 = safe_integral<bsl::int_fast32>;
    /// @brief provides the bsl::safe_integral version of bsl::int_fast64
    using safe_int_fast64 = safe_integral<bsl::int_fast64>;
    /// @brief provides the bsl::safe_integral version of bsl::int_least8
    using safe_int_least8 = safe_integral<bsl::int_least8>;
    /// @brief provides the bsl::safe_integral version of bsl::int_least16
    using safe_int_least16 = safe_integral<bsl::int_least16>;
    /// @brief provides the bsl::safe_integral version of bsl::int_least32
    using safe_int_least32 = safe_integral<bsl::int_least32>;
    /// @brief provides the bsl::safe_integral version of bsl::int_least64
    using safe_int_least64 = safe_integral<bsl::int_least64>;
    /// @brief provides the bsl::safe_integral version of bsl::intmax
    using safe_intmax = safe_integral<bsl::intmax>;
    /// @brief provides the bsl::safe_integral version of bsl::intptr
    using safe_intptr = safe_integral<bsl::intptr>;

    /// @brief provides the bsl::safe_integral version of bsl::uint8
    using safe_uint8 = safe_integral<bsl::uint8>;
    /// @brief provides the bsl::safe_integral version of bsl::uint16
    using safe_uint16 = safe_integral<bsl::uint16>;
    /// @brief provides the bsl::safe_integral version of bsl::uint32
    using safe_uint32 = safe_integral<bsl::uint32>;
    /// @brief provides the bsl::safe_integral version of bsl::uint64
    using safe_uint64 = safe_integral<bsl::uint64>;
    /// @brief provides the bsl::safe_integral version of bsl::uint_fast8
    using safe_uint_fast8 = safe_integral<bsl::uint_fast8>;
    /// @brief provides the bsl::safe_integral version of bsl::uint_fast16
    using safe_uint_fast16 = safe_integral<bsl::uint_fast16>;
    /// @brief provides the bsl::safe_integral version of bsl::uint_fast32
    using safe_uint_fast32 = safe_integral<bsl::uint_fast32>;
    /// @brief provides the bsl::safe_integral version of bsl::uint_fast64
    using safe_uint_fast64 = safe_integral<bsl::uint_fast64>;
    /// @brief provides the bsl::safe_integral version of bsl::uint_least8
    using safe_uint_least8 = safe_integral<bsl::uint_least8>;
    /// @brief provides the bsl::safe_integral version of bsl::uint_least16
    using safe_uint_least16 = safe_integral<bsl::uint_least16>;
    /// @brief provides the bsl::safe_integral version of bsl::uint_least32
    using safe_uint_least32 = safe_integral<bsl::uint_least32>;
    /// @brief provides the bsl::safe_integral version of bsl::uint_least64
    using safe_uint_least64 = safe_integral<bsl::uint_least64>;
    /// @brief provides the bsl::safe_integral version of bsl::uintmax
    using safe_uintmax = safe_integral<bsl::uintmax>;
    /// @brief provides the bsl::safe_integral version of bsl::uintptr
    using safe_uintptr = safe_integral<bsl::uintptr>;
}

#endif
