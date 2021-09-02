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
/// @file safe_idx.hpp
///

#ifndef BSL_SAFE_IDX_HPP
#define BSL_SAFE_IDX_HPP

#include "bsl/cstdint.hpp"    // IWYU pragma: export
#include "bsl/enable_if.hpp"
#include "bsl/integer.hpp"
#include "bsl/is_same.hpp"
#include "bsl/located_arg.hpp"    // IWYU pragma: export
#include "bsl/numeric_limits.hpp"
#include "bsl/safe_integral.hpp"
#include "bsl/touch.hpp"
#include "bsl/unlikely.hpp"

#include <bsl/assert.hpp>

namespace bsl
{
    /// <!-- description -->
    ///   @brief Used to tell the user during compile-time that a
    ///     safe_idx was poisoned.
    ///
    inline void
    a_safe_idx_was_poisoned() noexcept
    {}

    /// <!-- description -->
    ///   @brief Used to tell the user during compile-time that an
    ///     they attempted to use a safe_idx that's poisoned.
    ///
    inline void
    a_poisoned_safe_idx_was_read() noexcept
    {}

    /// @class bsl::safe_idx
    ///
    /// <!-- description -->
    ///   @brief Provides a safe implementation of an integral type that
    ///     adheres to AUTOSAR's requirement that an integral shall not
    ///     overflow, wrap, divide by zero, etc.
    ///   @include example_safe_idx_overview.hpp
    ///
    class safe_idx final
    {
        /// @brief stores the value of the integral
        // NOLINTNEXTLINE(bsl-non-safe-integral-types-are-forbidden)
        bsl::uintmx m_val;
        /// @brief stores whether or not the integral has been poisoned
        bool m_poisoned;

        /// <!-- description -->
        ///   @brief Sets the poisoned bit if poisoned is true.
        ///
        /// <!-- inputs/outputs -->
        ///   @param poisoned Sets the poisoned bit if equal to true
        ///
        constexpr void
        update_poisoned(bool const poisoned) noexcept
        {
            m_poisoned |= poisoned;
        }

        /// <!-- description -->
        ///   @brief Sets the poisoned bit if poisoned1 or poisoned2
        ///     is true.
        ///
        /// <!-- inputs/outputs -->
        ///   @param poisoned1 Sets the poisoned bit if equal to true
        ///   @param poisoned2 Sets the poisoned bit if equal to true
        ///
        constexpr void
        update_poisoned(bool const poisoned1, bool const poisoned2) noexcept
        {
            m_poisoned |= poisoned1;
            m_poisoned |= poisoned2;
        }

    public:
        /// <!-- description -->
        ///   @brief Default constructor that creates a safe_idx with
        ///     get() == 0.
        ///   @include safe_idx/example_safe_idx_default_constructor.hpp
        ///
        constexpr safe_idx() noexcept    // --
            : m_val{}, m_poisoned{}
        {}

        /// <!-- description -->
        ///   @brief Creates a bsl::safe_idx given a fixed width type
        ///   @include safe_idx/example_safe_idx_constructor_t.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam U Used to ensure the provided integer is the same as
        ///     T, effectively preventing implicit conversions from being
        ///     allowed.
        ///   @param val the value to set the bsl::safe_idx to
        ///
        template<typename U, enable_if_t<is_same<bsl::uintmx, U>::value, bool> = true>
        // NOLINTNEXTLINE(bsl-non-safe-integral-types-are-forbidden)
        explicit constexpr safe_idx(U const val) noexcept    // --
            : m_val{val}, m_poisoned{}
        {}

        /// <!-- description -->
        ///   @brief Creates a bsl::safe_idx given a fixed width type
        ///   @include safe_idx/example_safe_idx_constructor_t.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param val the value to set the bsl::safe_idx to
        ///   @param sloc the location of the call site
        ///
        explicit constexpr safe_idx(
            safe_umx const &val,
            source_location const &sloc) noexcept    // --
            : m_val{val.cdata_as_ref()}, m_poisoned{val.is_invalid()}
        {
            if (unlikely(val.is_invalid())) {
                a_safe_idx_was_poisoned();
                assert("a safe_idx was poisoned", sloc);
            }
            else {
                bsl::touch();
            }
        }

        /// <!-- description -->
        ///   @brief Destroyes a previously created bsl::safe_idx
        ///
        constexpr ~safe_idx() noexcept = default;

        /// <!-- description -->
        ///   @brief copy constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///
        constexpr safe_idx(safe_idx const &o) noexcept = default;

        /// <!-- description -->
        ///   @brief move constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_o the object being moved
        ///
        constexpr safe_idx(safe_idx &&mut_o) noexcept = default;

        /// <!-- description -->
        ///   @brief copy assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr auto operator=(safe_idx const &o) &noexcept
            -> safe_idx & = default;

        /// <!-- description -->
        ///   @brief move assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_o the object being moved
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr auto operator=(safe_idx &&mut_o) &noexcept
            -> safe_idx & = default;

        /// <!-- description -->
        ///   @brief Creates a bsl::safe_idx given a BSL fixed width
        ///     type. Note that this will clear the integral's error flag,
        ///     starting with a fresh value.
        ///   @include safe_idx/example_safe_idx_assignment_t.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam U Used to ensure the provided integer is the same as
        ///     T, effectively preventing implicit conversions from being
        ///     allowed.
        ///   @param val the value to set the bsl::safe_idx to
        ///   @return Returns *this
        ///
        template<typename U, enable_if_t<is_same<bsl::uintmx, U>::value, bool> = true>
        [[maybe_unused]] constexpr auto
        // NOLINTNEXTLINE(bsl-non-safe-integral-types-are-forbidden)
        operator=(U const val) &noexcept -> safe_idx &
        {
            *this = safe_idx{val};
            return *this;
        }

        /// <!-- description -->
        ///   @brief Returns the max value the bsl::safe_idx can store.
        ///   @include safe_idx/example_safe_idx_max_value.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the max value the bsl::safe_idx can store.
        ///
        [[nodiscard]] static constexpr auto
        max_value() noexcept -> safe_idx
        {
            return safe_idx{numeric_limits<bsl::uintmx>::max_value()};
        }

        /// <!-- description -->
        ///   @brief Returns the min value the bsl::safe_idx can store.
        ///   @include safe_idx/example_safe_idx_min_value.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the min value the bsl::safe_idx can store.
        ///
        [[nodiscard]] static constexpr auto
        min_value() noexcept -> safe_idx
        {
            return safe_idx{numeric_limits<bsl::uintmx>::min_value()};
        }

        /// <!-- description -->
        ///   @brief Returns safe_idx{0}
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns safe_idx{0}
        ///
        [[nodiscard]] static constexpr auto
        magic_0() noexcept -> safe_idx
        {
            return safe_idx{static_cast<bsl::uintmx>(0)};
        }

        /// <!-- description -->
        ///   @brief Returns safe_idx{1}
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns safe_idx{1}
        ///
        [[nodiscard]] static constexpr auto
        magic_1() noexcept -> safe_idx
        {
            return safe_idx{static_cast<bsl::uintmx>(1)};
        }

        /// <!-- description -->
        ///   @brief Returns safe_idx{2}
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns safe_idx{2}
        ///
        [[nodiscard]] static constexpr auto
        magic_2() noexcept -> safe_idx
        {
            return safe_idx{static_cast<bsl::uintmx>(2)};
        }

        /// <!-- description -->
        ///   @brief Returns safe_idx{3}
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns safe_idx{3}
        ///
        [[nodiscard]] static constexpr auto
        magic_3() noexcept -> safe_idx
        {
            return safe_idx{static_cast<bsl::uintmx>(3)};
        }

        /// <!-- description -->
        ///   @brief Returns a reference to the internal integral being managed
        ///     by this class, providing a means to directly read/write the
        ///     integral's value.
        ///   @include safe_idx/example_safe_idx_data.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a reference to the internal integral being managed
        ///     by this class, providing a means to directly read/write the
        ///     integral's value.
        ///
        [[nodiscard]] constexpr auto
        data_as_ref() noexcept -> bsl::uintmx &
        {
            return m_val;
        }

        /// <!-- description -->
        ///   @brief Returns a reference to the internal integral being managed
        ///     by this class, providing a means to directly read/write the
        ///     integral's value.
        ///   @include safe_idx/example_safe_idx_data.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a reference to the internal integral being managed
        ///     by this class, providing a means to directly read/write the
        ///     integral's value.
        ///
        [[nodiscard]] constexpr auto
        data_as_ref() const noexcept -> bsl::uintmx const &
        {
            return m_val;
        }

        /// <!-- description -->
        ///   @brief Returns a reference to the internal integral being managed
        ///     by this class, providing a means to directly read/write the
        ///     integral's value.
        ///   @include safe_idx/example_safe_idx_data.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a reference to the internal integral being managed
        ///     by this class, providing a means to directly read/write the
        ///     integral's value.
        ///
        [[nodiscard]] constexpr auto
        cdata_as_ref() const noexcept -> bsl::uintmx const &
        {
            return m_val;
        }

        /// <!-- description -->
        ///   @brief Returns a pointer to the internal integral being managed
        ///     by this class, providing a means to directly read/write the
        ///     integral's value.
        ///   @include safe_idx/example_safe_idx_data.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a pointer to the internal integral being managed
        ///     by this class, providing a means to directly read/write the
        ///     integral's value.
        ///
        [[nodiscard]] constexpr auto
        data() noexcept -> bsl::uintmx *
        {
            return &m_val;
        }

        /// <!-- description -->
        ///   @brief Returns a pointer to the internal integral being managed
        ///     by this class, providing a means to directly read/write the
        ///     integral's value.
        ///   @include safe_idx/example_safe_idx_data.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a pointer to the internal integral being managed
        ///     by this class, providing a means to directly read/write the
        ///     integral's value.
        ///
        [[nodiscard]] constexpr auto
        data() const noexcept -> bsl::uintmx const *
        {
            return &m_val;
        }

        /// <!-- description -->
        ///   @brief Returns a pointer to the internal integral being managed
        ///     by this class, providing a means to directly read/write the
        ///     integral's value.
        ///   @include safe_idx/example_safe_idx_data.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a pointer to the internal integral being managed
        ///     by this class, providing a means to directly read/write the
        ///     integral's value.
        ///
        [[nodiscard]] constexpr auto
        cdata() const noexcept -> bsl::uintmx const *
        {
            return &m_val;
        }

        /// <!-- description -->
        ///   @brief Returns the value stored by the bsl::safe_idx.
        ///     Attempting to get the value of an invalid safe_idx
        ///     results in undefined behavior.
        ///   @include safe_idx/example_safe_idx_get.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param sloc the location of the call site
        ///   @return Returns the value stored by the bsl::safe_idx.
        ///     Attempting to get the value of an invalid safe_idx
        ///     results in undefined behavior.
        ///
        [[nodiscard]] constexpr auto
        get(source_location const &sloc = here()) const noexcept -> bsl::uintmx
        {
            if (unlikely(m_poisoned)) {
                a_poisoned_safe_idx_was_read();
                assert("a poisoned safe_idx was read", sloc);
            }
            else {
                bsl::touch();
            }

            return m_val;
        }

        /// <!-- description -->
        ///   @brief Returns true if the safe_idx is positive.
        ///     Attempting to run is_pos on an invalid safe_idx
        ///     results in undefined behavior.
        ///   @include safe_idx/example_safe_idx_is_pos.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param sloc the location of the call site
        ///   @return Returns true if the safe_idx is positive
        ///
        [[nodiscard]] constexpr auto
        is_pos(source_location const &sloc = here()) const noexcept -> bool
        {
            if (unlikely(m_poisoned)) {
                a_poisoned_safe_idx_was_read();
                assert("a poisoned safe_idx was read", sloc);
            }
            else {
                bsl::touch();
            }

            // NOLINTNEXTLINE(bsl-implicit-conversions-forbidden, bsl-types-fixed-width-ints-arithmetic-check)
            return m_val > 0;
        }

        /// <!-- description -->
        ///   @brief Returns true if the safe_idx is 0.
        ///     Attempting to run is_zero on an invalid safe_idx
        ///     results in undefined behavior.
        ///   @include safe_idx/example_safe_idx_is_zero.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param sloc the location of the call site
        ///   @return Returns true if the safe_idx is 0
        ///
        [[nodiscard]] constexpr auto
        is_zero(source_location const &sloc = here()) const noexcept -> bool
        {
            if (unlikely(m_poisoned)) {
                a_poisoned_safe_idx_was_read();
                assert("a poisoned safe_idx was read", sloc);
            }
            else {
                bsl::touch();
            }

            // NOLINTNEXTLINE(bsl-implicit-conversions-forbidden, bsl-types-fixed-width-ints-arithmetic-check)
            return 0 == m_val;
        }

        /// <!-- description -->
        ///   @brief Returns true if the safe_idx has encountered and
        ///     error, false otherwise. This function DOES NOT marked the
        ///     safe_idx as checked.
        ///   @include safe_idx/example_safe_idx_is_invalid.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if the safe_idx has encountered and
        ///     error, false otherwise. This function DOES NOT marked the
        ///     safe_idx as checked.
        ///
        [[nodiscard]] constexpr auto
        is_invalid() const noexcept -> bool
        {
            return m_poisoned;
        }

        /// <!-- description -->
        ///   @brief Returns !this->is_invalid().
        ///   @include safe_idx/example_safe_idx_is_valid.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns !this->is_invalid()
        ///
        [[nodiscard]] constexpr auto
        is_valid() const noexcept -> bool
        {
            return !this->is_invalid();
        }

        /// <!-- description -->
        ///   @brief Returns *this += rhs. If this operation results in
        ///     an error (e.g., overflow, wrapping, etc.), the result of
        ///     this operation is undefined.
        ///   @include safe_idx/example_safe_idx_assign_add.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param rhs the value to add to *this
        ///   @return Returns *this += rhs. If this operation results in
        ///     an error (e.g., overflow, wrapping, etc.), the result of
        ///     this operation is undefined.
        ///
        [[maybe_unused]] constexpr auto
        operator+=(safe_idx const &rhs) &noexcept -> safe_idx &
        {
            bool const poisoned{builtin_add_overflow(m_val, rhs.m_val, &m_val)};
            this->update_poisoned(poisoned, rhs.is_invalid());

            return *this;
        }

        /// <!-- description -->
        ///   @brief Returns *this += rhs. If this operation results in
        ///     an error (e.g., overflow, wrapping, etc.), the result of
        ///     this operation is undefined.
        ///   @include safe_idx/example_safe_idx_assign_add.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam U Used to ensure the provided integer is the same as
        ///     T, effectively preventing implicit conversions from being
        ///     allowed.
        ///   @param rhs the value to add to *this
        ///   @return Returns *this += rhs. If this operation results in
        ///     an error (e.g., overflow, wrapping, etc.), the result of
        ///     this operation is undefined.
        ///
        template<typename U, enable_if_t<is_same<bsl::uintmx, U>::value, bool> = true>
        [[maybe_unused]] constexpr auto
        // NOLINTNEXTLINE(bsl-non-safe-integral-types-are-forbidden)
        operator+=(U const rhs) &noexcept -> safe_idx &
        {
            this->update_poisoned(builtin_add_overflow(m_val, rhs, &m_val));
            return *this;
        }

        /// <!-- description -->
        ///   @brief Returns *this -= rhs. If this operation results in
        ///     an error (e.g., overflow, wrapping, etc.), the result of
        ///     this operation is undefined.
        ///   @include safe_idx/example_safe_idx_assign_sub.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param rhs the value to sub from *this
        ///   @return Returns *this -= rhs. If this operation results in
        ///     an error (e.g., overflow, wrapping, etc.), the result of
        ///     this operation is undefined.
        ///
        [[maybe_unused]] constexpr auto
        operator-=(safe_idx const &rhs) &noexcept -> safe_idx &
        {
            bool const poisoned{builtin_sub_overflow(m_val, rhs.m_val, &m_val)};
            this->update_poisoned(poisoned, rhs.is_invalid());

            return *this;
        }

        /// <!-- description -->
        ///   @brief Returns *this -= rhs. If this operation results in
        ///     an error (e.g., overflow, wrapping, etc.), the result of
        ///     this operation is undefined.
        ///   @include safe_idx/example_safe_idx_assign_sub.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam U Used to ensure the provided integer is the same as
        ///     T, effectively preventing implicit conversions from being
        ///     allowed.
        ///   @param rhs the value to sub from *this
        ///   @return Returns *this -= rhs. If this operation results in
        ///     an error (e.g., overflow, wrapping, etc.), the result of
        ///     this operation is undefined.
        ///
        template<typename U, enable_if_t<is_same<bsl::uintmx, U>::value, bool> = true>
        [[maybe_unused]] constexpr auto
        // NOLINTNEXTLINE(bsl-non-safe-integral-types-are-forbidden)
        operator-=(U const rhs) &noexcept -> safe_idx &
        {
            this->update_poisoned(builtin_sub_overflow(m_val, rhs, &m_val));
            return *this;
        }

        /// <!-- description -->
        ///   @brief Returns ++(*this). If this operation results in
        ///     an error (e.g., overflow, wrapping, etc.), the result of
        ///     this operation is undefined.
        ///   @include safe_idx/example_safe_idx_inc.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns ++(*this). If this operation results in
        ///     an error (e.g., overflow, wrapping, etc.), the result of
        ///     this operation is undefined.
        ///
        [[maybe_unused]] constexpr auto
        operator++() &noexcept -> safe_idx &
        {
            return *this += static_cast<bsl::uintmx>(1);
        }

        /// <!-- description -->
        ///   @brief Returns --(*this). If this operation results in
        ///     an error (e.g., overflow, wrapping, etc.), the result of
        ///     this operation is undefined.
        ///   @include safe_idx/example_safe_idx_dec.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns --(*this). If this operation results in
        ///     an error (e.g., overflow, wrapping, etc.), the result of
        ///     this operation is undefined.
        ///
        [[maybe_unused]] constexpr auto
        operator--() &noexcept -> safe_idx &
        {
            return *this -= static_cast<bsl::uintmx>(1);
        }
    };

    // -------------------------------------------------------------------------
    // safe_idx rational operators
    // -------------------------------------------------------------------------

    /// <!-- description -->
    ///   @brief Returns lhs.get() == rhs.get()
    ///   @include safe_idx/example_safe_idx_equals.hpp
    ///   @related bsl::safe_idx
    ///
    /// <!-- inputs/outputs -->
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns lhs.get() == rhs.get()
    ///
    [[nodiscard]] constexpr auto
    operator==(located_arg<safe_idx> const &lhs, located_arg<safe_idx> const &rhs) noexcept -> bool
    {
        // NOLINTNEXTLINE(bsl-implicit-conversions-forbidden)
        return lhs.get().get(lhs.sloc()) == rhs.get().get(rhs.sloc());
    }

    /// <!-- description -->
    ///   @brief Returns lhs.get() == rhs.get()
    ///   @include safe_idx/example_safe_idx_equals.hpp
    ///   @related bsl::safe_idx
    ///
    /// <!-- inputs/outputs -->
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns lhs.get() == rhs.get()
    ///
    [[nodiscard]] constexpr auto
    operator==(located_arg<safe_idx> const &lhs, located_arg<safe_umx> const &rhs) noexcept -> bool
    {
        // NOLINTNEXTLINE(bsl-implicit-conversions-forbidden)
        return lhs.get().get(lhs.sloc()) == rhs.get().get(rhs.sloc());
    }

    /// <!-- description -->
    ///   @brief Returns lhs.get() == rhs.get()
    ///   @include safe_idx/example_safe_idx_equals.hpp
    ///   @related bsl::safe_idx
    ///
    /// <!-- inputs/outputs -->
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns lhs.get() == rhs.get()
    ///
    [[nodiscard]] constexpr auto
    operator==(located_arg<safe_umx> const &lhs, located_arg<safe_idx> const &rhs) noexcept -> bool
    {
        // NOLINTNEXTLINE(bsl-implicit-conversions-forbidden)
        return lhs.get().get(lhs.sloc()) == rhs.get().get(rhs.sloc());
    }

    /// <!-- description -->
    ///   @brief Returns lhs == safe_idx{rhs}
    ///   @include safe_idx/example_safe_idx_equals.hpp
    ///   @related bsl::safe_idx
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam U Used to ensure the provided integer is the same as
    ///     T, effectively preventing implicit conversions from being
    ///     allowed.
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns lhs == safe_idx{rhs}
    ///
    template<typename U, enable_if_t<is_same<bsl::uintmx, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-non-safe-integral-types-are-forbidden)
    operator==(located_arg<safe_idx> const &lhs, U const rhs) noexcept -> bool
    {
        // NOLINTNEXTLINE(bsl-implicit-conversions-forbidden)
        return lhs.get().get(lhs.sloc()) == rhs;
    }

    /// <!-- description -->
    ///   @brief Returns safe_idx{lhs} == rhs
    ///   @include safe_idx/example_safe_idx_equals.hpp
    ///   @related bsl::safe_idx
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam U Used to ensure the provided integer is the same as
    ///     T, effectively preventing implicit conversions from being
    ///     allowed.
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns safe_idx{lhs} == rhs
    ///
    template<typename U, enable_if_t<is_same<bsl::uintmx, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-non-safe-integral-types-are-forbidden)
    operator==(U const lhs, located_arg<safe_idx> const &rhs) noexcept -> bool
    {
        // NOLINTNEXTLINE(bsl-implicit-conversions-forbidden)
        return lhs == rhs.get().get(rhs.sloc());
    }

    /// <!-- description -->
    ///   @brief Returns !(lhs == rhs)
    ///   @include safe_idx/example_safe_idx_not_equals.hpp
    ///   @related bsl::safe_idx
    ///
    /// <!-- inputs/outputs -->
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns !(lhs == rhs)
    ///
    [[nodiscard]] constexpr auto
    operator!=(located_arg<safe_idx> const &lhs, located_arg<safe_idx> const &rhs) noexcept -> bool
    {
        return !(lhs == rhs);
    }

    /// <!-- description -->
    ///   @brief Returns !(lhs == rhs)
    ///   @include safe_idx/example_safe_idx_not_equals.hpp
    ///   @related bsl::safe_idx
    ///
    /// <!-- inputs/outputs -->
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns !(lhs == rhs)
    ///
    [[nodiscard]] constexpr auto
    operator!=(located_arg<safe_idx> const &lhs, located_arg<safe_umx> const &rhs) noexcept -> bool
    {
        return !(lhs == rhs);
    }

    /// <!-- description -->
    ///   @brief Returns !(lhs == rhs)
    ///   @include safe_idx/example_safe_idx_not_equals.hpp
    ///   @related bsl::safe_idx
    ///
    /// <!-- inputs/outputs -->
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns !(lhs == rhs)
    ///
    [[nodiscard]] constexpr auto
    operator!=(located_arg<safe_umx> const &lhs, located_arg<safe_idx> const &rhs) noexcept -> bool
    {
        return !(lhs == rhs);
    }

    /// <!-- description -->
    ///   @brief Returns !(lhs == rhs)
    ///   @include safe_idx/example_safe_idx_not_equals.hpp
    ///   @related bsl::safe_idx
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam U Used to ensure the provided integer is the same as
    ///     T, effectively preventing implicit conversions from being
    ///     allowed.
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns !(lhs == rhs)
    ///
    template<typename U, enable_if_t<is_same<bsl::uintmx, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-non-safe-integral-types-are-forbidden)
    operator!=(located_arg<safe_idx> const &lhs, U const rhs) noexcept -> bool
    {
        return !(lhs == rhs);
    }

    /// <!-- description -->
    ///   @brief Returns !(lhs == rhs)
    ///   @include safe_idx/example_safe_idx_not_equals.hpp
    ///   @related bsl::safe_idx
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam U Used to ensure the provided integer is the same as
    ///     T, effectively preventing implicit conversions from being
    ///     allowed.
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns !(lhs == rhs)
    ///
    template<typename U, enable_if_t<is_same<bsl::uintmx, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-non-safe-integral-types-are-forbidden)
    operator!=(U const lhs, located_arg<safe_idx> const &rhs) noexcept -> bool
    {
        return !(lhs == rhs);
    }

    /// <!-- description -->
    ///   @brief Returns lhs.get() < rhs.get()
    ///   @include safe_idx/example_safe_idx_lt.hpp
    ///   @related bsl::safe_idx
    ///
    /// <!-- inputs/outputs -->
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns lhs.get() < rhs.get()
    ///
    [[nodiscard]] constexpr auto
    operator<(located_arg<safe_idx> const &lhs, located_arg<safe_idx> const &rhs) noexcept -> bool
    {
        // NOLINTNEXTLINE(bsl-implicit-conversions-forbidden, bsl-types-fixed-width-ints-arithmetic-check)
        return lhs.get().get(lhs.sloc()) < rhs.get().get(rhs.sloc());
    }

    /// <!-- description -->
    ///   @brief Returns lhs < safe_idx{rhs}
    ///   @include safe_idx/example_safe_idx_lt.hpp
    ///   @related bsl::safe_idx
    ///
    /// <!-- inputs/outputs -->
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns lhs < safe_idx{rhs}
    ///
    [[nodiscard]] constexpr auto
    operator<(located_arg<safe_idx> const &lhs, located_arg<safe_umx> const &rhs) noexcept -> bool
    {
        // NOLINTNEXTLINE(bsl-implicit-conversions-forbidden, bsl-types-fixed-width-ints-arithmetic-check)
        return lhs.get().get(lhs.sloc()) < rhs.get().get(rhs.sloc());
    }

    /// <!-- description -->
    ///   @brief Returns safe_idx{lhs} < rhs
    ///   @include safe_idx/example_safe_idx_lt.hpp
    ///   @related bsl::safe_idx
    ///
    /// <!-- inputs/outputs -->
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns safe_idx{lhs} < rhs
    ///
    [[nodiscard]] constexpr auto
    operator<(located_arg<safe_umx> const &lhs, located_arg<safe_idx> const &rhs) noexcept -> bool
    {
        // NOLINTNEXTLINE(bsl-implicit-conversions-forbidden, bsl-types-fixed-width-ints-arithmetic-check)
        return lhs.get().get(lhs.sloc()) < rhs.get().get(rhs.sloc());
    }

    /// <!-- description -->
    ///   @brief Returns lhs < safe_idx{rhs}
    ///   @include safe_idx/example_safe_idx_lt.hpp
    ///   @related bsl::safe_idx
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam U Used to ensure the provided integer is the same as
    ///     T, effectively preventing implicit conversions from being
    ///     allowed.
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns lhs < safe_idx{rhs}
    ///
    template<typename U, enable_if_t<is_same<bsl::uintmx, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-non-safe-integral-types-are-forbidden)
    operator<(located_arg<safe_idx> const &lhs, U const rhs) noexcept -> bool
    {
        // NOLINTNEXTLINE(bsl-implicit-conversions-forbidden, bsl-types-fixed-width-ints-arithmetic-check)
        return lhs.get().get(lhs.sloc()) < rhs;
    }

    /// <!-- description -->
    ///   @brief Returns safe_idx{lhs} < rhs
    ///   @include safe_idx/example_safe_idx_lt.hpp
    ///   @related bsl::safe_idx
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam U Used to ensure the provided integer is the same as
    ///     T, effectively preventing implicit conversions from being
    ///     allowed.
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns safe_idx{lhs} < rhs
    ///
    template<typename U, enable_if_t<is_same<bsl::uintmx, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-non-safe-integral-types-are-forbidden)
    operator<(U const lhs, located_arg<safe_idx> const &rhs) noexcept -> bool
    {
        // NOLINTNEXTLINE(bsl-implicit-conversions-forbidden, bsl-types-fixed-width-ints-arithmetic-check)
        return lhs < rhs.get().get(rhs.sloc());
    }

    /// <!-- description -->
    ///   @brief Returns lhs.get() > rhs.get()
    ///   @include safe_idx/example_safe_idx_gt.hpp
    ///   @related bsl::safe_idx
    ///
    /// <!-- inputs/outputs -->
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns lhs.get() > rhs.get()
    ///
    [[nodiscard]] constexpr auto
    operator>(located_arg<safe_idx> const &lhs, located_arg<safe_idx> const &rhs) noexcept -> bool
    {
        // NOLINTNEXTLINE(bsl-implicit-conversions-forbidden, bsl-types-fixed-width-ints-arithmetic-check)
        return lhs.get().get(lhs.sloc()) > rhs.get().get(rhs.sloc());
    }

    /// <!-- description -->
    ///   @brief Returns lhs > safe_idx{rhs}
    ///   @include safe_idx/example_safe_idx_gt.hpp
    ///   @related bsl::safe_idx
    ///
    /// <!-- inputs/outputs -->
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns lhs > safe_idx{rhs}
    ///
    [[nodiscard]] constexpr auto
    operator>(located_arg<safe_idx> const &lhs, located_arg<safe_umx> const &rhs) noexcept -> bool
    {
        // NOLINTNEXTLINE(bsl-implicit-conversions-forbidden, bsl-types-fixed-width-ints-arithmetic-check)
        return lhs.get().get(lhs.sloc()) > rhs.get().get(rhs.sloc());
    }

    /// <!-- description -->
    ///   @brief Returns safe_idx{lhs} > rhs
    ///   @include safe_idx/example_safe_idx_gt.hpp
    ///   @related bsl::safe_idx
    ///
    /// <!-- inputs/outputs -->
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns safe_idx{lhs} > rhs
    ///
    [[nodiscard]] constexpr auto
    operator>(located_arg<safe_umx> const &lhs, located_arg<safe_idx> const &rhs) noexcept -> bool
    {
        // NOLINTNEXTLINE(bsl-implicit-conversions-forbidden, bsl-types-fixed-width-ints-arithmetic-check)
        return lhs.get().get(lhs.sloc()) > rhs.get().get(rhs.sloc());
    }

    /// <!-- description -->
    ///   @brief Returns lhs > safe_idx{rhs}
    ///   @include safe_idx/example_safe_idx_gt.hpp
    ///   @related bsl::safe_idx
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam U Used to ensure the provided integer is the same as
    ///     T, effectively preventing implicit conversions from being
    ///     allowed.
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns lhs > safe_idx{rhs}
    ///
    template<typename U, enable_if_t<is_same<bsl::uintmx, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-non-safe-integral-types-are-forbidden)
    operator>(located_arg<safe_idx> const &lhs, U const rhs) noexcept -> bool
    {
        // NOLINTNEXTLINE(bsl-implicit-conversions-forbidden, bsl-types-fixed-width-ints-arithmetic-check)
        return lhs.get().get(lhs.sloc()) > rhs;
    }

    /// <!-- description -->
    ///   @brief Returns safe_idx{lhs} > rhs
    ///   @include safe_idx/example_safe_idx_gt.hpp
    ///   @related bsl::safe_idx
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam U Used to ensure the provided integer is the same as
    ///     T, effectively preventing implicit conversions from being
    ///     allowed.
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns safe_idx{lhs} > rhs
    ///
    template<typename U, enable_if_t<is_same<bsl::uintmx, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-non-safe-integral-types-are-forbidden)
    operator>(U const lhs, located_arg<safe_idx> const &rhs) noexcept -> bool
    {
        // NOLINTNEXTLINE(bsl-implicit-conversions-forbidden, bsl-types-fixed-width-ints-arithmetic-check)
        return lhs > rhs.get().get(rhs.sloc());
    }

    /// <!-- description -->
    ///   @brief Returns lhs.get() <= rhs.get()
    ///   @include safe_idx/example_safe_idx_lt.hpp
    ///   @related bsl::safe_idx
    ///
    /// <!-- inputs/outputs -->
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns lhs.get() <= rhs.get()
    ///
    [[nodiscard]] constexpr auto
    operator<=(located_arg<safe_idx> const &lhs, located_arg<safe_idx> const &rhs) noexcept -> bool
    {
        // NOLINTNEXTLINE(bsl-implicit-conversions-forbidden, bsl-types-fixed-width-ints-arithmetic-check)
        return lhs.get().get(lhs.sloc()) <= rhs.get().get(rhs.sloc());
    }

    /// <!-- description -->
    ///   @brief Returns lhs <= safe_idx{rhs}
    ///   @include safe_idx/example_safe_idx_lt.hpp
    ///   @related bsl::safe_idx
    ///
    /// <!-- inputs/outputs -->
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns lhs <= safe_idx{rhs}
    ///
    [[nodiscard]] constexpr auto
    operator<=(located_arg<safe_idx> const &lhs, located_arg<safe_umx> const &rhs) noexcept -> bool
    {
        // NOLINTNEXTLINE(bsl-implicit-conversions-forbidden, bsl-types-fixed-width-ints-arithmetic-check)
        return lhs.get().get(lhs.sloc()) <= rhs.get().get(rhs.sloc());
    }

    /// <!-- description -->
    ///   @brief Returns safe_idx{lhs} <= rhs
    ///   @include safe_idx/example_safe_idx_lt.hpp
    ///   @related bsl::safe_idx
    ///
    /// <!-- inputs/outputs -->
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns safe_idx{lhs} <= rhs
    ///
    [[nodiscard]] constexpr auto
    operator<=(located_arg<safe_umx> const &lhs, located_arg<safe_idx> const &rhs) noexcept -> bool
    {
        // NOLINTNEXTLINE(bsl-implicit-conversions-forbidden, bsl-types-fixed-width-ints-arithmetic-check)
        return lhs.get().get(lhs.sloc()) <= rhs.get().get(rhs.sloc());
    }

    /// <!-- description -->
    ///   @brief Returns lhs <= safe_idx{rhs}
    ///   @include safe_idx/example_safe_idx_lt.hpp
    ///   @related bsl::safe_idx
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam U Used to ensure the provided integer is the same as
    ///     T, effectively preventing implicit conversions from being
    ///     allowed.
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns lhs <= safe_idx{rhs}
    ///
    template<typename U, enable_if_t<is_same<bsl::uintmx, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-non-safe-integral-types-are-forbidden)
    operator<=(located_arg<safe_idx> const &lhs, U const rhs) noexcept -> bool
    {
        // NOLINTNEXTLINE(bsl-implicit-conversions-forbidden, bsl-types-fixed-width-ints-arithmetic-check)
        return lhs.get().get(lhs.sloc()) <= rhs;
    }

    /// <!-- description -->
    ///   @brief Returns safe_idx{lhs} <= rhs
    ///   @include safe_idx/example_safe_idx_lt.hpp
    ///   @related bsl::safe_idx
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam U Used to ensure the provided integer is the same as
    ///     T, effectively preventing implicit conversions from being
    ///     allowed.
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns safe_idx{lhs} <= rhs
    ///
    template<typename U, enable_if_t<is_same<bsl::uintmx, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-non-safe-integral-types-are-forbidden)
    operator<=(U const lhs, located_arg<safe_idx> const &rhs) noexcept -> bool
    {
        // NOLINTNEXTLINE(bsl-implicit-conversions-forbidden, bsl-types-fixed-width-ints-arithmetic-check)
        return lhs <= rhs.get().get(rhs.sloc());
    }

    /// <!-- description -->
    ///   @brief Returns lhs.get() >= rhs.get()
    ///   @include safe_idx/example_safe_idx_gt.hpp
    ///   @related bsl::safe_idx
    ///
    /// <!-- inputs/outputs -->
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns lhs.get() >= rhs.get()
    ///
    [[nodiscard]] constexpr auto
    operator>=(located_arg<safe_idx> const &lhs, located_arg<safe_idx> const &rhs) noexcept -> bool
    {
        // NOLINTNEXTLINE(bsl-implicit-conversions-forbidden, bsl-types-fixed-width-ints-arithmetic-check)
        return lhs.get().get(lhs.sloc()) >= rhs.get().get(rhs.sloc());
    }

    /// <!-- description -->
    ///   @brief Returns lhs <= safe_idx{rhs}
    ///   @include safe_idx/example_safe_idx_gt.hpp
    ///   @related bsl::safe_idx
    ///
    /// <!-- inputs/outputs -->
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns lhs <= safe_idx{rhs}
    ///
    [[nodiscard]] constexpr auto
    operator>=(located_arg<safe_idx> const &lhs, located_arg<safe_umx> const &rhs) noexcept -> bool
    {
        // NOLINTNEXTLINE(bsl-implicit-conversions-forbidden, bsl-types-fixed-width-ints-arithmetic-check)
        return lhs.get().get(lhs.sloc()) >= rhs.get().get(rhs.sloc());
    }

    /// <!-- description -->
    ///   @brief Returns safe_idx{lhs} <= rhs
    ///   @include safe_idx/example_safe_idx_gt.hpp
    ///   @related bsl::safe_idx
    ///
    /// <!-- inputs/outputs -->
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns safe_idx{lhs} <= rhs
    ///
    [[nodiscard]] constexpr auto
    operator>=(located_arg<safe_umx> const &lhs, located_arg<safe_idx> const &rhs) noexcept -> bool
    {
        // NOLINTNEXTLINE(bsl-implicit-conversions-forbidden, bsl-types-fixed-width-ints-arithmetic-check)
        return lhs.get().get(lhs.sloc()) >= rhs.get().get(rhs.sloc());
    }

    /// <!-- description -->
    ///   @brief Returns lhs <= safe_idx{rhs}
    ///   @include safe_idx/example_safe_idx_gt.hpp
    ///   @related bsl::safe_idx
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam U Used to ensure the provided integer is the same as
    ///     T, effectively preventing implicit conversions from being
    ///     allowed.
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns lhs <= safe_idx{rhs}
    ///
    template<typename U, enable_if_t<is_same<bsl::uintmx, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-non-safe-integral-types-are-forbidden)
    operator>=(located_arg<safe_idx> const &lhs, U const rhs) noexcept -> bool
    {
        // NOLINTNEXTLINE(bsl-implicit-conversions-forbidden, bsl-types-fixed-width-ints-arithmetic-check)
        return lhs.get().get(lhs.sloc()) >= rhs;
    }

    /// <!-- description -->
    ///   @brief Returns safe_idx{lhs} <= rhs
    ///   @include safe_idx/example_safe_idx_gt.hpp
    ///   @related bsl::safe_idx
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam U Used to ensure the provided integer is the same as
    ///     T, effectively preventing implicit conversions from being
    ///     allowed.
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns safe_idx{lhs} <= rhs
    ///
    template<typename U, enable_if_t<is_same<bsl::uintmx, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-non-safe-integral-types-are-forbidden)
    operator>=(U const lhs, located_arg<safe_idx> const &rhs) noexcept -> bool
    {
        // NOLINTNEXTLINE(bsl-implicit-conversions-forbidden, bsl-types-fixed-width-ints-arithmetic-check)
        return lhs >= rhs.get().get(rhs.sloc());
    }

    // -------------------------------------------------------------------------
    // safe_idx arithmetic operators
    // -------------------------------------------------------------------------

    /// <!-- description -->
    ///   @brief Returns safe_idx{lhs} += rhs
    ///   @include safe_idx/example_safe_idx_add.hpp
    ///   @related bsl::safe_idx
    ///
    /// <!-- inputs/outputs -->
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns safe_idx{lhs} += rhs
    ///
    [[nodiscard]] constexpr auto
    operator+(safe_idx const &lhs, safe_idx const &rhs) noexcept -> safe_idx
    {
        safe_idx mut_tmp{lhs};
        return mut_tmp += rhs;
    }

    /// <!-- description -->
    ///   @brief Returns lhs + safe_idx{rhs}
    ///   @include safe_idx/example_safe_idx_add.hpp
    ///   @related bsl::safe_idx
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam U Used to ensure the provided integer is the same as
    ///     T, effectively preventing implicit conversions from being
    ///     allowed.
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns lhs + safe_idx{rhs}
    ///
    template<typename U, enable_if_t<is_same<bsl::uintmx, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-non-safe-integral-types-are-forbidden)
    operator+(safe_idx const &lhs, U const rhs) noexcept -> safe_idx
    {
        return lhs + safe_idx{rhs};
    }

    /// <!-- description -->
    ///   @brief Returns safe_idx{lhs} + rhs
    ///   @include safe_idx/example_safe_idx_add.hpp
    ///   @related bsl::safe_idx
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam U Used to ensure the provided integer is the same as
    ///     T, effectively preventing implicit conversions from being
    ///     allowed.
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns safe_idx{lhs} + rhs
    ///
    template<typename U, enable_if_t<is_same<bsl::uintmx, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-non-safe-integral-types-are-forbidden)
    operator+(U const lhs, safe_idx const &rhs) noexcept -> safe_idx
    {
        return safe_idx{lhs} + rhs;
    }

    /// <!-- description -->
    ///   @brief Returns safe_idx{lhs} -= rhs
    ///   @include safe_idx/example_safe_idx_sub.hpp
    ///   @related bsl::safe_idx
    ///
    /// <!-- inputs/outputs -->
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns safe_idx{lhs} -= rhs
    ///
    [[nodiscard]] constexpr auto
    operator-(safe_idx const &lhs, safe_idx const &rhs) noexcept -> safe_idx
    {
        safe_idx mut_tmp{lhs};
        return mut_tmp -= rhs;
    }

    /// <!-- description -->
    ///   @brief Returns lhs - safe_idx{rhs}
    ///   @include safe_idx/example_safe_idx_sub.hpp
    ///   @related bsl::safe_idx
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam U Used to ensure the provided integer is the same as
    ///     T, effectively preventing implicit conversions from being
    ///     allowed.
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns lhs - safe_idx{rhs}
    ///
    template<typename U, enable_if_t<is_same<bsl::uintmx, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-non-safe-integral-types-are-forbidden)
    operator-(safe_idx const &lhs, U const rhs) noexcept -> safe_idx
    {
        return lhs - safe_idx{rhs};
    }

    /// <!-- description -->
    ///   @brief Returns safe_idx{lhs} - rhs
    ///   @include safe_idx/example_safe_idx_sub.hpp
    ///   @related bsl::safe_idx
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam U Used to ensure the provided integer is the same as
    ///     T, effectively preventing implicit conversions from being
    ///     allowed.
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns safe_idx{lhs} - rhs
    ///
    template<typename U, enable_if_t<is_same<bsl::uintmx, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-non-safe-integral-types-are-forbidden)
    operator-(U const lhs, safe_idx const &rhs) noexcept -> safe_idx
    {
        return safe_idx{lhs} - rhs;
    }
}

#endif
