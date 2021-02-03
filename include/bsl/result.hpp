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
/// @file result.hpp
///

#ifndef BSL_RESULT_HPP
#define BSL_RESULT_HPP

#include "conjunction.hpp"
#include "construct_at.hpp"
#include "debug.hpp"
#include "destroy_at.hpp"
#include "details/out.hpp"
#include "details/result_type.hpp"
#include "errc_type.hpp"
#include "in_place_t.hpp"
#include "is_nothrow_constructible.hpp"
#include "is_nothrow_copy_assignable.hpp"
#include "is_nothrow_copy_constructible.hpp"
#include "is_nothrow_default_constructible.hpp"
#include "is_nothrow_destructible.hpp"
#include "is_nothrow_move_assignable.hpp"
#include "is_nothrow_move_constructible.hpp"
#include "is_nothrow_swappable.hpp"
#include "is_same.hpp"
#include "likely.hpp"
#include "move.hpp"
#include "swap.hpp"

namespace bsl
{
    /// @class bsl::result
    ///
    /// <!-- description -->
    ///   @brief Provides the ability to return T or E from a function,
    ///     ensuring that T is only created if an error is not present.
    ///   @include example_result_overview.hpp
    ///
    /// <!-- template parameters -->
    ///   @tparam T the nullable type
    ///   @tparam E the error type to use
    ///
    template<typename T, typename E = errc_type>
    class result final
    {
        static_assert(!is_same<T, E>::value);
        static_assert(is_nothrow_copy_constructible<E>::value);
        static_assert(is_nothrow_copy_assignable<E>::value);
        static_assert(is_nothrow_destructible<E>::value);
        static_assert(is_nothrow_move_constructible<E>::value);
        static_assert(is_nothrow_move_assignable<E>::value);

        /// <!-- description -->
        ///   @brief Swaps *this with other
        ///
        /// <!-- inputs/outputs -->
        ///   @param lhs the left hand side of the exchange
        ///   @param rhs the right hand side of the exchange
        ///
        static constexpr void
        private_swap(result &lhs, result &rhs) noexcept
        {
            if (details::result_type::contains_t == lhs.m_which) {
                if (details::result_type::contains_t == rhs.m_which) {
                    // This is needed to implement the this class
                    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-union-access)
                    bsl::swap(lhs.m_t, rhs.m_t);
                }
                else {
                    // This is needed to implement the this class
                    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-union-access)
                    E tmp_e_rwl{bsl::move(rhs.m_e)};
                    // This is needed to implement the this class
                    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-union-access)
                    destroy_at(&rhs.m_e);
                    // This is needed to implement the this class
                    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-union-access)
                    construct_at<T>(&rhs.m_t, bsl::move(lhs.m_t));
                    // This is needed to implement the this class
                    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-union-access)
                    destroy_at(&lhs.m_t);
                    // This is needed to implement the this class
                    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-union-access)
                    construct_at<E>(&lhs.m_e, bsl::move(tmp_e_rwl));
                }
            }
            else {
                if (details::result_type::contains_t == rhs.m_which) {
                    // This is needed to implement the this class
                    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-union-access)
                    E tmp_e_lwr{bsl::move(lhs.m_e)};
                    // This is needed to implement the this class
                    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-union-access)
                    destroy_at(&lhs.m_e);
                    // This is needed to implement the this class
                    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-union-access)
                    construct_at<T>(&lhs.m_t, bsl::move(rhs.m_t));
                    // This is needed to implement the this class
                    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-union-access)
                    destroy_at(&rhs.m_t);
                    // This is needed to implement the this class
                    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-union-access)
                    construct_at<E>(&rhs.m_e, bsl::move(tmp_e_lwr));
                }
                else {
                    // This is needed to implement the this class
                    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-union-access)
                    bsl::swap(lhs.m_e, rhs.m_e);
                }
            }

            bsl::swap(lhs.m_which, rhs.m_which);
        }

    public:
        /// @brief alias for: T
        using value_type = T;

        /// <!-- description -->
        ///   @brief Constructs a bsl::result that contains T,
        ///     by default constructing "t"
        ///   @include result/example_result_default_constructor.hpp
        ///
        /// <!-- exceptions -->
        ///   @throw throws if T's default constructor throws
        ///
        // The bsl-class-member-init has issues with union types,
        // which is not worth fixing as they are not supported in general.
        // NOLINTNEXTLINE(bsl-class-member-init)
        constexpr result() noexcept(is_nothrow_default_constructible<T>::value)
            : m_which{details::result_type::contains_t}, m_t{}
        {}

        /// <!-- description -->
        ///   @brief Constructs a bsl::result that contains T,
        ///     by copying "t"
        ///   @include result/example_result_t_copy_constructor.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param val the value being copied
        ///
        /// <!-- exceptions -->
        ///   @throw throws if T's copy constructor throws
        ///
        // We use a deleted single argument template constructor to prevent
        // implicit conversions, so this rule is OBE. Also, we cannot pass
        // by value here as we would lose the noexcept information as a result.
        // Finally, the bsl-class-member-init has issues with union types,
        // which is not worth fixing as they are not supported in general.
        // NOLINTNEXTLINE(hicpp-explicit-conversions, modernize-pass-by-value, bsl-class-member-init)
        constexpr result(T const &val) noexcept(is_nothrow_copy_constructible<T>::value)
            : m_which{details::result_type::contains_t}, m_t{val}
        {}

        /// <!-- description -->
        ///   @brief Constructs a bsl::result that contains T,
        ///     by moving "t"
        ///   @include result/example_result_t_move_constructor.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param val the value being moved
        ///
        /// <!-- exceptions -->
        ///   @throw throws if T's move constructor throws
        ///
        // We use a deleted single argument template constructor to prevent
        // implicit conversions, so this rule is OBE. Also, we cannot pass
        // by value here as we would lose the noexcept information as a result.
        // Finally, the bsl-class-member-init has issues with union types,
        // which is not worth fixing as they are not supported in general.
        // NOLINTNEXTLINE(hicpp-explicit-conversions, modernize-pass-by-value, bsl-class-member-init)
        constexpr result(T &&val) noexcept(is_nothrow_move_constructible<T>::value)
            : m_which{details::result_type::contains_t}, m_t{bsl::move(val)}
        {}

        /// <!-- description -->
        ///   @brief Constructs a bsl::result that contains T by constructing
        ///     T in place.
        ///   @include result/example_result_t_in_place_constructor.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam ARGS the type of arguments to pass to the constructor
        ///     of T
        ///   @param ip provide bsl::in_place to construct in place
        ///   @param a the arguments to create T with
        ///
        /// <!-- exceptions -->
        ///   @throw throws if T's constructor throws
        ///
        template<typename... ARGS>
        // We use a deleted single argument template constructor to prevent
        // implicit conversions, so this rule is OBE. The bsl-class-member-init
        // has issues with union types, which is not worth fixing as they are
        // not supported in general.
        // NOLINTNEXTLINE(hicpp-explicit-conversions, bsl-class-member-init)
        constexpr result(bsl::in_place_t const &ip, ARGS &&...a) noexcept(
            is_nothrow_constructible<T, ARGS...>::value)
            : m_which{details::result_type::contains_t}, m_t{bsl::forward<ARGS>(a)...}
        {
            bsl::discard(ip);
        }

        /// <!-- description -->
        ///   @brief Constructs a bsl::result that contains E,
        ///     by copying "e"
        ///   @include result/example_result_errc_copy_constructor.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param val the error code being copied
        ///
        // We use a deleted single argument template constructor to prevent
        // implicit conversions, so this rule is OBE. The bsl-class-member-init
        // has issues with union types, which is not worth fixing as they are
        // not supported in general.
        // NOLINTNEXTLINE(hicpp-explicit-conversions, bsl-class-member-init)
        constexpr result(E const &val) noexcept    // --
            : m_which{details::result_type::contains_e}, m_e{val}
        {}

        /// <!-- description -->
        ///   @brief Constructs a bsl::result that contains E,
        ///     by moving "e"
        ///   @include result/example_result_errc_move_constructor.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param val the error code being moved
        ///
        // We use a deleted single argument template constructor to prevent
        // implicit conversions, so this rule is OBE. The bsl-class-member-init
        // has issues with union types, which is not worth fixing as they are
        // not supported in general.
        // NOLINTNEXTLINE(hicpp-explicit-conversions, bsl-class-member-init)
        constexpr result(E &&val) noexcept
            : m_which{details::result_type::contains_e}, m_e{bsl::move(val)}
        {}

        /// <!-- description -->
        ///   @brief Destroyes a previously created bsl::result. Since
        ///     we require E to be trivially destructible, we only need to
        ///     call a destructor if this object contains a T
        ///
        /// <!-- exceptions -->
        ///   @throw throws if the bsl::result stores a T and T's destructor
        ///     throws
        ///
        constexpr ~result() noexcept(is_nothrow_destructible<T>::value)
        {
            if (details::result_type::contains_t == m_which) {
                // This is needed to implement the this class
                // NOLINTNEXTLINE(cppcoreguidelines-pro-type-union-access)
                destroy_at(&m_t);
            }
            else {
                // This is needed to implement the this class
                // NOLINTNEXTLINE(cppcoreguidelines-pro-type-union-access)
                destroy_at(&m_e);
            }
        }

        /// <!-- description -->
        ///   @brief copy constructor
        ///   @include result/example_result_copy_constructor.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///
        /// <!-- exceptions -->
        ///   @throw throws if the bsl::result stores a T and T's copy
        ///     constructor throws
        ///
        constexpr result(result const &o) noexcept(is_nothrow_copy_constructible<T>::value)
            : m_which{o.m_which}
        {
            if (details::result_type::contains_t == m_which) {
                // A BitCast conversion is needed when working with unions
                // NOLINTNEXTLINE(cppcoreguidelines-pro-type-union-access, bsl-implicit-conversions-forbidden)
                construct_at<T>(&m_t, o.m_t);
            }
            else {
                // A BitCast conversion is needed when working with unions
                // NOLINTNEXTLINE(cppcoreguidelines-pro-type-union-access, bsl-implicit-conversions-forbidden)
                construct_at<E>(&m_e, o.m_e);
            }
        }

        /// <!-- description -->
        ///   @brief move constructor
        ///   @include result/example_result_move_constructor.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being moved
        ///
        /// <!-- exceptions -->
        ///   @throw throws if the bsl::result stores a T and T's move
        ///     constructor throws
        ///
        constexpr result(result &&o) noexcept(is_nothrow_move_constructible<T>::value)
            : m_which{o.m_which}
        {
            if (details::result_type::contains_t == m_which) {
                // A BitCast conversion is needed when working with unions
                // NOLINTNEXTLINE(cppcoreguidelines-pro-type-union-access, bsl-implicit-conversions-forbidden)
                construct_at<T>(&m_t, bsl::move(o.m_t));
            }
            else {
                // A BitCast conversion is needed when working with unions
                // NOLINTNEXTLINE(cppcoreguidelines-pro-type-union-access, bsl-implicit-conversions-forbidden)
                construct_at<E>(&m_e, bsl::move(o.m_e));
            }
        }

        /// <!-- description -->
        ///   @brief copy assignment
        ///   @include result/example_result_copy_assignment.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///   @return a reference to *this
        ///
        /// <!-- exceptions -->
        ///   @throw throws if the bsl::result stores a T and T's copy
        ///     constructor throws or swapping T throws
        ///
        [[maybe_unused]] constexpr auto
        operator=(result const &o) &noexcept(
            conjunction<is_nothrow_copy_constructible<T>, is_nothrow_swappable<T>>::value)
            -> result &
        {
            result tmp{o};
            this->private_swap(*this, tmp);
            return *this;
        }

        /// <!-- description -->
        ///   @brief move assignment
        ///   @include result/example_result_move_assignment.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being moved
        ///   @return a reference to *this
        ///
        /// <!-- exceptions -->
        ///   @throw throws if the bsl::result stores a T and T's move
        ///     constructor throws or swapping T throws
        ///
        [[maybe_unused]] constexpr auto
        operator=(result &&o) &noexcept(
            conjunction<is_nothrow_move_constructible<T>, is_nothrow_swappable<T>>::value)
            -> result &
        {
            result tmp{bsl::move(o)};
            this->private_swap(*this, tmp);
            return *this;
        }

        /// <!-- description -->
        ///   @brief This constructor allows for single argument constructors
        ///     without the need to mark them as explicit as it will absorb
        ///     any incoming potential implicit conversion and prevent it.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam O the type that could be implicitly converted
        ///   @param val the value that could be implicitly converted
        ///
        template<typename O>
        constexpr result(O val) noexcept = delete;

        /// <!-- description -->
        ///   @brief Returns a handle to T if this object contains T,
        ///     otherwise it returns a nullptr.
        ///   @include result/example_result_get_if.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a handle to T if this object contains T,
        ///     otherwise it returns a nullptr.
        ///
        [[nodiscard]] constexpr auto
        get_if() &noexcept -> T *
        {
            if (likely(details::result_type::contains_t == m_which)) {
                // This is needed to implement the this class
                // NOLINTNEXTLINE(cppcoreguidelines-pro-type-union-access)
                return &m_t;
            }

            return nullptr;
        }

        /// <!-- description -->
        ///   @brief Returns a handle to T if this object contains T,
        ///     otherwise it returns a nullptr.
        ///   @include result/example_result_get_if.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a handle to T if this object contains T,
        ///     otherwise it returns a nullptr.
        ///
        [[nodiscard]] constexpr auto
        get_if() const &noexcept -> T const *
        {
            if (likely(details::result_type::contains_t == m_which)) {
                // This is needed to implement the this class
                // NOLINTNEXTLINE(cppcoreguidelines-pro-type-union-access)
                return &m_t;
            }

            return nullptr;
        }

        /// <!-- description -->
        ///   @brief The r-value version of this function is not supported
        ///
        /// <!-- inputs/outputs -->
        ///   @return n/a
        ///
        [[nodiscard]] constexpr auto get_if() const &&noexcept -> T const * = delete;

        /// <!-- description -->
        ///   @brief Returns an error code if this object contains E,
        ///     otherwise it returns "fallback".
        ///   @include result/example_result_errc.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param fallback returned if this bsl::result contains T
        ///   @return Returns an error code if this object contains E,
        ///     otherwise it returns "or".
        ///
        [[nodiscard]] constexpr auto
        errc(E const &fallback = E{}) const noexcept -> E
        {
            if (likely(details::result_type::contains_e == m_which)) {
                // This is needed to implement the this class
                // NOLINTNEXTLINE(cppcoreguidelines-pro-type-union-access)
                return m_e;
            }

            return fallback;
        }

        /// <!-- description -->
        ///   @brief Returns success()
        ///   @include result/example_result_operator_bool.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns success()
        ///
        [[nodiscard]] constexpr explicit operator bool() const noexcept
        {
            return this->success();
        }

        /// <!-- description -->
        ///   @brief Returns true if the bsl::result contains T,
        ///     otherwise, if the bsl::result contains an error code,
        ///     returns false.
        ///   @include result/example_result_success.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if the bsl::result contains T,
        ///     otherwise, if the bsl::result contains an error code,
        ///     returns false.
        ///
        [[nodiscard]] constexpr auto
        success() const noexcept -> bool
        {
            return details::result_type::contains_t == m_which;
        }

        /// <!-- description -->
        ///   @brief Returns true if the bsl::result contains E,
        ///     otherwise, if the bsl::result contains T,
        ///     returns false.
        ///   @include result/example_result_failure.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if the bsl::result contains E,
        ///     otherwise, if the bsl::result contains T,
        ///     returns false.
        ///
        [[nodiscard]] constexpr auto
        failure() const noexcept -> bool
        {
            return details::result_type::contains_e == m_which;
        }

    private:
        /// @brief stores which type the union stores
        details::result_type m_which;

        /// @brief Provides access to T or an error code
        // This class implements a version of std::variant, and as a result,
        // a union is needed. Note that this is a tagged union, which is
        // allowed by AUTOSAR.
        // NOLINTNEXTLINE(bsl-decl-forbidden)
        union
        {
            /// @brief stores T when not storing an error code
            T m_t;
            /// @brief stores an error code when not storing T
            E m_e;
        };
    };

    /// <!-- description -->
    ///   @brief Returns true if the lhs is equal to the rhs, false otherwise
    ///   @include result/example_result_equals.hpp
    ///   @related bsl::result
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the nullable type
    ///   @tparam E the error type to use
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns true if the lhs is equal to the rhs, false otherwise
    ///
    template<typename T, typename E>
    [[nodiscard]] constexpr auto
    operator==(result<T, E> const &lhs, result<T, E> const &rhs) noexcept -> bool
    {
        if (lhs.success() != rhs.success()) {
            return false;
        }

        if (lhs.success()) {
            return *lhs.get_if() == *rhs.get_if();
        }

        return lhs.errc() == rhs.errc();
    }

    /// <!-- description -->
    ///   @brief Returns false if the lhs is equal to the rhs, true otherwise
    ///   @include result/example_result_not_equals.hpp
    ///   @related bsl::result
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the nullable type
    ///   @tparam E the error type to use
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns false if the lhs is equal to the rhs, true otherwise
    ///
    template<typename T, typename E>
    [[nodiscard]] constexpr auto
    operator!=(result<T, E> const &lhs, result<T, E> const &rhs) noexcept -> bool
    {
        return !(lhs == rhs);
    }

    /// <!-- description -->
    ///   @brief Outputs the provided bsl::result to the provided
    ///     output type.
    ///   @related bsl::result
    ///   @include result/example_result_ostream.hpp
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T1 the type of outputter provided
    ///   @tparam T2 the type of element being encapsulated.
    ///   @tparam E the error type to use
    ///   @param o the instance of the outputter used to output the value.
    ///   @param val the result to output
    ///   @return return o
    ///
    template<typename T1, typename T2, typename E>
    [[maybe_unused]] constexpr auto
    operator<<(out<T1> const o, bsl::result<T2, E> const &val) noexcept -> out<T1>
    {
        if constexpr (!o) {
            return o;
        }

        if (auto const *const ptr{val.get_if()}) {
            return o << *ptr;
        }

        return o << val.errc();
    }
}

#endif
