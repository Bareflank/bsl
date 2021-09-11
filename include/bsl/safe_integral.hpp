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

#include "bsl/always_false.hpp"
#include "bsl/cstdint.hpp"    // IWYU pragma: export
#include "bsl/enable_if.hpp"
#include "bsl/integer.hpp"
#include "bsl/is_integral.hpp"
#include "bsl/is_same.hpp"
#include "bsl/is_signed.hpp"
#include "bsl/is_unsigned.hpp"
#include "bsl/located_arg.hpp"    // IWYU pragma: export
#include "bsl/numeric_limits.hpp"
#include "bsl/source_location.hpp"
#include "bsl/touch.hpp"
#include "bsl/unlikely.hpp"

#include <bsl/assert.hpp>

namespace bsl
{
    /// <!-- description -->
    ///   @brief Used to tell the user during compile-time that an
    ///     they attempted to use a safe_integral but never checked
    ///     to see if it was valid first.
    ///
    inline void
    safe_integrals_must_be_checked_before_use() noexcept
    {}

    /// <!-- description -->
    ///   @brief Used to tell the user during compile-time that an
    ///     they attempted to use a safe_integral that's poisoned.
    ///
    inline void
    a_poisoned_safe_integral_was_read() noexcept
    {}

    /// @class bsl::safe_integral
    ///
    /// <!-- description -->
    ///   @brief Provides a safe implementation of an integral type that
    ///     adheres to AUTOSAR's requirement that an integral shall not
    ///     overflow, wrap, divide by zero, etc.
    ///   @include example_safe_integral_overview.hpp
    ///
    /// <!-- notes -->
    ///   @note A safe_integral requires that you check the validity of
    ///     the integral before you use it. C and C++ do not enforce any
    ///     rules with the use of integral types. Rust has the complete
    ///     opposite where all operations are checked, and all behavior
    ///     is defined and anything that violates this will result in a
    ///     panic(). Both are terrible for critical systems as one is
    ///     the wild west, and the other is slow at best, and at worst,
    ///     is a ticking time bomb in debug mode, and is again, the wild
    ///     west in release mode as all validation is disabled (or even
    ///     worse, validation is re-enabled in release mode, in which case
    ///     the code is slow again and could fast fail which is not allowed)
    ///
    ///     The difference with this implementation is that only certain
    ///     operations require validation, and validation is only required
    ///     at the time of use. SEI CERT defines the integer rules used by
    ///     both MISRA and AUTOSAR. These rules ensure that optimizations
    ///     due to UB are still possible and sane in release mode (unlike
    ///     Rust which doesn't have UB for arithmetic), while still ensuring
    ///     that arithmetic that would cause a problem are handled properly.
    ///     https://wiki.sei.cmu.edu/confluence/pages/viewpage.action?pageId=87151979
    ///
    ///     The safe_integral implements these rules. For example, all
    ///     arithmetic (+, -, *, /, %) must be checked. But all shift
    ///     and binary operations are safe to use without the need for
    ///     validation. Shift and binary operations are only allowed
    ///     on unsigned integers while negation is only allowed on signed
    ///     integers. In addition, like with Rust, implicit conversions
    ///     from one integer type to another is not allowed. Everything
    ///     must be explicit. The convert.hpp/convert.rs contains the
    ///     APIs needed for handling safe conversions when needed, and
    ///     any loss of data will result in a need to validate.
    ///
    ///     Validation rules can be seen in the unit tests, but they are
    ///     as follows:
    ///     - Newly created safe integrals do NOT need validation.
    ///     - Shift, binary and compliment operations do NOT need validation.
    ///     - Arithmetic requires validation.
    ///     - Conversions that loss data require validation.
    ///     - Safe conversions do NOT need validation.
    ///
    ///     Unlike Rust, validations only need to occur at the time of use,
    ///     and not at the time of the operation. What this means is that
    ///     you can overflow all day long, performing millions of operations.
    ///     The compiler is smart enough to track the poison bit (i.e. carry)
    ///     bit, removing most if not all of the overhead associated with
    ///     the safe integral, meaning safety checks can be enabled in
    ///     release mode because operations that never need to be checked
    ///     completely optimize away the safe integral while operations that
    ///     need validation can still optimize away the safe integral and
    ///     simply track the carry bit as needed.
    ///
    ///     Once you attempt to read the value using get(), is_xxx(),
    ///     or any of the rational operators like == and !=, you must
    ///     check the integral before you use it. The safe integral in debug
    ///     mode tracks whether or not the safe integral needs to be checked
    ///     and whether or not you have actually performed this check before
    ///     attempting to read the safe integral's internal value. If you
    ///     fail to check before reading a safe integral that needs to be
    ///     validated based on the SEI CERT rules, or if you attempt to read
    ///     an invalid integral, a fast fail using assert will occur.
    ///
    ///     In release mode, all of the check validations are removed, and
    ///     all assertions due to reading invalid integrals are also removed.
    ///     The only thing that remains is software can still query the
    ///     poisoned bit to ensuring the safe integral is valid. What this
    ///     means is that in debug mode, this code ensures, when combined with
    ///     good unit tests, that all of your code is properly checking for
    ///     validation only when it is needed. Once release mode is turned on
    ///     these validations remain and ensure that UB is never executed,
    ///     allowing us to safely remove the assertions without having to
    ///     simply "cross our fingers" like C, C++ and Rust do today, while
    ///     still ensuring that optimizations around this logic are possible.
    ///     We even have some binary analysis tests designed to ensure that
    ///     we can manually inspect the resulting generated ASM to ensure
    ///     optimizations are in fact occurring.
    ///
    ///     There are some tricks that are important when using the safe
    ///     integrals. Any code that performs arithmetic must use the
    ///     is_poisoned() function with a mutable variable. For example,
    ///     @code
    ///     auto mut_val{42_umx + 42_umx}:
    ///     if (bsl::unlikely(mut_val.is_poisoned())) {
    ///         return handle_error();
    ///     }
    ///     do_something(mut_val.get());
    ///     @endcode
    ///
    ///     The above code performs some arithmetic, and then needs to read
    ///     the results and pass it to do_something(). You cannot read the
    ///     until you have told the safe_integral that you have performed
    ///     the check, even if the safe_integral is valid, the check must
    ///     be performed. When unit testing, if you fail to perform this
    ///     check, a fast fail will occur telling you that you are missing
    ///     a check. Remember though that not all operations require the
    ///     safe integral to be checked. For example, if you use a shift,
    ///     or binary operation, you can safely read the integer without
    ///     checking (and should as the code can better be optimized by the
    ///     compiler). Also, it should be noted that is_poisoned() will flip
    ///     a bit in the safe_integral which means that it must be made
    ///     mutable.
    ///
    ///     Sometimes, when you are given a safe integral as an input to a
    ///     function, you need to determine what your contract will be. A
    ///     wide contract would need to handle the situation where the
    ///     integral is invalid and unchecked, but most inputs to a function
    ///     are marked as a const. To handle this, you can do the following
    ///     when implementing a wide contract:
    ///     @code
    ///     [[nodiscard]] constexpr auto
    ///     foo(bsl::safe_umx const &val) noexcept -> bsl::errc_type
    ///     {
    ///         auto mut_val{val};
    ///         if (bsl::unlikely(mut_val.is_poisoned())) {
    ///             return handle_error();
    ///         }
    ///         do_something(mut_val.get());
    ///     }
    ///     @endcode
    ///
    ///     As seen above, we create a mutable version of the variable and
    ///     then check (and use) the mutable version only. In release mode,
    ///     the compiler will detect that there is no difference between the
    ///     two and promote mut_val to a const and optimize as needed.
    ///
    ///     Another way to handle this case is to simply use a narrow contract
    ///     as follows:
    ///     @code
    ///     constexpr void
    ///     foo(bsl::safe_umx const &val) noexcept
    ///     {
    ///         bsl::expects(val.is_valid_and_checked());
    ///         do_something(val.get());
    ///     }
    ///     @endcode
    ///
    ///     As seen above, with a narrow contract, you might even be able to
    ///     remove the need to return an error. This basically states that
    ///     this function expects that val has already been validated and
    ///     that this function does not need to do this validation. This is
    ///     really important because for most private functions, you do not
    ///     want wide contracts. Doing so would result in every function
    ///     being huge, and integrals being checked over and over and over
    ///     for no reason. Proper unit testing is required to ensure that
    ///     these contracts are in fact being adhered to, but in general,
    ///     this is likely the best option for private interfaces while
    ///     public interfaces should use a wide contract. Note that what
    ///     defines a public vs private interface is not based on "public"
    ///     vs "private" labels in a class, but rather who will be using the
    ///     interface. An API that other people will use (like a library)
    ///     should use a wide contract, or a syscall/hypercall interface
    ///     should also use an infinitely wide contract. But classes (even with
    ///     public APIs) that are private to your kernel, application, etc.
    ///     should use narrow contracts.
    ///
    ///     To support narrow contracts, functions that return a safe integral
    ///     should ensure their return value is always checked if arithmetic
    ///     is performed. For example:
    ///     @code
    ///     [[nodiscard]] constexpr auto
    ///     foo() noexcept -> bsl::safe_umx
    ///     {
    ///         auto mut_val{42_umx + 42_umx};
    ///         if (bsl::unlikely(mut_val.is_poisoned())) {
    ///             return safe_umx::failure();
    ///         }
    ///
    ///         bsl::ensures(mut_val.is_valid_and_checked());
    ///         return mut_val;
    ///     }
    ///     @endcode
    ///
    ///     In the example above, we are not ensuring that the return value
    ///     is always valid. If an error occurs, we will still return
    ///     failure(). But we are ensuring that if no error occurs, that the
    ///     safe integral that we return will always be valid and checked.
    ///     This means that software calling this function can leave the
    ///     return value as const:
    ///     @code
    ///     [[nodiscard]] constexpr auto
    ///     bar() noexcept -> bsl::safe_umx
    ///     {
    ///         auto const val{foo()};
    ///         if (bsl::unlikely(val.is_invalid())) {
    ///             return safe_umx::failure();
    ///         }
    ///
    ///         do_something(val.get());
    ///     }
    ///     @endcode
    ///
    ///     In the example above, the bar function calls foo. Foo will either
    ///     return failure(), or a valid and checked safe_umx. In this case,
    ///     the bar function can leave the val variable as const and use the
    ///     is_invalid()/is_valid() functions instead. If an error occurs,
    ///     bar() can handle it without ever reading the value as it can't
    ///     because doing so would lead to UB anyways. If no error occurs,
    ///     val, by contract, is checked, so bar does not need to perform this
    ///     check again. It can safely read the value without an issue.
    ///
    ///     The above pattern is used A LOT. The rule of thumb is, try to
    ///     make ALL safe integrals const. To do this, all functions should
    ///     either return failure() on an error, or valid and checked
    ///     integrals on success. All function inputs (for private APIs)
    ///     should expect valid and checked integrals. Doing so means that
    ///     most, if not all safe integrals are marked const, and validation
    ///     is done using is_invalid() instead of is_poisoned(), resulting
    ///     in cleaner APIs and better optimized code.
    ///
    ///     You might have noticed that foo() performs math that will never
    ///     be invalid. Even though arithmetic is performed, constants are
    ///     being used, or some other constraint might have  occurred that
    ///     prevents the branch in foo from ever being taken. You can see this
    ///     in a unit test as you will never be able to trigger this branch no
    ///     matter what input you provide the function. These situations can
    ///     also occur a lot. To handle these, we provide the checked()
    ///     function as follows:
    ///     @code
    ///     [[nodiscard]] constexpr auto
    ///     foo() noexcept -> bsl::safe_umx
    ///     {
    ///         auto const val{(42_umx + 42_umx).checked()};
    ///         return val;
    ///     }
    ///     @endcode
    ///
    ///     In the code above, since val will always be valid, we can safely
    ///     use the checked() function, which returns a checked() version of
    ///     the safe_integral that results from the arithmetic. Since the
    ///     result is checked, foo() can now set val to const, as it has
    ///     already been checked and doesn't need to be checked again. We
    ///     also don't need the bsl::ensures() to enforce our contract. This
    ///     is because the checked() function is doing this for use. If the
    ///     result is actually invalid, the same assert() will trigger,
    ///     meaning if you accidentally mark arithmetic that actually can
    ///     become invalid as checked, the checked() function will detect this
    ///     and yell at you the same way the bsl::ensures() statement would
    ///     have.
    ///
    ///     If you look at the hypervisor repo, we rarely need mutable
    ///     variables. Most safe integrals are IDs, or other values that
    ///     are either failure(), or valid and checked, and so they are
    ///     always const. Most functions use narrow contracts, meaning they
    ///     always assume they are given valid and checked safe integrals,
    ///     and they always ensure they return valid and safe integrals.
    ///     This results in simple APIs and insanely optimized code, while
    ///     allowing us to use runtime overflow checks in release mode as
    ///     MISRA and AUTOSAR require without fast failing which is also
    ///     not allowed.
    ///
    ///     Finally, there is one more thing to talk about, and that is
    ///     indexes. For loops do a lot of math that WILL NEVER result in
    ///     an invalid safe integral. For example
    ///     @code
    ///     for (bsl::safe_idx mut_i{}; mut_i < 5_umx; ++mut_i) {
    ///         do_something(array.at_if(mut_i));
    ///     }
    ///     @endcode
    ///
    ///     The safe_idx implements a safe integral, but with a limited API.
    ///     Unlike a safe integral, a safe_idx can only perform +, -, ++, --
    ///     and the rational operators. Nothing else. But, as a result, you
    ///     are not required to check the results of arithmetic. This is
    ///     because most of the time, indexes will never overflow. Ever. In
    ///     the example above, we loop from 0 to 5. This arithmetic is
    ///     bounded and therefore will never overflow. As also shown above,
    ///     you can mix a safe_idx with a safe_umx using the rational
    ///     operators. This is because most size() and length() functions
    ///     will return a safe_umx. If, however, you need to convert a safe
    ///     integral into a safe_idx, it is allowed, but the conversion is
    ///     checked for validity in debug mode to ensure that you are not
    ///     creating an invalid safe_idx as that is not allowed. In fact,
    ///     the safe_idx does not have a failure() function, nor does it
    ///     have any of the checked or validation functions with the exception
    ///     to is_invalid, which is needed internally for the above mentioned
    ///     sanity checks (and sadly, AUTOSAR does not allow friend functions
    ///     so is_invalid must be made public).
    ///
    ///     The point is, a safe_idx provides a very narrow contract. You
    ///     can use it for for loops without having to check your arithmetic,
    ///     and it is used to index into data structures which means these
    ///     data structures will not accept invalid safe integrals (although
    ///     that is the case for pretty much all of the BSL APIs with the
    ///     exception to things like bsl::print() and friends which will
    ///     output an error instead). The poisoned bit for a safe integral is
    ///     still there, and likely is optimized out as it is almost never
    ///     used outside of some rare situations, but as a result, the API
    ///     is very limited, only really allowing you to use the safe_idx
    ///     as an index and nothing more.
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
        /// @brief stores whether or not the integral has been poisoned
        bool m_poisoned;
        /// @brief stores whether or not the integral has been checked
        bool m_unchecked;

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

            if constexpr (BSL_RELEASE_MODE) {
                return;
            }

            m_unchecked = true;
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

            if constexpr (BSL_RELEASE_MODE) {
                return;
            }

            m_unchecked = true;
        }

        /// <!-- description -->
        ///   @brief Verifies that the poison has been checked. If it has not
        ///     we throw an error during compile-time, and we print a warning
        ///     during runtime.
        ///
        /// <!-- inputs/outputs -->
        ///   @param sloc the location of the call site
        ///
        constexpr void
        verify_poison_has_been_checked(source_location const &sloc) const noexcept
        {
            if constexpr (BSL_RELEASE_MODE) {
                return;
            }

            if (unlikely(m_unchecked)) {
                safe_integrals_must_be_checked_before_use();
                assert("safe_integrals must be checked before use", sloc);
            }
            else {
                bsl::touch();
            }
        }

        /// <!-- description -->
        ///   @brief Sets the poison checked flag if the safe_integral is
        ///     valid.
        ///
        constexpr void
        mark_as_checked_if_valid() noexcept
        {
            if constexpr (BSL_RELEASE_MODE) {
                return;
            }

            m_unchecked = m_poisoned;
        }

        /// <!-- description -->
        ///   @brief Private constructor for creating a new safe_integral
        ///     with all of the arguments however we want them.
        ///
        /// <!-- inputs/outputs -->
        ///   @param val the value to set the safe integral to
        ///   @param poisoned the poisoned flags to set the safe integral to
        ///   @param unchecked the unchecked flags to set the safe integral to
        ///
        constexpr safe_integral(
            T const val, bool const poisoned, bool const unchecked) noexcept    // --
            : m_val{val}, m_poisoned{poisoned}, m_unchecked{unchecked}
        {}

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
            : m_val{}, m_poisoned{}, m_unchecked{}
        {}

        /// <!-- description -->
        ///   @brief Creates a bsl::safe_integral given a fixed width type
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
            : m_val{val}, m_poisoned{}, m_unchecked{}
        {}

        /// <!-- description -->
        ///   @brief Creates a bsl::safe_integral given a fixed width type
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam U Used to ensure the provided integer is the same as
        ///     T, effectively preventing implicit conversions from being
        ///     allowed.
        ///   @tparam O the type of safe integral containing the flags to merge
        ///   @param val the value to set the bsl::safe_integral to
        ///   @param flags a safe_integral containing the poisoned and
        ///     unchecked flags to use.
        ///
        template<typename U, typename O, enable_if_t<is_same<T, U>::value, bool> = true>
        explicit constexpr safe_integral(
            U const val, safe_integral<O> const &flags) noexcept    // --
            : m_val{val}, m_poisoned{flags.is_invalid()}, m_unchecked{flags.is_unchecked()}
        {}

        /// <!-- description -->
        ///   @brief Creates a bsl::safe_integral given a fixed width type
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam O the type of safe integral containing the flags to merge
        ///   @param val the value to set the bsl::safe_integral to
        ///   @param flags a safe_integral containing the poisoned and
        ///     unchecked flags to use.
        ///
        template<typename O>
        explicit constexpr safe_integral(
            safe_integral<T> const &val, safe_integral<O> const &flags) noexcept    // --
            : m_val{val.m_val}
            , m_poisoned{(val.m_poisoned) || (flags.is_invalid())}        // NOLINT
            , m_unchecked{(val.m_unchecked) || (flags.is_unchecked())}    // NOLINT
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
        operator=(U const val) &noexcept -> safe_integral &
        {
            *this = safe_integral{val};
            return *this;
        }

        /// <!-- description -->
        ///   @brief Returns the max value the bsl::safe_integral can store.
        ///   @include safe_integral/example_safe_integral_max_value.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the max value the bsl::safe_integral can store.
        ///
        [[nodiscard]] static constexpr auto
        max_value() noexcept -> safe_integral
        {
            return safe_integral{numeric_limits<value_type>::max_value()};
        }

        /// <!-- description -->
        ///   @brief Returns the min value the bsl::safe_integral can store.
        ///   @include safe_integral/example_safe_integral_min_value.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the min value the bsl::safe_integral can store.
        ///
        [[nodiscard]] static constexpr auto
        min_value() noexcept -> safe_integral
        {
            return safe_integral{numeric_limits<value_type>::min_value()};
        }

        /// <!-- description -->
        ///   @brief Returns safe_integral{-1}
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns safe_integral{-1}
        ///
        [[nodiscard]] static constexpr auto
        magic_neg_1() noexcept -> safe_integral
        {
            if constexpr (is_unsigned<value_type>::value) {
                static_assert(always_false<value_type>(), "unsigned neg_one not supported");
            }

            return safe_integral{static_cast<value_type>(-1)};
        }

        /// <!-- description -->
        ///   @brief Returns safe_integral{-2}
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns safe_integral{-2}
        ///
        [[nodiscard]] static constexpr auto
        magic_neg_2() noexcept -> safe_integral
        {
            if constexpr (is_unsigned<value_type>::value) {
                static_assert(always_false<value_type>(), "unsigned neg_one not supported");
            }

            return safe_integral{static_cast<value_type>(-2)};
        }

        /// <!-- description -->
        ///   @brief Returns safe_integral{-3}
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns safe_integral{-3}
        ///
        [[nodiscard]] static constexpr auto
        magic_neg_3() noexcept -> safe_integral
        {
            if constexpr (is_unsigned<value_type>::value) {
                static_assert(always_false<value_type>(), "unsigned neg_one not supported");
            }

            return safe_integral{static_cast<value_type>(-3)};
        }

        /// <!-- description -->
        ///   @brief Returns safe_integral{0}
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns safe_integral{0}
        ///
        [[nodiscard]] static constexpr auto
        magic_0() noexcept -> safe_integral
        {
            return safe_integral{static_cast<value_type>(0)};
        }

        /// <!-- description -->
        ///   @brief Returns safe_integral{1}
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns safe_integral{1}
        ///
        [[nodiscard]] static constexpr auto
        magic_1() noexcept -> safe_integral
        {
            return safe_integral{static_cast<value_type>(1)};
        }

        /// <!-- description -->
        ///   @brief Returns safe_integral{2}
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns safe_integral{2}
        ///
        [[nodiscard]] static constexpr auto
        magic_2() noexcept -> safe_integral
        {
            return safe_integral{static_cast<value_type>(2)};
        }

        /// <!-- description -->
        ///   @brief Returns safe_integral{3}
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns safe_integral{3}
        ///
        [[nodiscard]] static constexpr auto
        magic_3() noexcept -> safe_integral
        {
            return safe_integral{static_cast<value_type>(3)};
        }

        /// <!-- description -->
        ///   @brief Returns a reference to the internal integral being managed
        ///     by this class, providing a means to directly read/write the
        ///     integral's value.
        ///   @include safe_integral/example_safe_integral_data.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a reference to the internal integral being managed
        ///     by this class, providing a means to directly read/write the
        ///     integral's value.
        ///
        [[nodiscard]] constexpr auto
        data_as_ref() noexcept -> reference_type
        {
            return m_val;
        }

        /// <!-- description -->
        ///   @brief Returns a reference to the internal integral being managed
        ///     by this class, providing a means to directly read/write the
        ///     integral's value.
        ///   @include safe_integral/example_safe_integral_data.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a reference to the internal integral being managed
        ///     by this class, providing a means to directly read/write the
        ///     integral's value.
        ///
        [[nodiscard]] constexpr auto
        data_as_ref() const noexcept -> const_reference_type
        {
            return m_val;
        }

        /// <!-- description -->
        ///   @brief Returns a reference to the internal integral being managed
        ///     by this class, providing a means to directly read/write the
        ///     integral's value.
        ///   @include safe_integral/example_safe_integral_data.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a reference to the internal integral being managed
        ///     by this class, providing a means to directly read/write the
        ///     integral's value.
        ///
        [[nodiscard]] constexpr auto
        cdata_as_ref() const noexcept -> const_reference_type
        {
            return m_val;
        }

        /// <!-- description -->
        ///   @brief Returns a pointer to the internal integral being managed
        ///     by this class, providing a means to directly read/write the
        ///     integral's value.
        ///   @include safe_integral/example_safe_integral_data.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a pointer to the internal integral being managed
        ///     by this class, providing a means to directly read/write the
        ///     integral's value.
        ///
        [[nodiscard]] constexpr auto
        data() noexcept -> pointer_type
        {
            return &m_val;
        }

        /// <!-- description -->
        ///   @brief Returns a pointer to the internal integral being managed
        ///     by this class, providing a means to directly read/write the
        ///     integral's value.
        ///   @include safe_integral/example_safe_integral_data.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a pointer to the internal integral being managed
        ///     by this class, providing a means to directly read/write the
        ///     integral's value.
        ///
        [[nodiscard]] constexpr auto
        data() const noexcept -> const_pointer_type
        {
            return &m_val;
        }

        /// <!-- description -->
        ///   @brief Returns a pointer to the internal integral being managed
        ///     by this class, providing a means to directly read/write the
        ///     integral's value.
        ///   @include safe_integral/example_safe_integral_data.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a pointer to the internal integral being managed
        ///     by this class, providing a means to directly read/write the
        ///     integral's value.
        ///
        [[nodiscard]] constexpr auto
        cdata() const noexcept -> const_pointer_type
        {
            return &m_val;
        }

        /// <!-- description -->
        ///   @brief Returns the value stored by the bsl::safe_integral.
        ///     Attempting to get the value of an invalid safe_integral
        ///     results in undefined behavior.
        ///   @include safe_integral/example_safe_integral_get.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param sloc the location of the call site
        ///   @return Returns the value stored by the bsl::safe_integral.
        ///     Attempting to get the value of an invalid safe_integral
        ///     results in undefined behavior.
        ///
        [[nodiscard]] constexpr auto
        get(source_location const &sloc = here()) const noexcept -> value_type
        {
            if (unlikely(m_poisoned)) {
                a_poisoned_safe_integral_was_read();
                assert("a poisoned safe_integral was read", sloc);
            }
            else {
                bsl::touch();
            }

            this->verify_poison_has_been_checked(sloc);
            return m_val;
        }

        /// <!-- description -->
        ///   @brief Returns true if the safe_integral is positive.
        ///     Attempting to run is_pos on an invalid safe_integral
        ///     results in undefined behavior.
        ///   @include safe_integral/example_safe_integral_is_pos.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param sloc the location of the call site
        ///   @return Returns true if the safe_integral is positive
        ///
        [[nodiscard]] constexpr auto
        is_pos(source_location const &sloc = here()) const noexcept -> bool
        {
            if (unlikely(m_poisoned)) {
                a_poisoned_safe_integral_was_read();
                assert("a poisoned safe_integral was read", sloc);
            }
            else {
                bsl::touch();
            }

            this->verify_poison_has_been_checked(sloc);
            return m_val > 0;
        }

        /// <!-- description -->
        ///   @brief Returns true if the safe_integral is negative.
        ///     Attempting to run is_neg on an invalid safe_integral
        ///     results in undefined behavior.
        ///   @include safe_integral/example_safe_integral_is_neg.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param sloc the location of the call site
        ///   @return Returns true if the safe_integral is negative
        ///
        [[nodiscard]] constexpr auto
        is_neg(source_location const &sloc = here()) const noexcept -> bool
        {
            if constexpr (is_unsigned<value_type>::value) {
                static_assert(always_false<value_type>(), "unsigned is_neg not supported");
            }

            if (unlikely(m_poisoned)) {
                a_poisoned_safe_integral_was_read();
                assert("a poisoned safe_integral was read", sloc);
            }
            else {
                bsl::touch();
            }

            this->verify_poison_has_been_checked(sloc);
            return m_val < 0;
        }

        /// <!-- description -->
        ///   @brief Returns true if the safe_integral is 0.
        ///     Attempting to run is_zero on an invalid safe_integral
        ///     results in undefined behavior.
        ///   @include safe_integral/example_safe_integral_is_zero.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param sloc the location of the call site
        ///   @return Returns true if the safe_integral is 0
        ///
        [[nodiscard]] constexpr auto
        is_zero(source_location const &sloc = here()) const noexcept -> bool
        {
            if (unlikely(m_poisoned)) {
                a_poisoned_safe_integral_was_read();
                assert("a poisoned safe_integral was read", sloc);
            }
            else {
                bsl::touch();
            }

            this->verify_poison_has_been_checked(sloc);
            return 0 == m_val;
        }

        /// <!-- description -->
        ///   @brief Returns true if the safe_integral has encountered and
        ///     error, false otherwise. This function WILL mark the
        ///     safe_integral as checked.
        ///   @include safe_integral/example_safe_integral_is_poisoned.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if the safe_integral has encountered and
        ///     error, false otherwise. This function WILL mark the
        ///     safe_integral as checked.
        ///
        [[nodiscard]] constexpr auto
        is_poisoned() noexcept -> bool
        {
            this->mark_as_checked_if_valid();
            return m_poisoned;
        }

        /// <!-- description -->
        ///   @brief Returns true if the safe_integral has encountered and
        ///     error, false otherwise. This function DOES NOT marked the
        ///     safe_integral as checked.
        ///   @include safe_integral/example_safe_integral_is_invalid.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if the safe_integral has encountered and
        ///     error, false otherwise. This function DOES NOT marked the
        ///     safe_integral as checked.
        ///
        [[nodiscard]] constexpr auto
        is_invalid() const noexcept -> bool
        {
            return m_poisoned;
        }

        /// <!-- description -->
        ///   @brief Returns !this->is_invalid().
        ///   @include safe_integral/example_safe_integral_is_invalid.hpp
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
        ///   @brief Returns true if the safe_integral is 0. Will
        ///     always return true if an error has been encountered. This
        ///     function WILL mark the safe_integral as checked.
        ///   @include safe_integral/example_safe_integral_is_zero_or_poisoned.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if the safe_integral is 0. Will
        ///     always return true if an error has been encountered. This
        ///     function WILL mark the safe_integral as checked.
        ///
        [[nodiscard]] constexpr auto
        is_zero_or_poisoned() noexcept -> bool
        {
            if (unlikely(this->is_poisoned())) {
                return true;
            }

            return 0 == m_val;
        }

        /// <!-- description -->
        ///   @brief Returns true if the safe_integral is 0. Will
        ///     always return true if an error has been encountered. This
        ///     function DOES NOT marked the safe_integral as checked.
        ///   @include safe_integral/example_safe_integral_is_zero_or_invalid.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if the safe_integral is 0. Will
        ///     always return true if an error has been encountered. This
        ///     function DOES NOT marked the safe_integral as checked.
        ///
        [[nodiscard]] constexpr auto
        is_zero_or_invalid() const noexcept -> bool
        {
            if (unlikely(this->is_invalid())) {
                return true;
            }

            return 0 == m_val;
        }

        /// <!-- description -->
        ///   @brief Returns the checked version of the safe_integral. This
        ///     should only be used if the safe_integral has actually been
        ///     checked, or unit testing has proven that it is impossible for
        ///     the safe_integral to become poisoned (because all of the
        ///     possible ways the integral could become poisoned have been
        ///     verified external to the safe_integral).
        ///   @include safe_integral/example_safe_integral_checked.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param sloc the location of the call site
        ///   @return Returns the checked version of the safe_integral.
        ///
        [[nodiscard]] constexpr auto
        checked(source_location const &sloc = here()) const noexcept -> safe_integral
        {
            if constexpr (BSL_RELEASE_MODE) {
                return *this;
            }

            if (unlikely(m_poisoned)) {
                a_poisoned_safe_integral_was_read();
                assert("a poisoned safe_integral was read", sloc);
                return *this;
            }

            return safe_integral{m_val, m_poisoned, false};
        }

        /// <!-- description -->
        ///   @brief Returns true if the safe_integral must be checked using
        ///     ! or is_poisoned() prior to using get(), or any helper that
        ///     uses get(). In release mode, this function always returns
        ///     false.
        ///   @include safe_integral/example_safe_integral_is_unchecked.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if the safe_integral must be checked using
        ///     ! or is_poisoned() prior to using get(), or any helper that
        ///     uses get(). In release mode, this function always returns
        ///     false.
        ///
        [[nodiscard]] constexpr auto
        is_unchecked() const noexcept -> bool
        {
            if constexpr (BSL_RELEASE_MODE) {
                return false;
            }

            return m_unchecked;
        }

        /// <!-- description -->
        ///   @brief Returns !this->is_unchecked().
        ///   @include safe_integral/example_safe_integral_is_checked.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns !this->is_unchecked()
        ///
        [[nodiscard]] constexpr auto
        is_checked() const noexcept -> bool
        {
            return !this->is_unchecked();
        }

        /// <!-- description -->
        ///   @brief Returns this->is_valid() && this->is_checked()
        ///   @include safe_integral/example_safe_integral_is_valid_and_checked.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns this->is_valid() && this->is_checked()
        ///
        [[nodiscard]] constexpr auto
        is_valid_and_checked() const noexcept -> bool
        {
            /// NOTE:
            /// - In release mode, the checked bit is removed. In debug mode,
            ///   if a value is invalid, it is always unchecked. Note that
            ///   if it is unchecked, that does not mean that it is value,
            ///   so the reverse is not true.
            ///

            if constexpr (BSL_RELEASE_MODE) {
                return this->is_valid();
            }

            return this->is_checked();
        }

        /// <!-- description -->
        ///   @brief Returns a SafeIntegral with the poisoned flag set
        ///   @include safe_integral/example_safe_integral_failure.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a SafeIntegral with the poisoned flag set
        ///
        [[nodiscard]] static constexpr auto
        failure() noexcept -> safe_integral
        {
            return safe_integral{{}, true, true};
        }

        /// <!-- description -->
        ///   @brief Returns *this if lhs.get() > rhs.get(). Otherwise
        ///     returns rhs.
        ///   @include safe_integral/example_safe_integral_max.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param rhs the other integral to compare with
        ///   @return Returns *this if lhs.get() > rhs.get(). Otherwise
        ///     returns rhs.
        ///
        [[nodiscard]] constexpr auto
        max(safe_integral const &rhs) const noexcept -> safe_integral
        {
            if (this->is_invalid()) {
                return safe_integral::failure();
            }

            if (rhs.is_invalid()) {
                return safe_integral::failure();
            }

            if (*this > rhs) {
                return *this;
            }

            return rhs;
        }

        /// <!-- description -->
        ///   @brief Returns *this if lhs.get() < rhs.get(). Otherwise
        ///     returns rhs.
        ///   @include safe_integral/example_safe_integral_min.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param rhs the other integral to compare with
        ///   @return Returns *this if lhs.get() < rhs.get(). Otherwise
        ///     returns rhs.
        ///
        [[nodiscard]] constexpr auto
        min(safe_integral const &rhs) const noexcept -> safe_integral
        {
            if (this->is_invalid()) {
                return safe_integral::failure();
            }

            if (rhs.is_invalid()) {
                return safe_integral::failure();
            }

            if (*this < rhs) {
                return *this;
            }

            return rhs;
        }

        /// <!-- description -->
        ///   @brief Returns *this += rhs. If this operation results in
        ///     an error (e.g., overflow, wrapping, etc.), the result of
        ///     this operation is undefined.
        ///   @include safe_integral/example_safe_integral_assign_add.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param rhs the value to add to *this
        ///   @return Returns *this += rhs. If this operation results in
        ///     an error (e.g., overflow, wrapping, etc.), the result of
        ///     this operation is undefined.
        ///
        [[maybe_unused]] constexpr auto
        operator+=(safe_integral<T> const &rhs) &noexcept -> safe_integral &
        {
            bool const poisoned{builtin_add_overflow(m_val, rhs.m_val, &m_val)};
            this->update_poisoned(poisoned, rhs.is_invalid());

            return *this;
        }

        /// <!-- description -->
        ///   @brief Returns *this += rhs. If this operation results in
        ///     an error (e.g., overflow, wrapping, etc.), the result of
        ///     this operation is undefined.
        ///   @include safe_integral/example_safe_integral_assign_add.hpp
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
        template<typename U, enable_if_t<is_same<T, U>::value, bool> = true>
        [[maybe_unused]] constexpr auto
        operator+=(U const rhs) &noexcept -> safe_integral &
        {
            this->update_poisoned(builtin_add_overflow(m_val, rhs, &m_val));
            return *this;
        }

        /// <!-- description -->
        ///   @brief Returns *this -= rhs. If this operation results in
        ///     an error (e.g., overflow, wrapping, etc.), the result of
        ///     this operation is undefined.
        ///   @include safe_integral/example_safe_integral_assign_sub.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param rhs the value to sub from *this
        ///   @return Returns *this -= rhs. If this operation results in
        ///     an error (e.g., overflow, wrapping, etc.), the result of
        ///     this operation is undefined.
        ///
        [[maybe_unused]] constexpr auto
        operator-=(safe_integral<T> const &rhs) &noexcept -> safe_integral &
        {
            bool const poisoned{builtin_sub_overflow(m_val, rhs.m_val, &m_val)};
            this->update_poisoned(poisoned, rhs.is_invalid());

            return *this;
        }

        /// <!-- description -->
        ///   @brief Returns *this -= rhs. If this operation results in
        ///     an error (e.g., overflow, wrapping, etc.), the result of
        ///     this operation is undefined.
        ///   @include safe_integral/example_safe_integral_assign_sub.hpp
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
        template<typename U, enable_if_t<is_same<T, U>::value, bool> = true>
        [[maybe_unused]] constexpr auto
        operator-=(U const rhs) &noexcept -> safe_integral &
        {
            this->update_poisoned(builtin_sub_overflow(m_val, rhs, &m_val));
            return *this;
        }

        /// <!-- description -->
        ///   @brief Returns *this *= rhs. If this operation results in
        ///     an error (e.g., overflow, wrapping, etc.), the result of
        ///     this operation is undefined.
        ///   @include safe_integral/example_safe_integral_assign_mul.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param rhs the value to multiply *this by
        ///   @return Returns *this *= rhs. If this operation results in
        ///     an error (e.g., overflow, wrapping, etc.), the result of
        ///     this operation is undefined.
        ///
        [[maybe_unused]] constexpr auto
        operator*=(safe_integral<T> const &rhs) &noexcept -> safe_integral &
        {
            bool const poisoned{builtin_mul_overflow(m_val, rhs.m_val, &m_val)};
            this->update_poisoned(poisoned, rhs.is_invalid());

            return *this;
        }

        /// <!-- description -->
        ///   @brief Returns *this *= rhs. If this operation results in
        ///     an error (e.g., overflow, wrapping, etc.), the result of
        ///     this operation is undefined.
        ///   @include safe_integral/example_safe_integral_assign_mul.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam U Used to ensure the provided integer is the same as
        ///     T, effectively preventing implicit conversions from being
        ///     allowed.
        ///   @param rhs the value to multiply *this by
        ///   @return Returns *this *= rhs. If this operation results in
        ///     an error (e.g., overflow, wrapping, etc.), the result of
        ///     this operation is undefined.
        ///
        template<typename U, enable_if_t<is_same<T, U>::value, bool> = true>
        [[maybe_unused]] constexpr auto
        operator*=(U const rhs) &noexcept -> safe_integral &
        {
            this->update_poisoned(builtin_mul_overflow(m_val, rhs, &m_val));
            return *this;
        }

        /// <!-- description -->
        ///   @brief Returns *this /= rhs. If this operation results in
        ///     an error (e.g., overflow, wrapping, etc.), the result of
        ///     this operation is undefined.
        ///   @include safe_integral/example_safe_integral_assign_div.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param rhs the value to divide *this by
        ///   @return Returns *this /= rhs. If this operation results in
        ///     an error (e.g., overflow, wrapping, etc.), the result of
        ///     this operation is undefined.
        ///
        [[maybe_unused]] constexpr auto
        operator/=(safe_integral<T> const &rhs) &noexcept -> safe_integral &
        {
            bool const poisoned{builtin_div_overflow(m_val, rhs.m_val, &m_val)};
            this->update_poisoned(poisoned, rhs.is_invalid());

            return *this;
        }

        /// <!-- description -->
        ///   @brief Returns *this /= rhs. If this operation results in
        ///     an error (e.g., overflow, wrapping, etc.), the result of
        ///     this operation is undefined.
        ///   @include safe_integral/example_safe_integral_assign_div.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam U Used to ensure the provided integer is the same as
        ///     T, effectively preventing implicit conversions from being
        ///     allowed.
        ///   @param rhs the value to divide *this by
        ///   @return Returns *this /= rhs. If this operation results in
        ///     an error (e.g., overflow, wrapping, etc.), the result of
        ///     this operation is undefined.
        ///
        template<typename U, enable_if_t<is_same<T, U>::value, bool> = true>
        [[maybe_unused]] constexpr auto
        operator/=(U const rhs) &noexcept -> safe_integral &
        {
            this->update_poisoned(builtin_div_overflow(m_val, rhs, &m_val));
            return *this;
        }

        /// <!-- description -->
        ///   @brief Returns *this %= rhs. If this operation results in
        ///     an error (e.g., overflow, wrapping, etc.), the result of
        ///     this operation is undefined.
        ///   @include safe_integral/example_safe_integral_assign_mod.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param rhs the value to modulo *this by
        ///   @return Returns *this %= rhs. If this operation results in
        ///     an error (e.g., overflow, wrapping, etc.), the result of
        ///     this operation is undefined.
        ///
        [[maybe_unused]] constexpr auto
        operator%=(safe_integral<T> const &rhs) &noexcept -> safe_integral &
        {
            bool const poisoned{builtin_mod_overflow(m_val, rhs.m_val, &m_val)};
            this->update_poisoned(poisoned, rhs.is_invalid());

            return *this;
        }

        /// <!-- description -->
        ///   @brief Returns *this %= rhs. If this operation results in
        ///     an error (e.g., overflow, wrapping, etc.), the result of
        ///     this operation is undefined.
        ///   @include safe_integral/example_safe_integral_assign_mod.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam U Used to ensure the provided integer is the same as
        ///     T, effectively preventing implicit conversions from being
        ///     allowed.
        ///   @param rhs the value to modulo *this by
        ///   @return Returns *this %= rhs. If this operation results in
        ///     an error (e.g., overflow, wrapping, etc.), the result of
        ///     this operation is undefined.
        ///
        template<typename U, enable_if_t<is_same<T, U>::value, bool> = true>
        [[maybe_unused]] constexpr auto
        operator%=(U const rhs) &noexcept -> safe_integral &
        {
            this->update_poisoned(builtin_mod_overflow(m_val, rhs, &m_val));
            return *this;
        }

        /// <!-- description -->
        ///   @brief Returns *this <<= rhs.
        ///   @include safe_integral/example_safe_integral_assign_lshift.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param rhs the value to shift *this by
        ///   @return Returns *this <<= rhs.
        ///
        [[maybe_unused]] constexpr auto
        operator<<=(safe_integral<T> const &rhs) &noexcept -> safe_integral &
        {
            if constexpr (is_signed<value_type>::value) {
                static_assert(always_false<value_type>(), "signed shift not supported");
            }

            m_val <<= rhs.m_val;
            this->update_poisoned(rhs.is_invalid());
            this->mark_as_checked_if_valid();

            return *this;
        }

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
        operator<<=(U const rhs) &noexcept -> safe_integral &
        {
            if constexpr (is_signed<value_type>::value) {
                static_assert(always_false<value_type>(), "signed shift not supported");
            }

            m_val <<= rhs;
            return *this;
        }

        /// <!-- description -->
        ///   @brief Returns *this >>= rhs.
        ///   @include safe_integral/example_safe_integral_assign_rshift.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param rhs the value to shift *this by
        ///   @return Returns *this >>= rhs.
        ///
        [[maybe_unused]] constexpr auto
        operator>>=(safe_integral<T> const &rhs) &noexcept -> safe_integral &
        {
            if constexpr (is_signed<value_type>::value) {
                static_assert(always_false<value_type>(), "signed shift not supported");
            }

            m_val >>= rhs.m_val;
            this->update_poisoned(rhs.is_invalid());
            this->mark_as_checked_if_valid();

            return *this;
        }

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
        operator>>=(U const rhs) &noexcept -> safe_integral &
        {
            if constexpr (is_signed<value_type>::value) {
                static_assert(always_false<value_type>(), "signed shift not supported");
            }

            m_val >>= rhs;
            return *this;
        }

        /// <!-- description -->
        ///   @brief Returns *this &= rhs.
        ///   @include safe_integral/example_safe_integral_assign_and.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param rhs the value to and *this by
        ///   @return Returns *this &= rhs.
        ///
        [[maybe_unused]] constexpr auto
        operator&=(safe_integral<T> const &rhs) &noexcept -> safe_integral &
        {
            if constexpr (is_signed<value_type>::value) {
                static_assert(always_false<value_type>(), "signed and not supported");
            }

            m_val &= rhs.m_val;
            this->update_poisoned(rhs.is_invalid());
            this->mark_as_checked_if_valid();

            return *this;
        }

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
        operator&=(U const rhs) &noexcept -> safe_integral &
        {
            if constexpr (is_signed<value_type>::value) {
                static_assert(always_false<value_type>(), "signed and not supported");
            }

            m_val &= rhs;
            return *this;
        }

        /// <!-- description -->
        ///   @brief Returns *this |= rhs.
        ///   @include safe_integral/example_safe_integral_assign_or.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param rhs the value to or *this by
        ///   @return Returns *this |= rhs.
        ///
        [[maybe_unused]] constexpr auto
        operator|=(safe_integral<T> const &rhs) &noexcept -> safe_integral &
        {
            if constexpr (is_signed<value_type>::value) {
                static_assert(always_false<value_type>(), "signed or not supported");
            }

            m_val |= rhs.m_val;
            this->update_poisoned(rhs.is_invalid());
            this->mark_as_checked_if_valid();

            return *this;
        }

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
        operator|=(U const rhs) &noexcept -> safe_integral &
        {
            if constexpr (is_signed<value_type>::value) {
                static_assert(always_false<value_type>(), "signed or not supported");
            }

            m_val |= rhs;
            return *this;
        }

        /// <!-- description -->
        ///   @brief Returns *this ^= rhs.
        ///   @include safe_integral/example_safe_integral_assign_xor.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param rhs the value to xor *this by
        ///   @return Returns *this ^= rhs.
        ///
        [[maybe_unused]] constexpr auto
        operator^=(safe_integral<T> const &rhs) &noexcept -> safe_integral &
        {
            if constexpr (is_signed<value_type>::value) {
                static_assert(always_false<value_type>(), "signed xor not supported");
            }

            m_val ^= rhs.m_val;
            this->update_poisoned(rhs.is_invalid());
            this->mark_as_checked_if_valid();

            return *this;
        }

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
        operator^=(U const rhs) &noexcept -> safe_integral &
        {
            if constexpr (is_signed<value_type>::value) {
                static_assert(always_false<value_type>(), "signed xor not supported");
            }

            m_val ^= rhs;
            return *this;
        }

        /// <!-- description -->
        ///   @brief Returns ++(*this). If this operation results in
        ///     an error (e.g., overflow, wrapping, etc.), the result of
        ///     this operation is undefined.
        ///   @include safe_integral/example_safe_integral_inc.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns ++(*this). If this operation results in
        ///     an error (e.g., overflow, wrapping, etc.), the result of
        ///     this operation is undefined.
        ///
        [[maybe_unused]] constexpr auto
        operator++() &noexcept -> safe_integral &
        {
            return *this += static_cast<value_type>(1);
        }

        /// <!-- description -->
        ///   @brief Returns --(*this). If this operation results in
        ///     an error (e.g., overflow, wrapping, etc.), the result of
        ///     this operation is undefined.
        ///   @include safe_integral/example_safe_integral_dec.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns --(*this). If this operation results in
        ///     an error (e.g., overflow, wrapping, etc.), the result of
        ///     this operation is undefined.
        ///
        [[maybe_unused]] constexpr auto
        operator--() &noexcept -> safe_integral &
        {
            return *this -= static_cast<value_type>(1);
        }
    };

    // -------------------------------------------------------------------------
    // supported safe_integral types
    // -------------------------------------------------------------------------

    /// @brief provides the bsl::safe_integral version of bsl::int8
    using safe_i8 = safe_integral<bsl::int8>;
    /// @brief provides the bsl::safe_integral version of bsl::int16
    using safe_i16 = safe_integral<bsl::int16>;
    /// @brief provides the bsl::safe_integral version of bsl::int32
    using safe_i32 = safe_integral<bsl::int32>;
    /// @brief provides the bsl::safe_integral version of bsl::int64
    using safe_i64 = safe_integral<bsl::int64>;

    /// @brief provides the bsl::safe_integral version of bsl::uint8
    using safe_u8 = safe_integral<bsl::uint8>;
    /// @brief provides the bsl::safe_integral version of bsl::uint16
    using safe_u16 = safe_integral<bsl::uint16>;
    /// @brief provides the bsl::safe_integral version of bsl::uint32
    using safe_u32 = safe_integral<bsl::uint32>;
    /// @brief provides the bsl::safe_integral version of bsl::uint64
    using safe_u64 = safe_integral<bsl::uint64>;
    /// @brief provides the bsl::safe_integral version of bsl::uintmx
    using safe_umx = safe_integral<bsl::uintmx>;

    // -------------------------------------------------------------------------
    // == operator
    // -------------------------------------------------------------------------

    /// @cond doxygen off

    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator==(located_arg<safe_i8> const &lhs, located_arg<safe_i8> const &rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) == rhs.get().get(rhs.sloc());    // NOLINT
    }

    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator==(located_arg<safe_i16> const &lhs, located_arg<safe_i16> const &rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) == rhs.get().get(rhs.sloc());    // NOLINT
    }

    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator==(located_arg<safe_i32> const &lhs, located_arg<safe_i32> const &rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) == rhs.get().get(rhs.sloc());    // NOLINT
    }

    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator==(located_arg<safe_i64> const &lhs, located_arg<safe_i64> const &rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) == rhs.get().get(rhs.sloc());    // NOLINT
    }

    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator==(located_arg<safe_u8> const &lhs, located_arg<safe_u8> const &rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) == rhs.get().get(rhs.sloc());    // NOLINT
    }

    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator==(located_arg<safe_u16> const &lhs, located_arg<safe_u16> const &rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) == rhs.get().get(rhs.sloc());    // NOLINT
    }

    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator==(located_arg<safe_u32> const &lhs, located_arg<safe_u32> const &rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) == rhs.get().get(rhs.sloc());    // NOLINT
    }

    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator==(located_arg<safe_u64> const &lhs, located_arg<safe_u64> const &rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) == rhs.get().get(rhs.sloc());    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::int8, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator==(located_arg<safe_i8> const &lhs, U const rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) == rhs;    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::int16, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator==(located_arg<safe_i16> const &lhs, U const rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) == rhs;    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::int32, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator==(located_arg<safe_i32> const &lhs, U const rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) == rhs;    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::int64, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator==(located_arg<safe_i64> const &lhs, U const rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) == rhs;    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::uint8, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator==(located_arg<safe_u8> const &lhs, U const rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) == rhs;    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::uint16, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator==(located_arg<safe_u16> const &lhs, U const rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) == rhs;    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::uint32, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator==(located_arg<safe_u32> const &lhs, U const rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) == rhs;    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::uint64, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator==(located_arg<safe_u64> const &lhs, U const rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) == rhs;    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::int8, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator==(U const lhs, located_arg<safe_i8> const &rhs) noexcept -> bool
    {
        return lhs == rhs.get().get(rhs.sloc());    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::int16, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator==(U const lhs, located_arg<safe_i16> const &rhs) noexcept -> bool
    {
        return lhs == rhs.get().get(rhs.sloc());    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::int32, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator==(U const lhs, located_arg<safe_i32> const &rhs) noexcept -> bool
    {
        return lhs == rhs.get().get(rhs.sloc());    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::int64, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator==(U const lhs, located_arg<safe_i64> const &rhs) noexcept -> bool
    {
        return lhs == rhs.get().get(rhs.sloc());    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::uint8, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator==(U const lhs, located_arg<safe_u8> const &rhs) noexcept -> bool
    {
        return lhs == rhs.get().get(rhs.sloc());    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::uint16, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator==(U const lhs, located_arg<safe_u16> const &rhs) noexcept -> bool
    {
        return lhs == rhs.get().get(rhs.sloc());    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::uint32, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator==(U const lhs, located_arg<safe_u32> const &rhs) noexcept -> bool
    {
        return lhs == rhs.get().get(rhs.sloc());    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::uint64, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator==(U const lhs, located_arg<safe_u64> const &rhs) noexcept -> bool
    {
        return lhs == rhs.get().get(rhs.sloc());    // NOLINT
    }

    /// @endcond doxygen on

    // -------------------------------------------------------------------------
    // != operator
    // -------------------------------------------------------------------------

    /// @cond doxygen off

    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator!=(located_arg<safe_i8> const &lhs, located_arg<safe_i8> const &rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) != rhs.get().get(rhs.sloc());    // NOLINT
    }

    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator!=(located_arg<safe_i16> const &lhs, located_arg<safe_i16> const &rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) != rhs.get().get(rhs.sloc());    // NOLINT
    }

    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator!=(located_arg<safe_i32> const &lhs, located_arg<safe_i32> const &rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) != rhs.get().get(rhs.sloc());    // NOLINT
    }

    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator!=(located_arg<safe_i64> const &lhs, located_arg<safe_i64> const &rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) != rhs.get().get(rhs.sloc());    // NOLINT
    }

    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator!=(located_arg<safe_u8> const &lhs, located_arg<safe_u8> const &rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) != rhs.get().get(rhs.sloc());    // NOLINT
    }

    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator!=(located_arg<safe_u16> const &lhs, located_arg<safe_u16> const &rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) != rhs.get().get(rhs.sloc());    // NOLINT
    }

    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator!=(located_arg<safe_u32> const &lhs, located_arg<safe_u32> const &rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) != rhs.get().get(rhs.sloc());    // NOLINT
    }

    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator!=(located_arg<safe_u64> const &lhs, located_arg<safe_u64> const &rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) != rhs.get().get(rhs.sloc());    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::int8, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator!=(located_arg<safe_i8> const &lhs, U const rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) != rhs;    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::int16, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator!=(located_arg<safe_i16> const &lhs, U const rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) != rhs;    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::int32, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator!=(located_arg<safe_i32> const &lhs, U const rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) != rhs;    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::int64, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator!=(located_arg<safe_i64> const &lhs, U const rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) != rhs;    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::uint8, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator!=(located_arg<safe_u8> const &lhs, U const rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) != rhs;    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::uint16, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator!=(located_arg<safe_u16> const &lhs, U const rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) != rhs;    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::uint32, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator!=(located_arg<safe_u32> const &lhs, U const rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) != rhs;    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::uint64, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator!=(located_arg<safe_u64> const &lhs, U const rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) != rhs;    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::int8, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator!=(U const lhs, located_arg<safe_i8> const &rhs) noexcept -> bool
    {
        return lhs != rhs.get().get(rhs.sloc());    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::int16, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator!=(U const lhs, located_arg<safe_i16> const &rhs) noexcept -> bool
    {
        return lhs != rhs.get().get(rhs.sloc());    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::int32, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator!=(U const lhs, located_arg<safe_i32> const &rhs) noexcept -> bool
    {
        return lhs != rhs.get().get(rhs.sloc());    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::int64, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator!=(U const lhs, located_arg<safe_i64> const &rhs) noexcept -> bool
    {
        return lhs != rhs.get().get(rhs.sloc());    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::uint8, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator!=(U const lhs, located_arg<safe_u8> const &rhs) noexcept -> bool
    {
        return lhs != rhs.get().get(rhs.sloc());    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::uint16, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator!=(U const lhs, located_arg<safe_u16> const &rhs) noexcept -> bool
    {
        return lhs != rhs.get().get(rhs.sloc());    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::uint32, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator!=(U const lhs, located_arg<safe_u32> const &rhs) noexcept -> bool
    {
        return lhs != rhs.get().get(rhs.sloc());    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::uint64, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator!=(U const lhs, located_arg<safe_u64> const &rhs) noexcept -> bool
    {
        return lhs != rhs.get().get(rhs.sloc());    // NOLINT
    }

    /// @endcond doxygen on

    // -------------------------------------------------------------------------
    // < operator
    // -------------------------------------------------------------------------

    /// @cond doxygen off

    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator<(located_arg<safe_i8> const &lhs, located_arg<safe_i8> const &rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) < rhs.get().get(rhs.sloc());    // NOLINT
    }

    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator<(located_arg<safe_i16> const &lhs, located_arg<safe_i16> const &rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) < rhs.get().get(rhs.sloc());    // NOLINT
    }

    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator<(located_arg<safe_i32> const &lhs, located_arg<safe_i32> const &rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) < rhs.get().get(rhs.sloc());    // NOLINT
    }

    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator<(located_arg<safe_i64> const &lhs, located_arg<safe_i64> const &rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) < rhs.get().get(rhs.sloc());    // NOLINT
    }

    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator<(located_arg<safe_u8> const &lhs, located_arg<safe_u8> const &rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) < rhs.get().get(rhs.sloc());    // NOLINT
    }

    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator<(located_arg<safe_u16> const &lhs, located_arg<safe_u16> const &rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) < rhs.get().get(rhs.sloc());    // NOLINT
    }

    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator<(located_arg<safe_u32> const &lhs, located_arg<safe_u32> const &rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) < rhs.get().get(rhs.sloc());    // NOLINT
    }

    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator<(located_arg<safe_u64> const &lhs, located_arg<safe_u64> const &rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) < rhs.get().get(rhs.sloc());    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::int8, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator<(located_arg<safe_i8> const &lhs, U const rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) < rhs;    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::int16, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator<(located_arg<safe_i16> const &lhs, U const rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) < rhs;    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::int32, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator<(located_arg<safe_i32> const &lhs, U const rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) < rhs;    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::int64, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator<(located_arg<safe_i64> const &lhs, U const rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) < rhs;    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::uint8, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator<(located_arg<safe_u8> const &lhs, U const rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) < rhs;    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::uint16, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator<(located_arg<safe_u16> const &lhs, U const rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) < rhs;    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::uint32, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator<(located_arg<safe_u32> const &lhs, U const rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) < rhs;    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::uint64, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator<(located_arg<safe_u64> const &lhs, U const rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) < rhs;    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::int8, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator<(U const lhs, located_arg<safe_i8> const &rhs) noexcept -> bool
    {
        return lhs < rhs.get().get(rhs.sloc());    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::int16, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator<(U const lhs, located_arg<safe_i16> const &rhs) noexcept -> bool
    {
        return lhs < rhs.get().get(rhs.sloc());    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::int32, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator<(U const lhs, located_arg<safe_i32> const &rhs) noexcept -> bool
    {
        return lhs < rhs.get().get(rhs.sloc());    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::int64, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator<(U const lhs, located_arg<safe_i64> const &rhs) noexcept -> bool
    {
        return lhs < rhs.get().get(rhs.sloc());    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::uint8, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator<(U const lhs, located_arg<safe_u8> const &rhs) noexcept -> bool
    {
        return lhs < rhs.get().get(rhs.sloc());    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::uint16, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator<(U const lhs, located_arg<safe_u16> const &rhs) noexcept -> bool
    {
        return lhs < rhs.get().get(rhs.sloc());    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::uint32, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator<(U const lhs, located_arg<safe_u32> const &rhs) noexcept -> bool
    {
        return lhs < rhs.get().get(rhs.sloc());    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::uint64, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator<(U const lhs, located_arg<safe_u64> const &rhs) noexcept -> bool
    {
        return lhs < rhs.get().get(rhs.sloc());    // NOLINT
    }

    /// @endcond doxygen on

    // -------------------------------------------------------------------------
    // > operator
    // -------------------------------------------------------------------------

    /// @cond doxygen off

    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator>(located_arg<safe_i8> const &lhs, located_arg<safe_i8> const &rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) > rhs.get().get(rhs.sloc());    // NOLINT
    }

    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator>(located_arg<safe_i16> const &lhs, located_arg<safe_i16> const &rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) > rhs.get().get(rhs.sloc());    // NOLINT
    }

    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator>(located_arg<safe_i32> const &lhs, located_arg<safe_i32> const &rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) > rhs.get().get(rhs.sloc());    // NOLINT
    }

    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator>(located_arg<safe_i64> const &lhs, located_arg<safe_i64> const &rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) > rhs.get().get(rhs.sloc());    // NOLINT
    }

    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator>(located_arg<safe_u8> const &lhs, located_arg<safe_u8> const &rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) > rhs.get().get(rhs.sloc());    // NOLINT
    }

    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator>(located_arg<safe_u16> const &lhs, located_arg<safe_u16> const &rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) > rhs.get().get(rhs.sloc());    // NOLINT
    }

    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator>(located_arg<safe_u32> const &lhs, located_arg<safe_u32> const &rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) > rhs.get().get(rhs.sloc());    // NOLINT
    }

    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator>(located_arg<safe_u64> const &lhs, located_arg<safe_u64> const &rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) > rhs.get().get(rhs.sloc());    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::int8, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator>(located_arg<safe_i8> const &lhs, U const rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) > rhs;    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::int16, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator>(located_arg<safe_i16> const &lhs, U const rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) > rhs;    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::int32, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator>(located_arg<safe_i32> const &lhs, U const rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) > rhs;    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::int64, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator>(located_arg<safe_i64> const &lhs, U const rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) > rhs;    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::uint8, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator>(located_arg<safe_u8> const &lhs, U const rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) > rhs;    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::uint16, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator>(located_arg<safe_u16> const &lhs, U const rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) > rhs;    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::uint32, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator>(located_arg<safe_u32> const &lhs, U const rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) > rhs;    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::uint64, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator>(located_arg<safe_u64> const &lhs, U const rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) > rhs;    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::int8, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator>(U const lhs, located_arg<safe_i8> const &rhs) noexcept -> bool
    {
        return lhs > rhs.get().get(rhs.sloc());    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::int16, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator>(U const lhs, located_arg<safe_i16> const &rhs) noexcept -> bool
    {
        return lhs > rhs.get().get(rhs.sloc());    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::int32, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator>(U const lhs, located_arg<safe_i32> const &rhs) noexcept -> bool
    {
        return lhs > rhs.get().get(rhs.sloc());    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::int64, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator>(U const lhs, located_arg<safe_i64> const &rhs) noexcept -> bool
    {
        return lhs > rhs.get().get(rhs.sloc());    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::uint8, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator>(U const lhs, located_arg<safe_u8> const &rhs) noexcept -> bool
    {
        return lhs > rhs.get().get(rhs.sloc());    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::uint16, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator>(U const lhs, located_arg<safe_u16> const &rhs) noexcept -> bool
    {
        return lhs > rhs.get().get(rhs.sloc());    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::uint32, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator>(U const lhs, located_arg<safe_u32> const &rhs) noexcept -> bool
    {
        return lhs > rhs.get().get(rhs.sloc());    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::uint64, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator>(U const lhs, located_arg<safe_u64> const &rhs) noexcept -> bool
    {
        return lhs > rhs.get().get(rhs.sloc());    // NOLINT
    }

    /// @endcond doxygen on

    // -------------------------------------------------------------------------
    // <= operator
    // -------------------------------------------------------------------------

    /// @cond doxygen off

    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator<=(located_arg<safe_i8> const &lhs, located_arg<safe_i8> const &rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) <= rhs.get().get(rhs.sloc());    // NOLINT
    }

    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator<=(located_arg<safe_i16> const &lhs, located_arg<safe_i16> const &rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) <= rhs.get().get(rhs.sloc());    // NOLINT
    }

    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator<=(located_arg<safe_i32> const &lhs, located_arg<safe_i32> const &rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) <= rhs.get().get(rhs.sloc());    // NOLINT
    }

    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator<=(located_arg<safe_i64> const &lhs, located_arg<safe_i64> const &rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) <= rhs.get().get(rhs.sloc());    // NOLINT
    }

    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator<=(located_arg<safe_u8> const &lhs, located_arg<safe_u8> const &rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) <= rhs.get().get(rhs.sloc());    // NOLINT
    }

    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator<=(located_arg<safe_u16> const &lhs, located_arg<safe_u16> const &rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) <= rhs.get().get(rhs.sloc());    // NOLINT
    }

    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator<=(located_arg<safe_u32> const &lhs, located_arg<safe_u32> const &rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) <= rhs.get().get(rhs.sloc());    // NOLINT
    }

    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator<=(located_arg<safe_u64> const &lhs, located_arg<safe_u64> const &rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) <= rhs.get().get(rhs.sloc());    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::int8, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator<=(located_arg<safe_i8> const &lhs, U const rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) <= rhs;    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::int16, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator<=(located_arg<safe_i16> const &lhs, U const rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) <= rhs;    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::int32, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator<=(located_arg<safe_i32> const &lhs, U const rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) <= rhs;    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::int64, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator<=(located_arg<safe_i64> const &lhs, U const rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) <= rhs;    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::uint8, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator<=(located_arg<safe_u8> const &lhs, U const rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) <= rhs;    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::uint16, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator<=(located_arg<safe_u16> const &lhs, U const rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) <= rhs;    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::uint32, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator<=(located_arg<safe_u32> const &lhs, U const rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) <= rhs;    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::uint64, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator<=(located_arg<safe_u64> const &lhs, U const rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) <= rhs;    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::int8, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator<=(U const lhs, located_arg<safe_i8> const &rhs) noexcept -> bool
    {
        return lhs <= rhs.get().get(rhs.sloc());    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::int16, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator<=(U const lhs, located_arg<safe_i16> const &rhs) noexcept -> bool
    {
        return lhs <= rhs.get().get(rhs.sloc());    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::int32, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator<=(U const lhs, located_arg<safe_i32> const &rhs) noexcept -> bool
    {
        return lhs <= rhs.get().get(rhs.sloc());    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::int64, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator<=(U const lhs, located_arg<safe_i64> const &rhs) noexcept -> bool
    {
        return lhs <= rhs.get().get(rhs.sloc());    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::uint8, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator<=(U const lhs, located_arg<safe_u8> const &rhs) noexcept -> bool
    {
        return lhs <= rhs.get().get(rhs.sloc());    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::uint16, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator<=(U const lhs, located_arg<safe_u16> const &rhs) noexcept -> bool
    {
        return lhs <= rhs.get().get(rhs.sloc());    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::uint32, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator<=(U const lhs, located_arg<safe_u32> const &rhs) noexcept -> bool
    {
        return lhs <= rhs.get().get(rhs.sloc());    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::uint64, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator<=(U const lhs, located_arg<safe_u64> const &rhs) noexcept -> bool
    {
        return lhs <= rhs.get().get(rhs.sloc());    // NOLINT
    }

    /// @endcond doxygen on

    // -------------------------------------------------------------------------
    // >= operator
    // -------------------------------------------------------------------------

    /// @cond doxygen off

    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator>=(located_arg<safe_i8> const &lhs, located_arg<safe_i8> const &rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) >= rhs.get().get(rhs.sloc());    // NOLINT
    }

    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator>=(located_arg<safe_i16> const &lhs, located_arg<safe_i16> const &rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) >= rhs.get().get(rhs.sloc());    // NOLINT
    }

    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator>=(located_arg<safe_i32> const &lhs, located_arg<safe_i32> const &rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) >= rhs.get().get(rhs.sloc());    // NOLINT
    }

    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator>=(located_arg<safe_i64> const &lhs, located_arg<safe_i64> const &rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) >= rhs.get().get(rhs.sloc());    // NOLINT
    }

    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator>=(located_arg<safe_u8> const &lhs, located_arg<safe_u8> const &rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) >= rhs.get().get(rhs.sloc());    // NOLINT
    }

    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator>=(located_arg<safe_u16> const &lhs, located_arg<safe_u16> const &rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) >= rhs.get().get(rhs.sloc());    // NOLINT
    }

    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator>=(located_arg<safe_u32> const &lhs, located_arg<safe_u32> const &rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) >= rhs.get().get(rhs.sloc());    // NOLINT
    }

    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator>=(located_arg<safe_u64> const &lhs, located_arg<safe_u64> const &rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) >= rhs.get().get(rhs.sloc());    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::int8, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator>=(located_arg<safe_i8> const &lhs, U const rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) >= rhs;    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::int16, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator>=(located_arg<safe_i16> const &lhs, U const rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) >= rhs;    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::int32, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator>=(located_arg<safe_i32> const &lhs, U const rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) >= rhs;    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::int64, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator>=(located_arg<safe_i64> const &lhs, U const rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) >= rhs;    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::uint8, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator>=(located_arg<safe_u8> const &lhs, U const rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) >= rhs;    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::uint16, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator>=(located_arg<safe_u16> const &lhs, U const rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) >= rhs;    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::uint32, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator>=(located_arg<safe_u32> const &lhs, U const rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) >= rhs;    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::uint64, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator>=(located_arg<safe_u64> const &lhs, U const rhs) noexcept -> bool
    {
        return lhs.get().get(lhs.sloc()) >= rhs;    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::int8, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator>=(U const lhs, located_arg<safe_i8> const &rhs) noexcept -> bool
    {
        return lhs >= rhs.get().get(rhs.sloc());    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::int16, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator>=(U const lhs, located_arg<safe_i16> const &rhs) noexcept -> bool
    {
        return lhs >= rhs.get().get(rhs.sloc());    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::int32, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator>=(U const lhs, located_arg<safe_i32> const &rhs) noexcept -> bool
    {
        return lhs >= rhs.get().get(rhs.sloc());    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::int64, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator>=(U const lhs, located_arg<safe_i64> const &rhs) noexcept -> bool
    {
        return lhs >= rhs.get().get(rhs.sloc());    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::uint8, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator>=(U const lhs, located_arg<safe_u8> const &rhs) noexcept -> bool
    {
        return lhs >= rhs.get().get(rhs.sloc());    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::uint16, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator>=(U const lhs, located_arg<safe_u16> const &rhs) noexcept -> bool
    {
        return lhs >= rhs.get().get(rhs.sloc());    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::uint32, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator>=(U const lhs, located_arg<safe_u32> const &rhs) noexcept -> bool
    {
        return lhs >= rhs.get().get(rhs.sloc());    // NOLINT
    }

    template<typename U, enable_if_t<is_same<bsl::uint64, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-documentation)
    operator>=(U const lhs, located_arg<safe_u64> const &rhs) noexcept -> bool
    {
        return lhs >= rhs.get().get(rhs.sloc());    // NOLINT
    }

    /// @endcond doxygen on

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
        auto mut_rhs{rhs};
        if (unlikely(mut_rhs.is_poisoned())) {
            return safe_integral<T>::failure();
        }

        return safe_integral<T>{static_cast<T>(~mut_rhs.get())};
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
        auto mut_rhs{rhs};
        if (unlikely(mut_rhs.is_poisoned())) {
            return safe_integral<T>::failure();
        }

        if (mut_rhs == safe_integral<T>::min_value()) {
            return safe_integral<T>::failure();
        }

        return safe_integral<T>{static_cast<T>(-mut_rhs.get())};
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
}

#endif
