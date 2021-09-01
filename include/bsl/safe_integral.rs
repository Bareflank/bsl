// @copyright
// Copyright (C) 2019 Assured Information Security, Inc.
//
// @copyright
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// @copyright
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// @copyright
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
use crate::Integer;
use crate::SignedInteger;
use crate::SourceLocation;
use crate::UnsignedInteger;
use core::cmp;
use core::fmt;
use core::ops;

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
#[derive(Debug, Default, Copy, Clone)]
pub struct SafeIntegral<T> {
    m_val: T,
    m_poisoned: bool,
    m_unchecked: bool,
}

impl<T> SafeIntegral<T>
where
    T: Integer,
{
    #[cfg(debug_assertions)]
    fn update_poisoned(&mut self, poisoned: bool) {
        self.m_poisoned |= poisoned;
        self.m_unchecked = true;
    }

    #[cfg(not(debug_assertions))]
    fn update_poisoned(&mut self, poisoned: bool) {
        self.m_poisoned |= poisoned;
    }

    #[cfg(debug_assertions)]
    fn verify_poison_has_been_checked(&self, sloc: SourceLocation) {
        if self.m_unchecked {
            crate::assert("SafeIntegrals must be checked before use", sloc);
        } else {
            crate::touch();
        }
    }

    #[cfg(not(debug_assertions))]
    fn verify_poison_has_been_checked(_sloc: SourceLocation) {}

    #[cfg(debug_assertions)]
    fn mark_as_unchecked(&mut self) {
        self.m_unchecked = true;
    }

    #[cfg(not(debug_assertions))]
    fn mark_as_unchecked() {}

    #[cfg(debug_assertions)]
    fn mark_as_checked_if_valid(&mut self) {
        self.m_unchecked = self.m_poisoned;
    }

    #[cfg(not(debug_assertions))]
    fn mark_as_checked_if_valid() {}
}

impl<T> SafeIntegral<T>
where
    T: Sized,
{
    /// <!-- description -->
    ///   @brief Value initialization constructor
    ///
    /// <!-- inputs/outputs -->
    ///   @param val the value to set the SafeIntegral to
    ///
    pub const fn new(val: T) -> Self {
        Self {
            m_val: val,
            m_poisoned: false,
            m_unchecked: false,
        }
    }
}

impl<T> SafeIntegral<T>
where
    T: Integer,
{
    /// <!-- description -->
    ///   @brief Returns a new SafeIntegral given a value and flags
    ///     from another SafeIntegral of a different type.
    ///
    /// <!-- inputs/outputs -->
    ///   @param val the value to set the new SafeIntegral to
    ///   @param flags the SafeIntegral to get the flags from
    ///   @return Returns a new SafeIntegral given a value and flags
    ///     from another SafeIntegral of a different type.
    ///
    pub fn new_with_flags_from<U>(val: T, flags: SafeIntegral<U>) -> Self
    where
        U: Integer,
    {
        Self {
            m_val: val,
            m_poisoned: flags.m_poisoned,
            m_unchecked: flags.m_unchecked,
        }
    }

    /// <!-- description -->
    ///   @brief Returns a new SafeIntegral given an optional value and flags
    ///     from another SafeIntegral of a different type. If the optional
    ///     value is None, SafeIntegral::failure() is returned.
    ///
    /// <!-- inputs/outputs -->
    ///   @param val the optional value to set the new SafeIntegral to
    ///   @param flags the SafeIntegral to get the flags from
    ///   @return Returns a new SafeIntegral given an optional value and flags
    ///     from another SafeIntegral of a different type. If the optional
    ///     value is None, SafeIntegral::failure() is returned.
    ///
    pub fn new_from_option_with_flags_from<U>(val: Option<T>, flags: SafeIntegral<U>) -> Self
    where
        U: Integer,
    {
        match val {
            Some(v) => Self {
                m_val: v,
                m_poisoned: flags.m_poisoned,
                m_unchecked: flags.m_unchecked,
            },
            None => Self {
                m_val: T::default(),
                m_poisoned: true,
                m_unchecked: true,
            },
        }
    }

    /// <!-- description -->
    ///   @brief Returns the max value the bsl::SafeIntegral can store.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns the max value the bsl::SafeIntegral can store.
    ///
    pub fn max_value() -> Self {
        return Self::new(T::max_value());
    }

    /// <!-- description -->
    ///   @brief Returns the min value the bsl::SafeIntegral can store.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns the min value the bsl::SafeIntegral can store.
    ///
    pub fn min_value() -> Self {
        return Self::new(T::min_value());
    }
}

impl<T> SafeIntegral<T>
where
    T: SignedInteger,
{
    /// <!-- description -->
    ///   @brief Returns Self::new(T::magic_neg_1());
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns Self::new(T::magic_neg_1());
    ///
    pub fn magic_neg_1() -> Self {
        return Self::new(T::magic_neg_1());
    }

    /// <!-- description -->
    ///   @brief Returns Self::new(T::magic_neg_1());
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns Self::new(T::magic_neg_1());
    ///
    pub fn magic_neg_2() -> Self {
        return Self::new(T::magic_neg_2());
    }

    /// <!-- description -->
    ///   @brief Returns Self::new(T::magic_neg_1());
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns Self::new(T::magic_neg_1());
    ///
    pub fn magic_neg_3() -> Self {
        return Self::new(T::magic_neg_3());
    }
}

impl<T> SafeIntegral<T>
where
    T: Integer,
{
    /// <!-- description -->
    ///   @brief Returns Self::new(T::magic_0());
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns Self::new(T::magic_0());
    ///
    pub fn magic_0() -> Self {
        return Self::new(T::magic_0());
    }

    /// <!-- description -->
    ///   @brief Returns Self::new(T::magic_1());
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns Self::new(T::magic_1());
    ///
    pub fn magic_1() -> Self {
        return Self::new(T::magic_1());
    }

    /// <!-- description -->
    ///   @brief Returns Self::new(T::magic_2());
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns Self::new(T::magic_2());
    ///
    pub fn magic_2() -> Self {
        return Self::new(T::magic_2());
    }

    /// <!-- description -->
    ///   @brief Returns Self::new(T::magic_3());
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns Self::new(T::magic_3());
    ///
    pub fn magic_3() -> Self {
        return Self::new(T::magic_3());
    }

    /// <!-- description -->
    ///   @brief Returns a reference to the internal integral being managed
    ///     by this class, providing a means to directly read/write the
    ///     integral's value.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns a reference to the internal integral being managed
    ///     by this class, providing a means to directly read/write the
    ///     integral's value.
    ///
    pub fn data_as_ref(&mut self) -> &mut T {
        return &mut self.m_val;
    }

    /// <!-- description -->
    ///   @brief Returns a reference to the internal integral being managed
    ///     by this class, providing a means to directly read the
    ///     integral's value.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns a reference to the internal integral being managed
    ///     by this class, providing a means to directly read the
    ///     integral's value.
    ///
    pub fn cdata_as_ref(&self) -> &T {
        return &self.m_val;
    }

    /// <!-- description -->
    ///   @brief Returns a pointer to the internal integral being managed
    ///     by this class, providing a means to directly read/write the
    ///     integral's value.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns a pointer to the internal integral being managed
    ///     by this class, providing a means to directly read/write the
    ///     integral's value.
    ///
    pub fn data(&mut self) -> *mut T {
        return &mut self.m_val;
    }

    /// <!-- description -->
    ///   @brief Returns a pointer to the internal integral being managed
    ///     by this class, providing a means to directly read the
    ///     integral's value.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns a pointer to the internal integral being managed
    ///     by this class, providing a means to directly read the
    ///     integral's value.
    ///
    pub fn cdata(&mut self) -> *const T {
        return &self.m_val;
    }

    /// <!-- description -->
    ///   @brief Returns the value stored by the bsl::SafeIntegral.
    ///     Attempting to get the value of an invalid SafeIntegral
    ///     results in undefined behavior.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns the value stored by the bsl::SafeIntegral.
    ///     Attempting to get the value of an invalid SafeIntegral
    ///     results in undefined behavior.
    ///
    pub fn get_with_sloc(&self, sloc: SourceLocation) -> T {
        if self.m_poisoned {
            crate::assert("a poisoned SafeIntegral was read", sloc);
        } else {
            crate::touch();
        }

        self.verify_poison_has_been_checked(sloc);
        return self.m_val;
    }

    /// <!-- description -->
    ///   @brief Returns the value stored by the bsl::SafeIntegral.
    ///     Attempting to get the value of an invalid SafeIntegral
    ///     results in undefined behavior.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns the value stored by the bsl::SafeIntegral.
    ///     Attempting to get the value of an invalid SafeIntegral
    ///     results in undefined behavior.
    ///
    #[track_caller]
    pub fn get(&self) -> T {
        return self.get_with_sloc(crate::here());
    }

    /// <!-- description -->
    ///   @brief Returns true if the SafeIntegral is positive.
    ///     Attempting to run is_pos on an invalid SafeIntegral
    ///     results in undefined behavior.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns true if the SafeIntegral is positive
    ///
    #[track_caller]
    pub fn is_pos(&self) -> bool {
        let sloc = crate::here();
        if self.m_poisoned {
            crate::assert("a poisoned SafeIntegral was read", sloc);
        } else {
            crate::touch();
        }

        self.verify_poison_has_been_checked(sloc);
        return self.m_val > T::magic_0();
    }
}

impl<T> SafeIntegral<T>
where
    T: SignedInteger,
{
    /// <!-- description -->
    ///   @brief Returns true if the SafeIntegral is negative.
    ///     Attempting to run is_neg on an invalid SafeIntegral
    ///     results in undefined behavior.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns true if the SafeIntegral is negative
    ///
    #[track_caller]
    pub fn is_neg(&self) -> bool {
        let sloc = crate::here();
        if self.m_poisoned {
            crate::assert("a poisoned SafeIntegral was read", sloc);
        } else {
            crate::touch();
        }

        self.verify_poison_has_been_checked(sloc);
        return self.m_val < T::magic_0();
    }
}

impl<T> SafeIntegral<T>
where
    T: Integer,
{
    /// <!-- description -->
    ///   @brief Returns true if the SafeIntegral is 0.
    ///     Attempting to run is_zero on an invalid SafeIntegral
    ///     results in undefined behavior.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns true if the SafeIntegral is 0
    ///
    #[track_caller]
    pub fn is_zero(&self) -> bool {
        let sloc = crate::here();
        if self.m_poisoned {
            crate::assert("a poisoned SafeIntegral was read", sloc);
        } else {
            crate::touch();
        }

        self.verify_poison_has_been_checked(sloc);
        return self.m_val == T::magic_0();
    }

    /// <!-- description -->
    ///   @brief Returns true if the SafeIntegral has encountered and
    ///     error, false otherwise. This function WILL mark the
    ///     SafeIntegral as checked.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns true if the SafeIntegral has encountered and
    ///     error, false otherwise. This function WILL mark the
    ///     SafeIntegral as checked.
    ///
    pub fn is_poisoned(&mut self) -> bool {
        self.mark_as_checked_if_valid();
        return self.m_poisoned;
    }

    /// <!-- description -->
    ///   @brief Returns true if the SafeIntegral has encountered and
    ///     error, false otherwise. This function DOES NOT marked the
    ///     SafeIntegral as checked.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns true if the SafeIntegral has encountered and
    ///     error, false otherwise. This function DOES NOT marked the
    ///     SafeIntegral as checked.
    ///
    pub fn is_invalid(&self) -> bool {
        return self.m_poisoned;
    }

    /// <!-- description -->
    ///   @brief Returns !self.is_invalid().
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns !self.is_invalid()
    ///
    pub fn is_valid(&self) -> bool {
        return !self.is_invalid();
    }

    /// <!-- description -->
    ///   @brief Returns true if the SafeIntegral is 0. Will
    ///     always return true if an error has been encountered. This
    ///     function WILL mark the SafeIntegral as checked.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns true if the SafeIntegral is 0. Will
    ///     always return true if an error has been encountered. This
    ///     function WILL mark the SafeIntegral as checked.
    ///
    pub fn is_zero_or_poisoned(&mut self) -> bool {
        if self.is_poisoned() {
            return true;
        }

        return self.m_val == T::magic_0();
    }

    /// <!-- description -->
    ///   @brief Returns true if the SafeIntegral is 0. Will
    ///     always return true if an error has been encountered. This
    ///     function DOES NOT marked the SafeIntegral as checked.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns true if the SafeIntegral is 0. Will
    ///     always return true if an error has been encountered. This
    ///     function DOES NOT marked the SafeIntegral as checked.
    ///
    pub fn is_zero_or_invalid(&self) -> bool {
        if self.is_invalid() {
            return true;
        }

        return self.m_val == T::magic_0();
    }

    /// <!-- description -->
    ///   @brief Returns the checked version of the SafeIntegral. This
    ///     should only be used if the SafeIntegral has actually been
    ///     checked, or unit testing has proven that it is impossible for
    ///     the SafeIntegral to become poisoned (because all of the
    ///     possible ways the integral could become poisoned have been
    ///     verified external to the SafeIntegral).
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns the checked version of the SafeIntegral.
    ///
    #[cfg(debug_assertions)]
    #[track_caller]
    pub fn checked(&self) -> Self {
        if self.m_poisoned {
            crate::assert("a poisoned SafeIntegral was read", crate::here());
            return *self;
        }

        return Self {
            m_val: self.m_val,
            m_poisoned: self.m_poisoned,
            m_unchecked: false,
        };
    }

    /// <!-- description -->
    ///   @brief Returns the checked version of the SafeIntegral. This
    ///     should only be used if the SafeIntegral has actually been
    ///     checked, or unit testing has proven that it is impossible for
    ///     the SafeIntegral to become poisoned (because all of the
    ///     possible ways the integral could become poisoned have been
    ///     verified external to the SafeIntegral).
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns the checked version of the SafeIntegral.
    ///
    #[cfg(not(debug_assertions))]
    pub fn checked(&self) -> Self {
        return *self;
    }

    /// <!-- description -->
    ///   @brief Returns true if the SafeIntegral must be checked using
    ///     ! or is_poisoned() prior to using get(), or any helper that
    ///     uses get(). In release mode, this function always returns
    ///     false.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns true if the SafeIntegral must be checked using
    ///     ! or is_poisoned() prior to using get(), or any helper that
    ///     uses get(). In release mode, this function always returns
    ///     false.
    ///
    #[cfg(debug_assertions)]
    pub fn is_unchecked(&self) -> bool {
        return self.m_unchecked;
    }

    /// <!-- description -->
    ///   @brief Returns true if the SafeIntegral must be checked using
    ///     ! or is_poisoned() prior to using get(), or any helper that
    ///     uses get(). In release mode, this function always returns
    ///     false.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns true if the SafeIntegral must be checked using
    ///     ! or is_poisoned() prior to using get(), or any helper that
    ///     uses get(). In release mode, this function always returns
    ///     false.
    ///
    #[cfg(not(debug_assertions))]
    pub fn is_unchecked(&self) -> bool {
        return false;
    }

    /// <!-- description -->
    ///   @brief Returns !self.is_unchecked().
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns !self.is_unchecked()
    ///
    pub fn is_checked(&self) -> bool {
        return !self.is_unchecked();
    }

    /// <!-- description -->
    ///   @brief Returns self.is_valid() && self.is_checked()
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns self.is_valid() && self.is_checked()
    ///
    #[cfg(debug_assertions)]
    pub fn is_valid_and_checked(&self) -> bool {
        if self.is_invalid() {
            return false;
        }

        if self.is_unchecked() {
            return false;
        }

        return true;
    }

    /// <!-- description -->
    ///   @brief Returns self.is_valid() && self.is_checked()
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns self.is_valid() && self.is_checked()
    ///
    #[cfg(not(debug_assertions))]
    pub fn is_valid_and_checked(&self) -> bool {
        return self.is_valid();
    }

    /// <!-- description -->
    ///   @brief Returns a SafeIntegral with the poisoned flag set
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns a SafeIntegral with the poisoned flag set
    ///
    pub fn failure() -> Self {
        return Self {
            m_val: T::default(),
            m_poisoned: true,
            m_unchecked: true,
        };
    }

    /// <!-- description -->
    ///   @brief Returns *self if lhs.get() > rhs.get(). Otherwise
    ///     returns rhs.
    ///
    /// <!-- inputs/outputs -->
    ///   @param rhs the other integral to compare with
    ///   @return Returns *self if lhs.get() > rhs.get(). Otherwise
    ///     returns rhs.
    ///
    pub fn max(&self, rhs: Self) -> Self {
        if self.is_invalid() {
            return SafeIntegral::<T>::failure();
        }

        if rhs.is_invalid() {
            return SafeIntegral::<T>::failure();
        }

        if *self > rhs {
            return *self;
        }

        return rhs;
    }

    /// <!-- description -->
    ///   @brief Returns *self if lhs.get() < rhs.get(). Otherwise
    ///     returns rhs.
    ///
    /// <!-- inputs/outputs -->
    ///   @param rhs the other integral to compare with
    ///   @return Returns *self if lhs.get() < rhs.get(). Otherwise
    ///     returns rhs.
    ///
    pub fn min(&self, rhs: Self) -> Self {
        if self.is_invalid() {
            return SafeIntegral::<T>::failure();
        }

        if rhs.is_invalid() {
            return SafeIntegral::<T>::failure();
        }

        if *self < rhs {
            return *self;
        }

        return rhs;
    }
}

// -----------------------------------------------------------------------------
// Rational
// -----------------------------------------------------------------------------

impl<T> PartialEq for SafeIntegral<T>
where
    T: Integer,
{
    #[track_caller]
    fn eq(&self, rhs: &Self) -> bool {
        let sloc = crate::here();
        return self.get_with_sloc(sloc) == rhs.get_with_sloc(sloc);
    }
}

impl<T> PartialEq<T> for SafeIntegral<T>
where
    T: Integer,
{
    #[track_caller]
    fn eq(&self, rhs: &T) -> bool {
        let sloc = crate::here();
        return self.get_with_sloc(sloc) == *rhs;
    }
}

impl<T> PartialOrd for SafeIntegral<T>
where
    T: Integer,
{
    #[track_caller]
    fn partial_cmp(&self, rhs: &Self) -> Option<cmp::Ordering> {
        let sloc = crate::here();
        return Some(self.get_with_sloc(sloc).cmp(&rhs.get_with_sloc(sloc)));
    }
}

impl<T> PartialOrd<T> for SafeIntegral<T>
where
    T: Integer,
{
    #[track_caller]
    fn partial_cmp(&self, rhs: &T) -> Option<cmp::Ordering> {
        let sloc = crate::here();
        return Some(self.get_with_sloc(sloc).cmp(rhs));
    }
}

// -----------------------------------------------------------------------------
// Arithmetic
// -----------------------------------------------------------------------------

impl<T> ops::AddAssign for SafeIntegral<T>
where
    T: Integer,
{
    fn add_assign(&mut self, rhs: SafeIntegral<T>) {
        match self.m_val.add_checked(rhs.m_val) {
            Some(val) => {
                self.m_val = val;
                self.update_poisoned(rhs.is_invalid());
            }
            None => {
                self.update_poisoned(true);
            }
        }
    }
}

impl<T> ops::AddAssign<T> for SafeIntegral<T>
where
    T: Integer,
{
    fn add_assign(&mut self, rhs: T) {
        match self.m_val.add_checked(rhs) {
            Some(val) => {
                self.m_val = val;
                self.mark_as_unchecked();
            }
            None => {
                self.update_poisoned(true);
            }
        }
    }
}

impl<T> ops::Add<SafeIntegral<T>> for SafeIntegral<T>
where
    T: Integer,
{
    type Output = SafeIntegral<T>;
    fn add(self, rhs: SafeIntegral<T>) -> Self::Output {
        let mut ret = self.clone();
        ret += rhs;
        return ret;
    }
}

impl<T> ops::Add<T> for SafeIntegral<T>
where
    T: Integer,
{
    type Output = SafeIntegral<T>;
    fn add(self, rhs: T) -> Self::Output {
        let mut ret = self.clone();
        ret += rhs;
        return ret;
    }
}

impl<T> ops::SubAssign for SafeIntegral<T>
where
    T: Integer,
{
    fn sub_assign(&mut self, rhs: SafeIntegral<T>) {
        match self.m_val.sub_checked(rhs.m_val) {
            Some(val) => {
                self.m_val = val;
                self.update_poisoned(rhs.is_invalid());
            }
            None => {
                self.update_poisoned(true);
            }
        }
    }
}

impl<T> ops::SubAssign<T> for SafeIntegral<T>
where
    T: Integer,
{
    fn sub_assign(&mut self, rhs: T) {
        match self.m_val.sub_checked(rhs) {
            Some(val) => {
                self.m_val = val;
                self.mark_as_unchecked();
            }
            None => {
                self.update_poisoned(true);
            }
        }
    }
}

impl<T> ops::Sub<SafeIntegral<T>> for SafeIntegral<T>
where
    T: Integer,
{
    type Output = SafeIntegral<T>;
    fn sub(self, rhs: SafeIntegral<T>) -> Self::Output {
        let mut ret = self.clone();
        ret -= rhs;
        return ret;
    }
}

impl<T> ops::Sub<T> for SafeIntegral<T>
where
    T: Integer,
{
    type Output = SafeIntegral<T>;
    fn sub(self, rhs: T) -> Self::Output {
        let mut ret = self.clone();
        ret -= rhs;
        return ret;
    }
}

impl<T> ops::MulAssign for SafeIntegral<T>
where
    T: Integer,
{
    fn mul_assign(&mut self, rhs: SafeIntegral<T>) {
        match self.m_val.mul_checked(rhs.m_val) {
            Some(val) => {
                self.m_val = val;
                self.update_poisoned(rhs.is_invalid());
            }
            None => {
                self.update_poisoned(true);
            }
        }
    }
}

impl<T> ops::MulAssign<T> for SafeIntegral<T>
where
    T: Integer,
{
    fn mul_assign(&mut self, rhs: T) {
        match self.m_val.mul_checked(rhs) {
            Some(val) => {
                self.m_val = val;
                self.mark_as_unchecked();
            }
            None => {
                self.update_poisoned(true);
            }
        }
    }
}

impl<T> ops::Mul<SafeIntegral<T>> for SafeIntegral<T>
where
    T: Integer,
{
    type Output = SafeIntegral<T>;
    fn mul(self, rhs: SafeIntegral<T>) -> Self::Output {
        let mut ret = self.clone();
        ret *= rhs;
        return ret;
    }
}

impl<T> ops::Mul<T> for SafeIntegral<T>
where
    T: Integer,
{
    type Output = SafeIntegral<T>;
    fn mul(self, rhs: T) -> Self::Output {
        let mut ret = self.clone();
        ret *= rhs;
        return ret;
    }
}

impl<T> ops::DivAssign for SafeIntegral<T>
where
    T: Integer,
{
    fn div_assign(&mut self, rhs: SafeIntegral<T>) {
        match self.m_val.div_checked(rhs.m_val) {
            Some(val) => {
                self.m_val = val;
                self.update_poisoned(rhs.is_invalid());
            }
            None => {
                self.update_poisoned(true);
            }
        }
    }
}

impl<T> ops::DivAssign<T> for SafeIntegral<T>
where
    T: Integer,
{
    fn div_assign(&mut self, rhs: T) {
        match self.m_val.div_checked(rhs) {
            Some(val) => {
                self.m_val = val;
                self.mark_as_unchecked();
            }
            None => {
                self.update_poisoned(true);
            }
        }
    }
}

impl<T> ops::Div<SafeIntegral<T>> for SafeIntegral<T>
where
    T: Integer,
{
    type Output = SafeIntegral<T>;
    fn div(self, rhs: SafeIntegral<T>) -> Self::Output {
        let mut ret = self.clone();
        ret /= rhs;
        return ret;
    }
}

impl<T> ops::Div<T> for SafeIntegral<T>
where
    T: Integer,
{
    type Output = SafeIntegral<T>;
    fn div(self, rhs: T) -> Self::Output {
        let mut ret = self.clone();
        ret /= rhs;
        return ret;
    }
}

impl<T> ops::RemAssign for SafeIntegral<T>
where
    T: Integer,
{
    fn rem_assign(&mut self, rhs: SafeIntegral<T>) {
        match self.m_val.rem_checked(rhs.m_val) {
            Some(val) => {
                self.m_val = val;
                self.update_poisoned(rhs.is_invalid());
            }
            None => {
                self.update_poisoned(true);
            }
        }
    }
}

impl<T> ops::RemAssign<T> for SafeIntegral<T>
where
    T: Integer,
{
    fn rem_assign(&mut self, rhs: T) {
        match self.m_val.rem_checked(rhs) {
            Some(val) => {
                self.m_val = val;
                self.mark_as_unchecked();
            }
            None => {
                self.update_poisoned(true);
            }
        }
    }
}

impl<T> ops::Rem<SafeIntegral<T>> for SafeIntegral<T>
where
    T: Integer,
{
    type Output = SafeIntegral<T>;
    fn rem(self, rhs: SafeIntegral<T>) -> Self::Output {
        let mut ret = self.clone();
        ret %= rhs;
        return ret;
    }
}

impl<T> ops::Rem<T> for SafeIntegral<T>
where
    T: Integer,
{
    type Output = SafeIntegral<T>;
    fn rem(self, rhs: T) -> Self::Output {
        let mut ret = self.clone();
        ret %= rhs;
        return ret;
    }
}

// -----------------------------------------------------------------------------
// Shift
// -----------------------------------------------------------------------------

impl<T> ops::ShlAssign<SafeIntegral<u32>> for SafeIntegral<T>
where
    T: UnsignedInteger,
{
    fn shl_assign(&mut self, rhs: SafeIntegral<u32>) {
        self.m_val = self.m_val.shl_wrapping(rhs.m_val);
        self.update_poisoned(rhs.is_invalid());
        self.mark_as_checked_if_valid();
    }
}

impl<T> ops::ShlAssign<u32> for SafeIntegral<T>
where
    T: UnsignedInteger,
{
    fn shl_assign(&mut self, rhs: u32) {
        self.m_val = self.m_val.shl_wrapping(rhs);
    }
}

impl<T> ops::Shl<SafeIntegral<u32>> for SafeIntegral<T>
where
    T: UnsignedInteger,
{
    type Output = SafeIntegral<T>;
    fn shl(self, rhs: SafeIntegral<u32>) -> Self::Output {
        let mut ret = self.clone();
        ret <<= rhs;
        return ret;
    }
}

impl<T> ops::Shl<u32> for SafeIntegral<T>
where
    T: UnsignedInteger,
{
    type Output = SafeIntegral<T>;
    fn shl(self, rhs: u32) -> Self::Output {
        let mut ret = self.clone();
        ret <<= rhs;
        return ret;
    }
}

impl<T> ops::ShrAssign<SafeIntegral<u32>> for SafeIntegral<T>
where
    T: UnsignedInteger,
{
    fn shr_assign(&mut self, rhs: SafeIntegral<u32>) {
        self.m_val = self.m_val.shr_wrapping(rhs.m_val);
        self.update_poisoned(rhs.is_invalid());
        self.mark_as_checked_if_valid();
    }
}

impl<T> ops::ShrAssign<u32> for SafeIntegral<T>
where
    T: UnsignedInteger,
{
    fn shr_assign(&mut self, rhs: u32) {
        self.m_val = self.m_val.shr_wrapping(rhs);
    }
}

impl<T> ops::Shr<SafeIntegral<u32>> for SafeIntegral<T>
where
    T: UnsignedInteger,
{
    type Output = SafeIntegral<T>;
    fn shr(self, rhs: SafeIntegral<u32>) -> Self::Output {
        let mut ret = self.clone();
        ret >>= rhs;
        return ret;
    }
}

impl<T> ops::Shr<u32> for SafeIntegral<T>
where
    T: UnsignedInteger,
{
    type Output = SafeIntegral<T>;
    fn shr(self, rhs: u32) -> Self::Output {
        let mut ret = self.clone();
        ret >>= rhs;
        return ret;
    }
}

// -----------------------------------------------------------------------------
// Binary
// -----------------------------------------------------------------------------

impl<T> ops::BitAndAssign for SafeIntegral<T>
where
    T: UnsignedInteger,
{
    fn bitand_assign(&mut self, rhs: Self) {
        self.m_val &= rhs.m_val;
        self.update_poisoned(rhs.is_invalid());
        self.mark_as_checked_if_valid();
    }
}

impl<T> ops::BitAndAssign<T> for SafeIntegral<T>
where
    T: UnsignedInteger,
{
    fn bitand_assign(&mut self, rhs: T) {
        self.m_val &= rhs;
    }
}

impl<T> ops::BitAnd for SafeIntegral<T>
where
    T: UnsignedInteger,
{
    type Output = SafeIntegral<T>;
    fn bitand(self, rhs: SafeIntegral<T>) -> Self::Output {
        let mut ret = self.clone();
        ret &= rhs;
        return ret;
    }
}

impl<T> ops::BitAnd<T> for SafeIntegral<T>
where
    T: UnsignedInteger,
{
    type Output = SafeIntegral<T>;
    fn bitand(self, rhs: T) -> Self::Output {
        let mut ret = self.clone();
        ret &= rhs;
        return ret;
    }
}

impl<T> ops::BitOrAssign for SafeIntegral<T>
where
    T: UnsignedInteger,
{
    fn bitor_assign(&mut self, rhs: Self) {
        self.m_val |= rhs.m_val;
        self.update_poisoned(rhs.is_invalid());
        self.mark_as_checked_if_valid();
    }
}

impl<T> ops::BitOrAssign<T> for SafeIntegral<T>
where
    T: UnsignedInteger,
{
    fn bitor_assign(&mut self, rhs: T) {
        self.m_val |= rhs;
    }
}

impl<T> ops::BitOr for SafeIntegral<T>
where
    T: UnsignedInteger,
{
    type Output = SafeIntegral<T>;
    fn bitor(self, rhs: SafeIntegral<T>) -> Self::Output {
        let mut ret = self.clone();
        ret |= rhs;
        return ret;
    }
}

impl<T> ops::BitOr<T> for SafeIntegral<T>
where
    T: UnsignedInteger,
{
    type Output = SafeIntegral<T>;
    fn bitor(self, rhs: T) -> Self::Output {
        let mut ret = self.clone();
        ret |= rhs;
        return ret;
    }
}

impl<T> ops::BitXorAssign for SafeIntegral<T>
where
    T: UnsignedInteger,
{
    fn bitxor_assign(&mut self, rhs: Self) {
        self.m_val ^= rhs.m_val;
        self.update_poisoned(rhs.is_invalid());
        self.mark_as_checked_if_valid();
    }
}

impl<T> ops::BitXorAssign<T> for SafeIntegral<T>
where
    T: UnsignedInteger,
{
    fn bitxor_assign(&mut self, rhs: T) {
        self.m_val ^= rhs;
    }
}

impl<T> ops::BitXor for SafeIntegral<T>
where
    T: UnsignedInteger,
{
    type Output = SafeIntegral<T>;
    fn bitxor(self, rhs: SafeIntegral<T>) -> Self::Output {
        let mut ret = self.clone();
        ret ^= rhs;
        return ret;
    }
}

impl<T> ops::BitXor<T> for SafeIntegral<T>
where
    T: UnsignedInteger,
{
    type Output = SafeIntegral<T>;
    fn bitxor(self, rhs: T) -> Self::Output {
        let mut ret = self.clone();
        ret ^= rhs;
        return ret;
    }
}

// -----------------------------------------------------------------------------
// Complement
// -----------------------------------------------------------------------------

impl<T> ops::Not for SafeIntegral<T>
where
    T: UnsignedInteger,
{
    type Output = Self;
    fn not(self) -> Self::Output {
        let mut ret = self.clone();
        ret.m_val = !ret.m_val;
        return ret;
    }
}

// -----------------------------------------------------------------------------
// Negation
// -----------------------------------------------------------------------------

impl<T> ops::Neg for SafeIntegral<T>
where
    T: SignedInteger,
{
    type Output = Self;
    fn neg(self) -> Self::Output {
        let mut ret = self.clone();
        match self.m_val.neg_checked() {
            Some(val) => {
                ret.m_val = val;
            }
            None => {
                ret.update_poisoned(true);
            }
        }

        return ret;
    }
}

// -----------------------------------------------------------------------------
// Output
// -----------------------------------------------------------------------------

impl<T> fmt::Display for SafeIntegral<T>
where
    T: Integer,
{
    #[track_caller]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.is_invalid() {
            return write!(f, "[error]");
        } else {
            let val = self.get_with_sloc(crate::here());
            return write!(f, "{:?}", &val);
        }
    }
}

impl<T> fmt::Binary for SafeIntegral<T>
where
    T: Integer,
{
    #[track_caller]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_invalid() {
            return write!(f, "[error]");
        } else {
            let val = self.get_with_sloc(crate::here());
            return fmt::Binary::fmt(&val, f);
        }
    }
}

impl<T> fmt::LowerExp for SafeIntegral<T>
where
    T: Integer,
{
    #[track_caller]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_invalid() {
            return write!(f, "[error]");
        } else {
            let val = self.get_with_sloc(crate::here());
            return fmt::LowerExp::fmt(&val, f);
        }
    }
}

impl<T> fmt::LowerHex for SafeIntegral<T>
where
    T: Integer,
{
    #[track_caller]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_invalid() {
            return write!(f, "[error]");
        } else {
            let val = self.get_with_sloc(crate::here());
            return fmt::LowerHex::fmt(&val, f);
        }
    }
}

impl<T> fmt::Octal for SafeIntegral<T>
where
    T: Integer,
{
    #[track_caller]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_invalid() {
            return write!(f, "[error]");
        } else {
            let val = self.get_with_sloc(crate::here());
            return fmt::Octal::fmt(&val, f);
        }
    }
}

impl<T> fmt::UpperExp for SafeIntegral<T>
where
    T: Integer,
{
    #[track_caller]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_invalid() {
            return write!(f, "[error]");
        } else {
            let val = self.get_with_sloc(crate::here());
            return fmt::UpperExp::fmt(&val, f);
        }
    }
}

impl<T> fmt::UpperHex for SafeIntegral<T>
where
    T: Integer,
{
    #[track_caller]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_invalid() {
            return write!(f, "[error]");
        } else {
            let val = self.get_with_sloc(crate::here());
            return fmt::UpperHex::fmt(&val, f);
        }
    }
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// <!-- description -->
///   @brief Returns SafeIntegral<T>{val}
///
/// <!-- inputs/outputs -->
///   @tparam T the integral type to make safe.
///   @param val the integral to make safe
///   @return Returns SafeIntegral<T>{val}
///
pub const fn make_safe<T>(val: T) -> SafeIntegral<T> {
    return SafeIntegral::<T>::new(val);
}

// -----------------------------------------------------------------------------
// Types
// -----------------------------------------------------------------------------

/// @brief provides the bsl::SafeIntegral version of i8
pub type SafeI8 = SafeIntegral<i8>;
/// @brief provides the bsl::SafeIntegral version of i16
pub type SafeI16 = SafeIntegral<i16>;
/// @brief provides the bsl::SafeIntegral version of i32
pub type SafeI32 = SafeIntegral<i32>;
/// @brief provides the bsl::SafeIntegral version of i64
pub type SafeI64 = SafeIntegral<i64>;

/// @brief provides the bsl::SafeIntegral version of u8
pub type SafeU8 = SafeIntegral<u8>;
/// @brief provides the bsl::SafeIntegral version of u16
pub type SafeU16 = SafeIntegral<u16>;
/// @brief provides the bsl::SafeIntegral version of u32
pub type SafeU32 = SafeIntegral<u32>;
/// @brief provides the bsl::SafeIntegral version of u64
pub type SafeU64 = SafeIntegral<u64>;
/// @brief provides the bsl::SafeIntegral version of usize
pub type SafeUMx = SafeIntegral<usize>;

// -----------------------------------------------------------------------------
// Unit Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod safe_integral_tests {
    use super::*;

    fn safe_integral_constructors_for_t<T>()
    where
        T: Integer,
    {
        assert!(SafeIntegral::<T>::default().is_valid());
        assert!(SafeIntegral::<T>::new(T::magic_1()).is_valid());

        let val = SafeIntegral::<T>::default();
        assert!(SafeIntegral::<T>::new_with_flags_from(val.get(), val).is_valid());
        let val = SafeIntegral::<T>::failure();
        assert!(SafeIntegral::<T>::new_with_flags_from(*val.cdata_as_ref(), val).is_invalid());

        let val = SafeIntegral::<T>::default();
        let opt = Some(*val.cdata_as_ref());
        assert!(SafeIntegral::<T>::new_from_option_with_flags_from(opt, val).is_valid());
        let val = SafeIntegral::<T>::failure();
        let opt = Some(*val.cdata_as_ref());
        assert!(SafeIntegral::<T>::new_from_option_with_flags_from(opt, val).is_invalid());
    }

    #[test]
    fn safe_integral_constructors() {
        safe_integral_constructors_for_t::<i8>();
        safe_integral_constructors_for_t::<i16>();
        safe_integral_constructors_for_t::<i32>();
        safe_integral_constructors_for_t::<i64>();
        safe_integral_constructors_for_t::<u8>();
        safe_integral_constructors_for_t::<u16>();
        safe_integral_constructors_for_t::<u32>();
        safe_integral_constructors_for_t::<u64>();
        safe_integral_constructors_for_t::<usize>();
    }

    fn safe_integral_debug_for_t<T>()
    where
        T: Integer,
    {
        println!("{}", SafeIntegral::<T>::magic_1());
        println!("{}", SafeIntegral::<T>::failure());
        println!("{:?}", SafeIntegral::<T>::magic_1());
        println!("{:?}", SafeIntegral::<T>::failure());
        println!("{:x?}", SafeIntegral::<T>::magic_1());
        println!("{:x?}", SafeIntegral::<T>::failure());
        println!("{:X?}", SafeIntegral::<T>::magic_1());
        println!("{:X?}", SafeIntegral::<T>::failure());
        println!("{:o}", SafeIntegral::<T>::magic_1());
        println!("{:o}", SafeIntegral::<T>::failure());
        println!("{:x}", SafeIntegral::<T>::magic_1());
        println!("{:x}", SafeIntegral::<T>::failure());
        println!("{:X}", SafeIntegral::<T>::magic_1());
        println!("{:X}", SafeIntegral::<T>::failure());
        println!("{:b}", SafeIntegral::<T>::magic_1());
        println!("{:b}", SafeIntegral::<T>::failure());
        println!("{:e}", SafeIntegral::<T>::magic_1());
        println!("{:e}", SafeIntegral::<T>::failure());
        println!("{:E}", SafeIntegral::<T>::magic_1());
        println!("{:E}", SafeIntegral::<T>::failure());
    }

    #[test]
    fn safe_integral_debug() {
        safe_integral_debug_for_t::<i8>();
        safe_integral_debug_for_t::<i16>();
        safe_integral_debug_for_t::<i32>();
        safe_integral_debug_for_t::<i64>();
        safe_integral_debug_for_t::<u8>();
        safe_integral_debug_for_t::<u16>();
        safe_integral_debug_for_t::<u32>();
        safe_integral_debug_for_t::<u64>();
        safe_integral_debug_for_t::<usize>();
    }

    fn safe_integral_max_min_for_t<T>()
    where
        T: Integer,
    {
        assert!(SafeIntegral::<T>::max_value() == T::max_value());
        assert!(SafeIntegral::<T>::min_value() == T::min_value());
    }

    #[test]
    fn safe_integral_max_min() {
        safe_integral_max_min_for_t::<i8>();
        safe_integral_max_min_for_t::<i16>();
        safe_integral_max_min_for_t::<i32>();
        safe_integral_max_min_for_t::<i64>();
        safe_integral_max_min_for_t::<u8>();
        safe_integral_max_min_for_t::<u16>();
        safe_integral_max_min_for_t::<u32>();
        safe_integral_max_min_for_t::<u64>();
        safe_integral_max_min_for_t::<usize>();
    }

    fn safe_integral_magic_for_t<T>()
    where
        T: Integer,
    {
        assert!(SafeIntegral::<T>::magic_0() == T::magic_0());
        assert!(SafeIntegral::<T>::magic_1() == T::magic_1());
        assert!(SafeIntegral::<T>::magic_2() == T::magic_2());
        assert!(SafeIntegral::<T>::magic_3() == T::magic_3());
    }

    fn safe_integral_magic_for_signed_t<T>()
    where
        T: SignedInteger,
    {
        assert!(SafeIntegral::<T>::magic_neg_1() == T::magic_neg_1());
    }

    #[test]
    fn safe_integral_magic() {
        safe_integral_magic_for_t::<i8>();
        safe_integral_magic_for_t::<i16>();
        safe_integral_magic_for_t::<i32>();
        safe_integral_magic_for_t::<i64>();
        safe_integral_magic_for_t::<u8>();
        safe_integral_magic_for_t::<u16>();
        safe_integral_magic_for_t::<u32>();
        safe_integral_magic_for_t::<u64>();
        safe_integral_magic_for_t::<usize>();

        safe_integral_magic_for_signed_t::<i8>();
        safe_integral_magic_for_signed_t::<i16>();
        safe_integral_magic_for_signed_t::<i32>();
        safe_integral_magic_for_signed_t::<i64>();
    }

    fn safe_integral_data_for_t<T>()
    where
        T: Integer,
    {
        let mut val = SafeIntegral::<T>::default();

        unsafe {
            *val.data_as_ref() = T::magic_1();
            assert!(*val.data_as_ref() == T::magic_1());
            assert!(*val.cdata_as_ref() == T::magic_1());
            *val.data_as_ref() = T::magic_2();
            assert!(*val.data_as_ref() == T::magic_2());
            assert!(*val.cdata_as_ref() == T::magic_2());

            *val.data() = T::magic_1();
            assert!(*val.data() == T::magic_1());
            assert!(*val.cdata() == T::magic_1());
            *val.data() = T::magic_2();
            assert!(*val.data() == T::magic_2());
            assert!(*val.cdata() == T::magic_2());
        }
    }

    #[test]
    fn safe_integral_data() {
        safe_integral_data_for_t::<i8>();
        safe_integral_data_for_t::<i16>();
        safe_integral_data_for_t::<i32>();
        safe_integral_data_for_t::<i64>();
        safe_integral_data_for_t::<u8>();
        safe_integral_data_for_t::<u16>();
        safe_integral_data_for_t::<u32>();
        safe_integral_data_for_t::<u64>();
        safe_integral_data_for_t::<usize>();
    }

    fn safe_integral_get_for_t<T>()
    where
        T: Integer,
    {
        let val = SafeIntegral::new(T::magic_1());
        assert!(val.get() == T::magic_1());
    }

    #[test]
    fn safe_integral_get() {
        safe_integral_get_for_t::<i8>();
        safe_integral_get_for_t::<i16>();
        safe_integral_get_for_t::<i32>();
        safe_integral_get_for_t::<i64>();
        safe_integral_get_for_t::<u8>();
        safe_integral_get_for_t::<u16>();
        safe_integral_get_for_t::<u32>();
        safe_integral_get_for_t::<u64>();
        safe_integral_get_for_t::<usize>();
    }

    fn safe_integral_is_queries_for_t<T>()
    where
        T: Integer,
    {
        assert_eq!(SafeIntegral::<T>::magic_0().is_zero(), true);
        assert_eq!(SafeIntegral::<T>::magic_0().is_pos(), false);
        assert_eq!(SafeIntegral::<T>::magic_1().is_zero(), false);
        assert_eq!(SafeIntegral::<T>::magic_1().is_pos(), true);
    }

    fn safe_integral_is_queries_for_signed_t<T>()
    where
        T: SignedInteger,
    {
        assert_eq!(SafeIntegral::<T>::magic_0().is_neg(), false);
        assert_eq!(SafeIntegral::<T>::magic_1().is_neg(), false);
        assert_eq!(SafeIntegral::<T>::magic_neg_1().is_neg(), true);
    }

    #[test]
    fn safe_integral_is_queries() {
        safe_integral_is_queries_for_t::<i8>();
        safe_integral_is_queries_for_t::<i16>();
        safe_integral_is_queries_for_t::<i32>();
        safe_integral_is_queries_for_t::<i64>();
        safe_integral_is_queries_for_t::<u8>();
        safe_integral_is_queries_for_t::<u16>();
        safe_integral_is_queries_for_t::<u32>();
        safe_integral_is_queries_for_t::<u64>();
        safe_integral_is_queries_for_t::<usize>();

        safe_integral_is_queries_for_signed_t::<i8>();
        safe_integral_is_queries_for_signed_t::<i16>();
        safe_integral_is_queries_for_signed_t::<i32>();
        safe_integral_is_queries_for_signed_t::<i64>();
    }

    fn safe_integral_failure_for_t<T>()
    where
        T: Integer,
    {
        assert_eq!(SafeIntegral::<T>::magic_0().is_poisoned(), false);
        assert_eq!(SafeIntegral::<T>::magic_0().is_invalid(), false);
        assert_eq!(SafeIntegral::<T>::magic_0().is_valid(), true);
        assert_eq!(SafeIntegral::<T>::magic_0().is_zero_or_poisoned(), true);
        assert_eq!(SafeIntegral::<T>::magic_0().is_zero_or_invalid(), true);
        assert_eq!(SafeIntegral::<T>::magic_0().is_unchecked(), false);
        assert_eq!(SafeIntegral::<T>::magic_0().is_checked(), true);
        assert_eq!(SafeIntegral::<T>::magic_0().is_valid_and_checked(), true);

        assert_eq!(SafeIntegral::<T>::magic_1().is_poisoned(), false);
        assert_eq!(SafeIntegral::<T>::magic_1().is_invalid(), false);
        assert_eq!(SafeIntegral::<T>::magic_1().is_valid(), true);
        assert_eq!(SafeIntegral::<T>::magic_1().is_zero_or_poisoned(), false);
        assert_eq!(SafeIntegral::<T>::magic_1().is_zero_or_invalid(), false);
        assert_eq!(SafeIntegral::<T>::magic_1().is_unchecked(), false);
        assert_eq!(SafeIntegral::<T>::magic_1().is_checked(), true);
        assert_eq!(SafeIntegral::<T>::magic_1().is_valid_and_checked(), true);

        assert_eq!(SafeIntegral::<T>::failure().is_poisoned(), true);
        assert_eq!(SafeIntegral::<T>::failure().is_invalid(), true);
        assert_eq!(SafeIntegral::<T>::failure().is_valid(), false);
        assert_eq!(SafeIntegral::<T>::failure().is_zero_or_poisoned(), true);
        assert_eq!(SafeIntegral::<T>::failure().is_zero_or_invalid(), true);
        assert_eq!(SafeIntegral::<T>::failure().is_unchecked(), true);
        assert_eq!(SafeIntegral::<T>::failure().is_checked(), false);
        assert_eq!(SafeIntegral::<T>::failure().is_valid_and_checked(), false);

        let val = SafeIntegral::<T>::magic_1() + SafeIntegral::<T>::magic_1();
        assert_eq!(val.is_invalid(), false);
        assert_eq!(val.is_valid(), true);
        assert_eq!(val.is_zero_or_invalid(), false);
        assert_eq!(val.is_unchecked(), true);
        assert_eq!(val.is_checked(), false);
        assert_eq!(val.is_valid_and_checked(), false);
    }

    #[test]
    fn safe_integral_failure() {
        safe_integral_failure_for_t::<i8>();
        safe_integral_failure_for_t::<i16>();
        safe_integral_failure_for_t::<i32>();
        safe_integral_failure_for_t::<i64>();
        safe_integral_failure_for_t::<u8>();
        safe_integral_failure_for_t::<u16>();
        safe_integral_failure_for_t::<u32>();
        safe_integral_failure_for_t::<u64>();
        safe_integral_failure_for_t::<usize>();
    }

    fn safe_integral_max_for_t<T>()
    where
        T: Integer,
    {
        let val1 = super::SafeIntegral::<T>::magic_1();
        let val2 = super::SafeIntegral::<T>::magic_2();
        let fail = super::SafeIntegral::<T>::failure();

        assert!(val1.max(val2) == val2);
        assert!(val2.max(val1) == val2);

        assert!(val1.max(fail).is_invalid());
        assert!(fail.max(val1).is_invalid());
    }

    #[test]
    fn safe_integral_max() {
        safe_integral_max_for_t::<i8>();
        safe_integral_max_for_t::<i16>();
        safe_integral_max_for_t::<i32>();
        safe_integral_max_for_t::<i64>();
        safe_integral_max_for_t::<u8>();
        safe_integral_max_for_t::<u16>();
        safe_integral_max_for_t::<u32>();
        safe_integral_max_for_t::<u64>();
        safe_integral_max_for_t::<usize>();
    }

    fn safe_integral_min_for_t<T>()
    where
        T: Integer,
    {
        let val1 = super::SafeIntegral::<T>::magic_1();
        let val2 = super::SafeIntegral::<T>::magic_2();
        let fail = super::SafeIntegral::<T>::failure();

        assert!(val1.min(val2) == val1);
        assert!(val2.min(val1) == val1);

        assert!(val1.min(fail).is_invalid());
        assert!(fail.min(val1).is_invalid());
    }

    #[test]
    fn safe_integral_min() {
        safe_integral_min_for_t::<i8>();
        safe_integral_min_for_t::<i16>();
        safe_integral_min_for_t::<i32>();
        safe_integral_min_for_t::<i64>();
        safe_integral_min_for_t::<u8>();
        safe_integral_min_for_t::<u16>();
        safe_integral_min_for_t::<u32>();
        safe_integral_min_for_t::<u64>();
        safe_integral_min_for_t::<usize>();
    }

    fn safe_integral_rational_for_t<T>()
    where
        T: Integer,
    {
        assert!(SafeIntegral::<T>::magic_1() == SafeIntegral::<T>::magic_1());
        assert!(SafeIntegral::<T>::magic_1() != SafeIntegral::<T>::magic_2());
        assert!(SafeIntegral::<T>::magic_1() < SafeIntegral::<T>::magic_2());
        assert!(SafeIntegral::<T>::magic_1() <= SafeIntegral::<T>::magic_2());
        assert!(SafeIntegral::<T>::magic_1() <= SafeIntegral::<T>::magic_1());
        assert!(SafeIntegral::<T>::magic_1() > SafeIntegral::<T>::magic_0());
        assert!(SafeIntegral::<T>::magic_1() >= SafeIntegral::<T>::magic_0());
        assert!(SafeIntegral::<T>::magic_1() >= SafeIntegral::<T>::magic_1());

        assert!(SafeIntegral::<T>::magic_1() == SafeIntegral::<T>::magic_1().get());
        assert!(SafeIntegral::<T>::magic_1() != SafeIntegral::<T>::magic_2().get());
        assert!(SafeIntegral::<T>::magic_1() < SafeIntegral::<T>::magic_2().get());
        assert!(SafeIntegral::<T>::magic_1() <= SafeIntegral::<T>::magic_2().get());
        assert!(SafeIntegral::<T>::magic_1() <= SafeIntegral::<T>::magic_1().get());
        assert!(SafeIntegral::<T>::magic_1() > SafeIntegral::<T>::magic_0().get());
        assert!(SafeIntegral::<T>::magic_1() >= SafeIntegral::<T>::magic_0().get());
        assert!(SafeIntegral::<T>::magic_1() >= SafeIntegral::<T>::magic_1().get());
    }

    #[test]
    fn safe_integral_rational() {
        safe_integral_rational_for_t::<i8>();
        safe_integral_rational_for_t::<i16>();
        safe_integral_rational_for_t::<i32>();
        safe_integral_rational_for_t::<i64>();
        safe_integral_rational_for_t::<u8>();
        safe_integral_rational_for_t::<u16>();
        safe_integral_rational_for_t::<u32>();
        safe_integral_rational_for_t::<u64>();
        safe_integral_rational_for_t::<usize>();
    }

    fn safe_integral_add_for_t<T>()
    where
        T: Integer,
    {
        let mut val = SafeIntegral::<T>::magic_1();
        val += SafeIntegral::<T>::magic_1();
        assert!(val.checked() == T::magic_2());

        let mut val = SafeIntegral::<T>::magic_1();
        val += SafeIntegral::<T>::max_value();
        assert!(val.is_invalid());

        let val = SafeIntegral::<T>::magic_1();
        assert!((val + SafeIntegral::<T>::magic_1()).checked() == T::magic_2());

        let val = SafeIntegral::<T>::magic_1();
        assert!((val + SafeIntegral::<T>::max_value()).is_invalid());

        let mut val = SafeIntegral::<T>::magic_1();
        val += T::magic_1();
        assert!(val.checked() == T::magic_2());

        let mut val = SafeIntegral::<T>::magic_1();
        val += T::max_value();
        assert!(val.is_invalid());

        let val = SafeIntegral::<T>::magic_1();
        assert!((val + T::magic_1()).checked() == T::magic_2());

        let val = SafeIntegral::<T>::magic_1();
        assert!((val + T::max_value()).is_invalid());
    }

    fn safe_integral_add_for_signed_t<T>()
    where
        T: SignedInteger,
    {
        let mut val = SafeIntegral::<T>::new(T::magic_neg_1());
        val += SafeIntegral::<T>::min_value();
        assert!(val.is_invalid());

        let val = SafeIntegral::<T>::new(T::magic_neg_1());
        assert!((val + SafeIntegral::<T>::min_value()).is_invalid());

        let mut val = SafeIntegral::<T>::new(T::magic_neg_1());
        val += T::min_value();
        assert!(val.is_invalid());

        let val = SafeIntegral::<T>::new(T::magic_neg_1());
        assert!((val + T::min_value()).is_invalid());
    }

    #[test]
    fn safe_integral_add() {
        safe_integral_add_for_t::<i8>();
        safe_integral_add_for_t::<i16>();
        safe_integral_add_for_t::<i32>();
        safe_integral_add_for_t::<i64>();
        safe_integral_add_for_t::<u8>();
        safe_integral_add_for_t::<u16>();
        safe_integral_add_for_t::<u32>();
        safe_integral_add_for_t::<u64>();
        safe_integral_add_for_t::<usize>();

        safe_integral_add_for_signed_t::<i8>();
        safe_integral_add_for_signed_t::<i16>();
        safe_integral_add_for_signed_t::<i32>();
        safe_integral_add_for_signed_t::<i64>();
    }

    fn safe_integral_sub_for_t<T>()
    where
        T: Integer,
    {
        let mut val = SafeIntegral::<T>::magic_1();
        val -= SafeIntegral::<T>::magic_1();
        assert!(val.checked() == T::magic_0());

        let mut val = SafeIntegral::<T>::min_value();
        val -= SafeIntegral::<T>::magic_1();
        assert!(val.is_invalid());

        let val = SafeIntegral::<T>::magic_1();
        assert!((val - SafeIntegral::<T>::magic_1()).checked() == T::magic_0());

        let val = SafeIntegral::<T>::min_value();
        assert!((val - SafeIntegral::<T>::magic_1()).is_invalid());

        let mut val = SafeIntegral::<T>::magic_1();
        val -= T::magic_1();
        assert!(val.checked() == T::magic_0());

        let mut val = SafeIntegral::<T>::min_value();
        val -= T::magic_1();
        assert!(val.is_invalid());

        let val = SafeIntegral::<T>::magic_1();
        assert!((val - T::magic_1()).checked() == T::magic_0());

        let val = SafeIntegral::<T>::min_value();
        assert!((val - T::magic_1()).is_invalid());
    }

    fn safe_integral_sub_for_signed_t<T>()
    where
        T: SignedInteger,
    {
        let mut val = SafeIntegral::<T>::max_value();
        val -= SafeIntegral::<T>::new(T::magic_neg_1());
        assert!(val.is_invalid());

        let val = SafeIntegral::<T>::max_value();
        assert!((val - SafeIntegral::<T>::new(T::magic_neg_1())).is_invalid());

        let mut val = SafeIntegral::<T>::max_value();
        val -= T::magic_neg_1();
        assert!(val.is_invalid());

        let val = SafeIntegral::<T>::max_value();
        assert!((val - T::magic_neg_1()).is_invalid());
    }

    #[test]
    fn safe_integral_sub() {
        safe_integral_sub_for_t::<i8>();
        safe_integral_sub_for_t::<i16>();
        safe_integral_sub_for_t::<i32>();
        safe_integral_sub_for_t::<i64>();
        safe_integral_sub_for_t::<u8>();
        safe_integral_sub_for_t::<u16>();
        safe_integral_sub_for_t::<u32>();
        safe_integral_sub_for_t::<u64>();
        safe_integral_sub_for_t::<usize>();

        safe_integral_sub_for_signed_t::<i8>();
        safe_integral_sub_for_signed_t::<i16>();
        safe_integral_sub_for_signed_t::<i32>();
        safe_integral_sub_for_signed_t::<i64>();
    }

    fn safe_integral_mul_for_t<T>()
    where
        T: Integer,
    {
        let mut val = SafeIntegral::<T>::magic_1();
        val *= SafeIntegral::<T>::magic_1();
        assert!(val.checked() == T::magic_1());

        let mut val = SafeIntegral::<T>::magic_2();
        val *= SafeIntegral::<T>::max_value();
        assert!(val.is_invalid());

        let val = SafeIntegral::<T>::magic_1();
        assert!((val * SafeIntegral::<T>::magic_1()).checked() == T::magic_1());

        let val = SafeIntegral::<T>::magic_2();
        assert!((val * SafeIntegral::<T>::max_value()).is_invalid());

        let mut val = SafeIntegral::<T>::magic_1();
        val *= T::magic_1();
        assert!(val.checked() == T::magic_1());

        let mut val = SafeIntegral::<T>::magic_2();
        val *= T::max_value();
        assert!(val.is_invalid());

        let val = SafeIntegral::<T>::magic_1();
        assert!((val * T::magic_1()).checked() == T::magic_1());

        let val = SafeIntegral::<T>::magic_2();
        assert!((val * T::max_value()).is_invalid());
    }

    #[test]
    fn safe_integral_mul() {
        safe_integral_mul_for_t::<i8>();
        safe_integral_mul_for_t::<i16>();
        safe_integral_mul_for_t::<i32>();
        safe_integral_mul_for_t::<i64>();
        safe_integral_mul_for_t::<u8>();
        safe_integral_mul_for_t::<u16>();
        safe_integral_mul_for_t::<u32>();
        safe_integral_mul_for_t::<u64>();
        safe_integral_mul_for_t::<usize>();
    }

    fn safe_integral_div_for_t<T>()
    where
        T: Integer,
    {
        let mut val = SafeIntegral::<T>::magic_2();
        val /= SafeIntegral::<T>::magic_2();
        assert!(val.checked() == T::magic_1());

        let mut val = SafeIntegral::<T>::magic_2();
        val /= SafeIntegral::<T>::magic_0();
        assert!(val.is_invalid());

        let val = SafeIntegral::<T>::magic_2();
        assert!((val / SafeIntegral::<T>::magic_2()).checked() == T::magic_1());

        let val = SafeIntegral::<T>::magic_2();
        assert!((val / SafeIntegral::<T>::magic_0()).is_invalid());

        let mut val = SafeIntegral::<T>::magic_2();
        val /= T::magic_2();
        assert!(val.checked() == T::magic_1());

        let mut val = SafeIntegral::<T>::magic_2();
        val /= T::magic_0();
        assert!(val.is_invalid());

        let val = SafeIntegral::<T>::magic_2();
        assert!((val / T::magic_2()).checked() == T::magic_1());

        let val = SafeIntegral::<T>::magic_2();
        assert!((val / T::magic_0()).is_invalid());
    }

    #[test]
    fn safe_integral_div() {
        safe_integral_div_for_t::<i8>();
        safe_integral_div_for_t::<i16>();
        safe_integral_div_for_t::<i32>();
        safe_integral_div_for_t::<i64>();
        safe_integral_div_for_t::<u8>();
        safe_integral_div_for_t::<u16>();
        safe_integral_div_for_t::<u32>();
        safe_integral_div_for_t::<u64>();
        safe_integral_div_for_t::<usize>();
    }

    fn safe_integral_rem_for_t<T>()
    where
        T: Integer,
    {
        let mut val = SafeIntegral::<T>::magic_3();
        val %= SafeIntegral::<T>::magic_2();
        assert!(val.checked() == T::magic_1());

        let mut val = SafeIntegral::<T>::magic_2();
        val %= SafeIntegral::<T>::magic_0();
        assert!(val.is_invalid());

        let val = SafeIntegral::<T>::magic_3();
        assert!((val % SafeIntegral::<T>::magic_2()).checked() == T::magic_1());

        let val = SafeIntegral::<T>::magic_2();
        assert!((val % SafeIntegral::<T>::magic_0()).is_invalid());

        let mut val = SafeIntegral::<T>::magic_3();
        val %= T::magic_2();
        assert!(val.checked() == T::magic_1());

        let mut val = SafeIntegral::<T>::magic_2();
        val %= T::magic_0();
        assert!(val.is_invalid());

        let val = SafeIntegral::<T>::magic_3();
        assert!((val % T::magic_2()).checked() == T::magic_1());

        let val = SafeIntegral::<T>::magic_2();
        assert!((val % T::magic_0()).is_invalid());
    }

    #[test]
    fn safe_integral_rem() {
        safe_integral_rem_for_t::<i8>();
        safe_integral_rem_for_t::<i16>();
        safe_integral_rem_for_t::<i32>();
        safe_integral_rem_for_t::<i64>();
        safe_integral_rem_for_t::<u8>();
        safe_integral_rem_for_t::<u16>();
        safe_integral_rem_for_t::<u32>();
        safe_integral_rem_for_t::<u64>();
        safe_integral_rem_for_t::<usize>();
    }

    fn safe_integral_shl_for_t<T>()
    where
        T: UnsignedInteger,
    {
        let mut val = SafeIntegral::<T>::magic_1();
        val <<= SafeIntegral::<u32>::magic_1();
        assert!(val == T::magic_2());

        let mut val = SafeIntegral::<T>::magic_1();
        val <<= SafeIntegral::<u32>::max_value();
        assert!(val.is_valid_and_checked());

        let val = SafeIntegral::<T>::magic_1();
        assert!((val << SafeIntegral::<u32>::magic_1()) == T::magic_2());

        let val = SafeIntegral::<T>::magic_1();
        assert!((val << SafeIntegral::<u32>::max_value()).is_valid_and_checked());

        let mut val = SafeIntegral::<T>::magic_1();
        val <<= u32::magic_1();
        assert!(val == T::magic_2());

        let mut val = SafeIntegral::<T>::magic_2();
        val <<= u32::max_value();
        assert!(val.is_valid_and_checked());

        let val = SafeIntegral::<T>::magic_1();
        assert!((val << u32::magic_1()) == T::magic_2());

        let val = SafeIntegral::<T>::magic_2();
        assert!((val << u32::max_value()).is_valid_and_checked());
    }

    #[test]
    fn safe_integral_shl() {
        safe_integral_shl_for_t::<u8>();
        safe_integral_shl_for_t::<u16>();
        safe_integral_shl_for_t::<u32>();
        safe_integral_shl_for_t::<u64>();
        safe_integral_shl_for_t::<usize>();
    }

    fn safe_integral_shr_for_t<T>()
    where
        T: UnsignedInteger,
    {
        let mut val = SafeIntegral::<T>::magic_2();
        val >>= SafeIntegral::<u32>::magic_1();
        assert!(val == T::magic_1());

        let mut val = SafeIntegral::<T>::magic_2();
        val >>= SafeIntegral::<u32>::max_value();
        assert!(val.is_valid_and_checked());

        let val = SafeIntegral::<T>::magic_2();
        assert!((val >> SafeIntegral::<u32>::magic_1()) == T::magic_1());

        let val = SafeIntegral::<T>::magic_2();
        assert!((val >> SafeIntegral::<u32>::max_value()).is_valid_and_checked());

        let mut val = SafeIntegral::<T>::magic_2();
        val >>= u32::magic_1();
        assert!(val == T::magic_1());

        let mut val = SafeIntegral::<T>::magic_2();
        val >>= u32::max_value();
        assert!(val.is_valid_and_checked());

        let val = SafeIntegral::<T>::magic_2();
        assert!((val >> u32::magic_1()) == T::magic_1());

        let val = SafeIntegral::<T>::magic_2();
        assert!((val >> u32::max_value()).is_valid_and_checked());
    }

    #[test]
    fn safe_integral_shr() {
        safe_integral_shr_for_t::<u8>();
        safe_integral_shr_for_t::<u16>();
        safe_integral_shr_for_t::<u32>();
        safe_integral_shr_for_t::<u64>();
        safe_integral_shr_for_t::<usize>();
    }

    fn safe_integral_and_for_t<T>()
    where
        T: UnsignedInteger,
    {
        let mut val = SafeIntegral::<T>::magic_2();
        val &= SafeIntegral::<T>::magic_1();
        assert!(val == T::magic_0());

        let val = SafeIntegral::<T>::magic_2();
        assert!((val & SafeIntegral::<T>::magic_1()) == T::magic_0());

        let mut val = SafeIntegral::<T>::magic_2();
        val &= T::magic_1();
        assert!(val == T::magic_0());

        let val = SafeIntegral::<T>::magic_2();
        assert!((val & T::magic_1()) == T::magic_0());
    }

    #[test]
    fn safe_integral_and() {
        safe_integral_and_for_t::<u8>();
        safe_integral_and_for_t::<u16>();
        safe_integral_and_for_t::<u32>();
        safe_integral_and_for_t::<u64>();
        safe_integral_and_for_t::<usize>();
    }

    fn safe_integral_or_for_t<T>()
    where
        T: UnsignedInteger,
    {
        let mut val = SafeIntegral::<T>::magic_2();
        val |= SafeIntegral::<T>::magic_1();
        assert!(val == T::magic_3());

        let val = SafeIntegral::<T>::magic_2();
        assert!((val | SafeIntegral::<T>::magic_1()) == T::magic_3());

        let mut val = SafeIntegral::<T>::magic_2();
        val |= T::magic_1();
        assert!(val == T::magic_3());

        let val = SafeIntegral::<T>::magic_2();
        assert!((val | T::magic_1()) == T::magic_3());
    }

    #[test]
    fn safe_integral_or() {
        safe_integral_or_for_t::<u8>();
        safe_integral_or_for_t::<u16>();
        safe_integral_or_for_t::<u32>();
        safe_integral_or_for_t::<u64>();
        safe_integral_or_for_t::<usize>();
    }

    fn safe_integral_xor_for_t<T>()
    where
        T: UnsignedInteger,
    {
        let mut val = SafeIntegral::<T>::magic_2();
        val ^= SafeIntegral::<T>::magic_2();
        assert!(val == T::magic_0());

        let val = SafeIntegral::<T>::magic_2();
        assert!((val ^ SafeIntegral::<T>::magic_2()) == T::magic_0());

        let mut val = SafeIntegral::<T>::magic_2();
        val ^= T::magic_2();
        assert!(val == T::magic_0());

        let val = SafeIntegral::<T>::magic_2();
        assert!((val ^ T::magic_2()) == T::magic_0());
    }

    #[test]
    fn safe_integral_xor() {
        safe_integral_xor_for_t::<u8>();
        safe_integral_xor_for_t::<u16>();
        safe_integral_xor_for_t::<u32>();
        safe_integral_xor_for_t::<u64>();
        safe_integral_xor_for_t::<usize>();
    }

    fn safe_integral_not_for_t<T>()
    where
        T: UnsignedInteger,
    {
        assert!(!SafeIntegral::<T>::magic_1() == !T::magic_1());
    }

    #[test]
    fn safe_integral_not() {
        safe_integral_not_for_t::<u8>();
        safe_integral_not_for_t::<u16>();
        safe_integral_not_for_t::<u32>();
        safe_integral_not_for_t::<u64>();
        safe_integral_not_for_t::<usize>();
    }

    fn safe_integral_neg_for_t<T>()
    where
        T: SignedInteger,
    {
        assert!(-SafeIntegral::<T>::magic_1() == -T::magic_1());
    }

    #[test]
    fn safe_integral_neg() {
        safe_integral_neg_for_t::<i8>();
        safe_integral_neg_for_t::<i16>();
        safe_integral_neg_for_t::<i32>();
        safe_integral_neg_for_t::<i64>();
    }

    #[test]
    fn safe_integral_make_safe() {
        assert!(super::make_safe::<i8>(0).is_zero());
        assert!(super::make_safe::<i16>(0).is_zero());
        assert!(super::make_safe::<i32>(0).is_zero());
        assert!(super::make_safe::<i64>(0).is_zero());
        assert!(super::make_safe::<u8>(0).is_zero());
        assert!(super::make_safe::<u16>(0).is_zero());
        assert!(super::make_safe::<u32>(0).is_zero());
        assert!(super::make_safe::<u64>(0).is_zero());
        assert!(super::make_safe::<usize>(0).is_zero());
    }
}

// -----------------------------------------------------------------------------
// Policy Unit Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod safe_integral_policy_tests {
    use super::Integer;
    use super::SafeIntegral;
    use super::SignedInteger;
    use super::UnsignedInteger;

    fn safe_integral_constructors_checked_policy_for_t<T>()
    where
        T: Integer,
    {
        assert_eq!(SafeIntegral::<T>::new(T::magic_1()).is_unchecked(), false);
        assert_eq!(SafeIntegral::<T>::new(T::magic_1()).is_invalid(), false);
    }

    #[test]
    fn safe_integral_constructors_checked_policy() {
        safe_integral_constructors_checked_policy_for_t::<i8>();
        safe_integral_constructors_checked_policy_for_t::<i16>();
        safe_integral_constructors_checked_policy_for_t::<i32>();
        safe_integral_constructors_checked_policy_for_t::<i64>();
        safe_integral_constructors_checked_policy_for_t::<u8>();
        safe_integral_constructors_checked_policy_for_t::<u16>();
        safe_integral_constructors_checked_policy_for_t::<u32>();
        safe_integral_constructors_checked_policy_for_t::<u64>();
        safe_integral_constructors_checked_policy_for_t::<usize>();
    }

    fn safe_integral_assignment_checked_policy_for_t<T>()
    where
        T: Integer,
    {
        let val1 = SafeIntegral::<T>::magic_1();
        let val2 = val1;
        assert_eq!(val2.is_unchecked(), false);
        assert_eq!(val2.is_invalid(), false);

        let val1 = SafeIntegral::<T>::failure();
        let val2 = val1;
        assert_eq!(val2.is_unchecked(), true);
        assert_eq!(val2.is_invalid(), true);
    }

    #[test]
    fn safe_integral_assignment_checked_policy() {
        safe_integral_assignment_checked_policy_for_t::<i8>();
        safe_integral_assignment_checked_policy_for_t::<i16>();
        safe_integral_assignment_checked_policy_for_t::<i32>();
        safe_integral_assignment_checked_policy_for_t::<i64>();
        safe_integral_assignment_checked_policy_for_t::<u8>();
        safe_integral_assignment_checked_policy_for_t::<u16>();
        safe_integral_assignment_checked_policy_for_t::<u32>();
        safe_integral_assignment_checked_policy_for_t::<u64>();
        safe_integral_assignment_checked_policy_for_t::<usize>();
    }

    fn safe_integral_get_policy_for_t<T>()
    where
        T: Integer + std::panic::RefUnwindSafe,
    {
        let val = SafeIntegral::<T>::magic_1();
        assert_eq!(val.get(), T::magic_1());

        let val = SafeIntegral::<T>::magic_1() + SafeIntegral::<T>::magic_1();
        assert_eq!(val.checked().get(), T::magic_2());

        let val = SafeIntegral::<T>::failure();
        assert_panics!(val.get());

        let val = SafeIntegral::<T>::magic_1() + SafeIntegral::<T>::magic_1();
        assert_panics!(val.get() == T::magic_1());
    }

    #[test]
    fn safe_integral_get_policy() {
        safe_integral_get_policy_for_t::<i8>();
        safe_integral_get_policy_for_t::<i16>();
        safe_integral_get_policy_for_t::<i32>();
        safe_integral_get_policy_for_t::<i64>();
        safe_integral_get_policy_for_t::<u8>();
        safe_integral_get_policy_for_t::<u16>();
        safe_integral_get_policy_for_t::<u32>();
        safe_integral_get_policy_for_t::<u64>();
        safe_integral_get_policy_for_t::<usize>();
    }

    fn safe_integral_is_pos_policy_for_t<T>()
    where
        T: Integer + std::panic::RefUnwindSafe,
    {
        let val = SafeIntegral::<T>::magic_1();
        assert_eq!(val.is_pos(), true);

        let val = SafeIntegral::<T>::magic_1() + SafeIntegral::<T>::magic_1();
        assert_eq!(val.checked().is_pos(), true);

        let val = SafeIntegral::<T>::failure();
        assert_panics!(val.is_pos());

        let val = SafeIntegral::<T>::magic_1() + SafeIntegral::<T>::magic_1();
        assert_panics!(val.is_pos());
    }

    #[test]
    fn safe_integral_is_pos_policy() {
        safe_integral_is_pos_policy_for_t::<i8>();
        safe_integral_is_pos_policy_for_t::<i16>();
        safe_integral_is_pos_policy_for_t::<i32>();
        safe_integral_is_pos_policy_for_t::<i64>();
        safe_integral_is_pos_policy_for_t::<u8>();
        safe_integral_is_pos_policy_for_t::<u16>();
        safe_integral_is_pos_policy_for_t::<u32>();
        safe_integral_is_pos_policy_for_t::<u64>();
        safe_integral_is_pos_policy_for_t::<usize>();
    }

    fn safe_integral_is_zero_policy_for_t<T>()
    where
        T: Integer + std::panic::RefUnwindSafe,
    {
        let val = SafeIntegral::<T>::magic_1();
        assert_eq!(val.is_zero(), false);

        let val = SafeIntegral::<T>::magic_1() + SafeIntegral::<T>::magic_1();
        assert_eq!(val.checked().is_zero(), false);

        let val = SafeIntegral::<T>::failure();
        assert_panics!(val.is_zero());

        let val = SafeIntegral::<T>::magic_1() + SafeIntegral::<T>::magic_1();
        assert_panics!(val.is_zero());
    }

    #[test]
    fn safe_integral_is_zero_policy() {
        safe_integral_is_zero_policy_for_t::<i8>();
        safe_integral_is_zero_policy_for_t::<i16>();
        safe_integral_is_zero_policy_for_t::<i32>();
        safe_integral_is_zero_policy_for_t::<i64>();
        safe_integral_is_zero_policy_for_t::<u8>();
        safe_integral_is_zero_policy_for_t::<u16>();
        safe_integral_is_zero_policy_for_t::<u32>();
        safe_integral_is_zero_policy_for_t::<u64>();
        safe_integral_is_zero_policy_for_t::<usize>();
    }

    fn safe_integral_is_neg_policy_for_t<T>()
    where
        T: SignedInteger + std::panic::RefUnwindSafe,
    {
        let val = SafeIntegral::<T>::magic_neg_1();
        assert_eq!(val.is_neg(), true);

        let val = SafeIntegral::<T>::magic_neg_1() + SafeIntegral::<T>::magic_neg_1();
        assert_eq!(val.checked().is_neg(), true);

        let val = SafeIntegral::<T>::failure();
        assert_panics!(val.is_neg());

        let val = SafeIntegral::<T>::magic_neg_1() + SafeIntegral::<T>::magic_neg_1();
        assert_panics!(val.is_neg());
    }

    #[test]
    fn safe_integral_is_neg_policy() {
        safe_integral_is_neg_policy_for_t::<i8>();
        safe_integral_is_neg_policy_for_t::<i16>();
        safe_integral_is_neg_policy_for_t::<i32>();
        safe_integral_is_neg_policy_for_t::<i64>();
    }

    fn safe_integral_is_poisoned_policy_for_t<T>()
    where
        T: Integer,
    {
        let mut val = SafeIntegral::<T>::magic_1();
        assert_eq!(val.is_poisoned(), false);

        let mut val = SafeIntegral::<T>::failure();
        assert_eq!(val.is_poisoned(), true);

        let mut val = SafeIntegral::<T>::magic_1() + SafeIntegral::<T>::magic_1();
        assert_eq!(val.is_checked(), false);
        val.is_poisoned();
        assert_eq!(val.is_checked(), true);
    }

    #[test]
    fn safe_integral_is_poisoned_policy() {
        safe_integral_is_poisoned_policy_for_t::<i8>();
        safe_integral_is_poisoned_policy_for_t::<i16>();
        safe_integral_is_poisoned_policy_for_t::<i32>();
        safe_integral_is_poisoned_policy_for_t::<i64>();
        safe_integral_is_poisoned_policy_for_t::<u8>();
        safe_integral_is_poisoned_policy_for_t::<u16>();
        safe_integral_is_poisoned_policy_for_t::<u32>();
        safe_integral_is_poisoned_policy_for_t::<u64>();
        safe_integral_is_poisoned_policy_for_t::<usize>();
    }

    fn safe_integral_checked_policy_for_t<T>()
    where
        T: Integer + std::panic::RefUnwindSafe,
    {
        let val = SafeIntegral::<T>::magic_1();
        assert!(val.checked() == SafeIntegral::<T>::magic_1());

        let val = SafeIntegral::<T>::magic_1() + SafeIntegral::<T>::magic_1();
        assert!(val.checked() == SafeIntegral::<T>::magic_2());

        let val = SafeIntegral::<T>::failure();
        assert_panics!(val.checked());
    }

    #[test]
    fn safe_integral_checked_policy() {
        safe_integral_checked_policy_for_t::<i8>();
        safe_integral_checked_policy_for_t::<i16>();
        safe_integral_checked_policy_for_t::<i32>();
        safe_integral_checked_policy_for_t::<i64>();
        safe_integral_checked_policy_for_t::<u8>();
        safe_integral_checked_policy_for_t::<u16>();
        safe_integral_checked_policy_for_t::<u32>();
        safe_integral_checked_policy_for_t::<u64>();
        safe_integral_checked_policy_for_t::<usize>();
    }

    fn safe_integral_arithmetic_policy_for_t<T>()
    where
        T: Integer,
    {
        let val = SafeIntegral::<T>::magic_1() + SafeIntegral::<T>::magic_1();
        assert_eq!(val.is_checked(), false);
        let val = SafeIntegral::<T>::magic_1() + T::magic_1();
        assert_eq!(val.is_checked(), false);
        let mut val = SafeIntegral::<T>::magic_1();
        val += SafeIntegral::<T>::magic_1();
        assert_eq!(val.is_checked(), false);
        let mut val = SafeIntegral::<T>::magic_1();
        val += T::magic_1();
        assert_eq!(val.is_checked(), false);

        let val = SafeIntegral::<T>::failure() + SafeIntegral::<T>::magic_1();
        assert_eq!(val.is_valid(), false);
        let val = SafeIntegral::<T>::magic_1() + SafeIntegral::<T>::failure();
        assert_eq!(val.is_valid(), false);
        let val = SafeIntegral::<T>::failure() + T::magic_1();
        assert_eq!(val.is_valid(), false);
        let mut val = SafeIntegral::<T>::failure();
        val += SafeIntegral::<T>::magic_1();
        assert_eq!(val.is_valid(), false);
        let mut val = SafeIntegral::<T>::magic_1();
        val += SafeIntegral::<T>::failure();
        assert_eq!(val.is_valid(), false);
        let mut val = SafeIntegral::<T>::failure();
        val += T::magic_1();
        assert_eq!(val.is_valid(), false);

        let val = SafeIntegral::<T>::magic_1() - SafeIntegral::<T>::magic_1();
        assert_eq!(val.is_checked(), false);
        let val = SafeIntegral::<T>::magic_1() - T::magic_1();
        assert_eq!(val.is_checked(), false);
        let mut val = SafeIntegral::<T>::magic_1();
        val -= SafeIntegral::<T>::magic_1();
        assert_eq!(val.is_checked(), false);
        let mut val = SafeIntegral::<T>::magic_1();
        val -= T::magic_1();
        assert_eq!(val.is_checked(), false);

        let val = SafeIntegral::<T>::failure() - SafeIntegral::<T>::magic_1();
        assert_eq!(val.is_valid(), false);
        let val = SafeIntegral::<T>::magic_1() - SafeIntegral::<T>::failure();
        assert_eq!(val.is_valid(), false);
        let val = SafeIntegral::<T>::failure() - T::magic_1();
        assert_eq!(val.is_valid(), false);
        let mut val = SafeIntegral::<T>::failure();
        val -= SafeIntegral::<T>::magic_1();
        assert_eq!(val.is_valid(), false);
        let mut val = SafeIntegral::<T>::magic_1();
        val -= SafeIntegral::<T>::failure();
        assert_eq!(val.is_valid(), false);
        let mut val = SafeIntegral::<T>::failure();
        val -= T::magic_1();
        assert_eq!(val.is_valid(), false);

        let val = SafeIntegral::<T>::magic_1() * SafeIntegral::<T>::magic_1();
        assert_eq!(val.is_checked(), false);
        let val = SafeIntegral::<T>::magic_1() * T::magic_1();
        assert_eq!(val.is_checked(), false);
        let mut val = SafeIntegral::<T>::magic_1();
        val *= SafeIntegral::<T>::magic_1();
        assert_eq!(val.is_checked(), false);
        let mut val = SafeIntegral::<T>::magic_1();
        val *= T::magic_1();
        assert_eq!(val.is_checked(), false);

        let val = SafeIntegral::<T>::failure() * SafeIntegral::<T>::magic_1();
        assert_eq!(val.is_valid(), false);
        let val = SafeIntegral::<T>::magic_1() * SafeIntegral::<T>::failure();
        assert_eq!(val.is_valid(), false);
        let val = SafeIntegral::<T>::failure() * T::magic_1();
        assert_eq!(val.is_valid(), false);
        let mut val = SafeIntegral::<T>::failure();
        val *= SafeIntegral::<T>::magic_1();
        assert_eq!(val.is_valid(), false);
        let mut val = SafeIntegral::<T>::magic_1();
        val *= SafeIntegral::<T>::failure();
        assert_eq!(val.is_valid(), false);
        let mut val = SafeIntegral::<T>::failure();
        val *= T::magic_1();
        assert_eq!(val.is_valid(), false);

        let val = SafeIntegral::<T>::magic_1() / SafeIntegral::<T>::magic_1();
        assert_eq!(val.is_checked(), false);
        let val = SafeIntegral::<T>::magic_1() / T::magic_1();
        assert_eq!(val.is_checked(), false);
        let mut val = SafeIntegral::<T>::magic_1();
        val /= SafeIntegral::<T>::magic_1();
        assert_eq!(val.is_checked(), false);
        let mut val = SafeIntegral::<T>::magic_1();
        val /= T::magic_1();
        assert_eq!(val.is_checked(), false);

        let val = SafeIntegral::<T>::failure() / SafeIntegral::<T>::magic_1();
        assert_eq!(val.is_valid(), false);
        let val = SafeIntegral::<T>::magic_1() / SafeIntegral::<T>::failure();
        assert_eq!(val.is_valid(), false);
        let val = SafeIntegral::<T>::failure() / T::magic_1();
        assert_eq!(val.is_valid(), false);
        let mut val = SafeIntegral::<T>::failure();
        val /= SafeIntegral::<T>::magic_1();
        assert_eq!(val.is_valid(), false);
        let mut val = SafeIntegral::<T>::magic_1();
        val /= SafeIntegral::<T>::failure();
        assert_eq!(val.is_valid(), false);
        let mut val = SafeIntegral::<T>::failure();
        val /= T::magic_1();
        assert_eq!(val.is_valid(), false);

        let val = SafeIntegral::<T>::magic_1() % SafeIntegral::<T>::magic_1();
        assert_eq!(val.is_checked(), false);
        let val = SafeIntegral::<T>::magic_1() % T::magic_1();
        assert_eq!(val.is_checked(), false);
        let mut val = SafeIntegral::<T>::magic_1();
        val %= SafeIntegral::<T>::magic_1();
        assert_eq!(val.is_checked(), false);
        let mut val = SafeIntegral::<T>::magic_1();
        val %= T::magic_1();
        assert_eq!(val.is_checked(), false);

        let val = SafeIntegral::<T>::failure() % SafeIntegral::<T>::magic_1();
        assert_eq!(val.is_valid(), false);
        let val = SafeIntegral::<T>::magic_1() % SafeIntegral::<T>::failure();
        assert_eq!(val.is_valid(), false);
        let val = SafeIntegral::<T>::failure() % T::magic_1();
        assert_eq!(val.is_valid(), false);
        let mut val = SafeIntegral::<T>::failure();
        val %= SafeIntegral::<T>::magic_1();
        assert_eq!(val.is_valid(), false);
        let mut val = SafeIntegral::<T>::magic_1();
        val %= SafeIntegral::<T>::failure();
        assert_eq!(val.is_valid(), false);
        let mut val = SafeIntegral::<T>::failure();
        val %= T::magic_1();
        assert_eq!(val.is_valid(), false);
    }

    #[test]
    fn safe_integral_arithmetic_policy() {
        safe_integral_arithmetic_policy_for_t::<i8>();
        safe_integral_arithmetic_policy_for_t::<i16>();
        safe_integral_arithmetic_policy_for_t::<i32>();
        safe_integral_arithmetic_policy_for_t::<i64>();
        safe_integral_arithmetic_policy_for_t::<u8>();
        safe_integral_arithmetic_policy_for_t::<u16>();
        safe_integral_arithmetic_policy_for_t::<u32>();
        safe_integral_arithmetic_policy_for_t::<u64>();
        safe_integral_arithmetic_policy_for_t::<usize>();
    }

    fn safe_integral_shift_policy_for_t<T>()
    where
        T: UnsignedInteger,
    {
        let val = SafeIntegral::<T>::magic_1() << SafeIntegral::<u32>::magic_1();
        assert_eq!(val.is_checked(), true);
        let val = SafeIntegral::<T>::magic_1() << u32::magic_1();
        assert_eq!(val.is_checked(), true);
        let mut val = SafeIntegral::<T>::magic_1();
        val <<= SafeIntegral::<u32>::magic_1();
        assert_eq!(val.is_checked(), true);
        let mut val = SafeIntegral::<T>::magic_1();
        val <<= u32::magic_1();
        assert_eq!(val.is_checked(), true);

        let val = SafeIntegral::<T>::failure() << SafeIntegral::<u32>::magic_1();
        assert_eq!(val.is_checked(), false);
        assert_eq!(val.is_valid(), false);
        let val = SafeIntegral::<T>::magic_1() << SafeIntegral::<u32>::failure();
        assert_eq!(val.is_checked(), false);
        assert_eq!(val.is_valid(), false);
        let val = SafeIntegral::<T>::failure() << u32::magic_1();
        assert_eq!(val.is_checked(), false);
        assert_eq!(val.is_valid(), false);
        let mut val = SafeIntegral::<T>::failure();
        val <<= SafeIntegral::<u32>::magic_1();
        assert_eq!(val.is_checked(), false);
        assert_eq!(val.is_valid(), false);
        let mut val = SafeIntegral::<T>::magic_1();
        val <<= SafeIntegral::<u32>::failure();
        assert_eq!(val.is_checked(), false);
        assert_eq!(val.is_valid(), false);
        let mut val = SafeIntegral::<T>::failure();
        val <<= u32::magic_1();
        assert_eq!(val.is_checked(), false);
        assert_eq!(val.is_valid(), false);

        let val = SafeIntegral::<T>::magic_1() >> SafeIntegral::<u32>::magic_1();
        assert_eq!(val.is_checked(), true);
        let val = SafeIntegral::<T>::magic_1() >> u32::magic_1();
        assert_eq!(val.is_checked(), true);
        let mut val = SafeIntegral::<T>::magic_1();
        val >>= SafeIntegral::<u32>::magic_1();
        assert_eq!(val.is_checked(), true);
        let mut val = SafeIntegral::<T>::magic_1();
        val >>= u32::magic_1();
        assert_eq!(val.is_checked(), true);

        let val = SafeIntegral::<T>::failure() >> SafeIntegral::<u32>::magic_1();
        assert_eq!(val.is_checked(), false);
        assert_eq!(val.is_valid(), false);
        let val = SafeIntegral::<T>::magic_1() >> SafeIntegral::<u32>::failure();
        assert_eq!(val.is_checked(), false);
        assert_eq!(val.is_valid(), false);
        let val = SafeIntegral::<T>::failure() >> u32::magic_1();
        assert_eq!(val.is_checked(), false);
        assert_eq!(val.is_valid(), false);
        let mut val = SafeIntegral::<T>::failure();
        val >>= SafeIntegral::<u32>::magic_1();
        assert_eq!(val.is_checked(), false);
        assert_eq!(val.is_valid(), false);
        let mut val = SafeIntegral::<T>::magic_1();
        val >>= SafeIntegral::<u32>::failure();
        assert_eq!(val.is_checked(), false);
        assert_eq!(val.is_valid(), false);
        let mut val = SafeIntegral::<T>::failure();
        val >>= u32::magic_1();
        assert_eq!(val.is_checked(), false);
        assert_eq!(val.is_valid(), false);
    }

    #[test]
    fn safe_integral_shift_policy() {
        safe_integral_shift_policy_for_t::<u8>();
        safe_integral_shift_policy_for_t::<u16>();
        safe_integral_shift_policy_for_t::<u32>();
        safe_integral_shift_policy_for_t::<u64>();
        safe_integral_shift_policy_for_t::<usize>();
    }

    fn safe_integral_binary_policy_for_t<T>()
    where
        T: UnsignedInteger,
    {
        let val = SafeIntegral::<T>::magic_1() & SafeIntegral::<T>::magic_1();
        assert_eq!(val.is_checked(), true);
        let val = SafeIntegral::<T>::magic_1() & T::magic_1();
        assert_eq!(val.is_checked(), true);
        let mut val = SafeIntegral::<T>::magic_1();
        val &= SafeIntegral::<T>::magic_1();
        assert_eq!(val.is_checked(), true);
        let mut val = SafeIntegral::<T>::magic_1();
        val &= T::magic_1();
        assert_eq!(val.is_checked(), true);

        let val = SafeIntegral::<T>::failure() & SafeIntegral::<T>::magic_1();
        assert_eq!(val.is_checked(), false);
        assert_eq!(val.is_valid(), false);
        let val = SafeIntegral::<T>::magic_1() & SafeIntegral::<T>::failure();
        assert_eq!(val.is_checked(), false);
        assert_eq!(val.is_valid(), false);
        let val = SafeIntegral::<T>::failure() & T::magic_1();
        assert_eq!(val.is_checked(), false);
        assert_eq!(val.is_valid(), false);
        let mut val = SafeIntegral::<T>::failure();
        val &= SafeIntegral::<T>::magic_1();
        assert_eq!(val.is_checked(), false);
        assert_eq!(val.is_valid(), false);
        let mut val = SafeIntegral::<T>::magic_1();
        val &= SafeIntegral::<T>::failure();
        assert_eq!(val.is_checked(), false);
        assert_eq!(val.is_valid(), false);
        let mut val = SafeIntegral::<T>::failure();
        val &= T::magic_1();
        assert_eq!(val.is_checked(), false);
        assert_eq!(val.is_valid(), false);

        let val = SafeIntegral::<T>::magic_1() | SafeIntegral::<T>::magic_1();
        assert_eq!(val.is_checked(), true);
        let val = SafeIntegral::<T>::magic_1() | T::magic_1();
        assert_eq!(val.is_checked(), true);
        let mut val = SafeIntegral::<T>::magic_1();
        val |= SafeIntegral::<T>::magic_1();
        assert_eq!(val.is_checked(), true);
        let mut val = SafeIntegral::<T>::magic_1();
        val |= T::magic_1();
        assert_eq!(val.is_checked(), true);

        let val = SafeIntegral::<T>::failure() | SafeIntegral::<T>::magic_1();
        assert_eq!(val.is_checked(), false);
        assert_eq!(val.is_valid(), false);
        let val = SafeIntegral::<T>::magic_1() | SafeIntegral::<T>::failure();
        assert_eq!(val.is_checked(), false);
        assert_eq!(val.is_valid(), false);
        let val = SafeIntegral::<T>::failure() | T::magic_1();
        assert_eq!(val.is_checked(), false);
        assert_eq!(val.is_valid(), false);
        let mut val = SafeIntegral::<T>::failure();
        val |= SafeIntegral::<T>::magic_1();
        assert_eq!(val.is_checked(), false);
        assert_eq!(val.is_valid(), false);
        let mut val = SafeIntegral::<T>::magic_1();
        val |= SafeIntegral::<T>::failure();
        assert_eq!(val.is_checked(), false);
        assert_eq!(val.is_valid(), false);
        let mut val = SafeIntegral::<T>::failure();
        val |= T::magic_1();
        assert_eq!(val.is_checked(), false);
        assert_eq!(val.is_valid(), false);

        let val = SafeIntegral::<T>::magic_1() ^ SafeIntegral::<T>::magic_1();
        assert_eq!(val.is_checked(), true);
        let val = SafeIntegral::<T>::magic_1() ^ T::magic_1();
        assert_eq!(val.is_checked(), true);
        let mut val = SafeIntegral::<T>::magic_1();
        val ^= SafeIntegral::<T>::magic_1();
        assert_eq!(val.is_checked(), true);
        let mut val = SafeIntegral::<T>::magic_1();
        val ^= T::magic_1();
        assert_eq!(val.is_checked(), true);

        let val = SafeIntegral::<T>::failure() ^ SafeIntegral::<T>::magic_1();
        assert_eq!(val.is_checked(), false);
        assert_eq!(val.is_valid(), false);
        let val = SafeIntegral::<T>::magic_1() ^ SafeIntegral::<T>::failure();
        assert_eq!(val.is_checked(), false);
        assert_eq!(val.is_valid(), false);
        let val = SafeIntegral::<T>::failure() ^ T::magic_1();
        assert_eq!(val.is_checked(), false);
        assert_eq!(val.is_valid(), false);
        let mut val = SafeIntegral::<T>::failure();
        val ^= SafeIntegral::<T>::magic_1();
        assert_eq!(val.is_checked(), false);
        assert_eq!(val.is_valid(), false);
        let mut val = SafeIntegral::<T>::magic_1();
        val ^= SafeIntegral::<T>::failure();
        assert_eq!(val.is_checked(), false);
        assert_eq!(val.is_valid(), false);
        let mut val = SafeIntegral::<T>::failure();
        val ^= T::magic_1();
        assert_eq!(val.is_checked(), false);
        assert_eq!(val.is_valid(), false);
    }

    #[test]
    fn safe_integral_binary_policy() {
        safe_integral_binary_policy_for_t::<u8>();
        safe_integral_binary_policy_for_t::<u16>();
        safe_integral_binary_policy_for_t::<u32>();
        safe_integral_binary_policy_for_t::<u64>();
        safe_integral_binary_policy_for_t::<usize>();
    }

    fn safe_integral_not_policy_for_t<T>()
    where
        T: UnsignedInteger,
    {
        let val = !SafeIntegral::<T>::magic_1();
        assert_eq!(val.is_checked(), true);

        let val = !SafeIntegral::<T>::failure();
        assert_eq!(val.is_checked(), false);
        assert_eq!(val.is_valid(), false);
    }

    #[test]
    fn safe_integral_not_policy() {
        safe_integral_not_policy_for_t::<u8>();
        safe_integral_not_policy_for_t::<u16>();
        safe_integral_not_policy_for_t::<u32>();
        safe_integral_not_policy_for_t::<u64>();
        safe_integral_not_policy_for_t::<usize>();
    }

    fn safe_integral_neg_policy_for_t<T>()
    where
        T: SignedInteger,
    {
        let val = -SafeIntegral::<T>::magic_1();
        assert_eq!(val.is_checked(), true);

        let val = -SafeIntegral::<T>::failure();
        assert_eq!(val.is_checked(), false);
        assert_eq!(val.is_valid(), false);

        let val = -SafeIntegral::<T>::min_value();
        assert_eq!(val.is_checked(), false);
        assert_eq!(val.is_valid(), false);
    }

    #[test]
    fn safe_integral_neg_policy() {
        safe_integral_neg_policy_for_t::<i8>();
        safe_integral_neg_policy_for_t::<i16>();
        safe_integral_neg_policy_for_t::<i32>();
        safe_integral_neg_policy_for_t::<i64>();
    }
}
