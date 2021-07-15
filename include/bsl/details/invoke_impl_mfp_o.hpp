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

#ifndef BSL_DETAILS_INVOKE_IMPL_MFP_O_HPP
#define BSL_DETAILS_INVOKE_IMPL_MFP_O_HPP

#include "../forward.hpp"

namespace bsl::details
{
    /// @class bsl::details::invoke_impl_mfp_o
    ///
    /// <!-- description -->
    ///   @brief The "invoke" function is implemented by executing the
    ///     "call" function from invoke_impl. The invoke_impl class uses
    ///     SFINAE to figure out which invoke_impl_xxx function to inherit
    ///     from. If the compiler can find a valid invoke_impl_xxx, like
    ///     possibly this class, it will inherit from it, otherwise, it
    ///     will pick the default invoke_impl implementation which is an
    ///     empty class (i.e., it does not provide a call function). This
    ///     will either result in a compiler error, or an SFINAE
    ///     substitution error, which is used to implement is_invocable,
    ///     which is why invoke is implemented using class logic instead
    ///     of a constexpr-if statement as documented by cppreference.
    ///
    class invoke_impl_mfp_o
    {
    public:
        /// <!-- description -->
        ///   @brief Default constructor
        ///
        constexpr invoke_impl_mfp_o() noexcept = default;

        /// <!-- description -->
        ///   @brief Invokes a member function pointer given a reference to
        ///     an object.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam FUNC the type that defines the function being called
        ///   @tparam U the type that defines the class that encapsulates
        ///     the function being called.
        ///   @tparam T1 the type that defines the provided object. Note
        ///     that normally, U == T, but if inheritance is used, it might
        ///     not which is why U is provided instead of just using T.
        ///   @tparam TN the types that define the arguments passed to the
        ///     provided function when called.
        ///   @param pudm_udm_func a pointer to the function being called.
        ///   @param pudm_udm_val1 a reference to the object for which the function is
        ///     called from.
        ///   @param pudm_udm_valn the arguments passed to the function pudm_udm_func when called.
        ///   @return Returns the result of calling "pudm_udm_func" from "pudm_udm_val1" with "pudm_udm_valn"
        ///
        template<typename FUNC, typename U, typename T1, typename... TN>
        [[maybe_unused]] static constexpr auto
        call(FUNC U::*pudm_udm_func, T1 &&pudm_udm_val1, TN &&...pudm_udm_valn) noexcept(noexcept(
            (bsl::forward<T1>(pudm_udm_val1).*pudm_udm_func)(bsl::forward<TN>(pudm_udm_valn)...)))
            -> decltype((bsl::forward<T1>(pudm_udm_val1).*pudm_udm_func)(
                bsl::forward<TN>(pudm_udm_valn)...))
        {
            return (bsl::forward<T1>(pudm_udm_val1).*pudm_udm_func)(
                bsl::forward<TN>(pudm_udm_valn)...);
        }

    protected:
        /// <!-- description -->
        ///   @brief Destroyes a previously created bsl::invoke_impl_mfp_o
        ///
        constexpr ~invoke_impl_mfp_o() noexcept = default;

        /// <!-- description -->
        ///   @brief copy constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///
        constexpr invoke_impl_mfp_o(invoke_impl_mfp_o const &o) noexcept = default;

        /// <!-- description -->
        ///   @brief move constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_o the object being moved
        ///
        constexpr invoke_impl_mfp_o(invoke_impl_mfp_o &&mut_o) noexcept = default;

        /// <!-- description -->
        ///   @brief copy assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr auto operator=(invoke_impl_mfp_o const &o) &noexcept
            -> invoke_impl_mfp_o & = default;

        /// <!-- description -->
        ///   @brief move assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_o the object being moved
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr auto operator=(invoke_impl_mfp_o &&mut_o) &noexcept
            -> invoke_impl_mfp_o & = default;
    };
}

#endif
