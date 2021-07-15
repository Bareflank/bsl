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

#ifndef BSL_DETAILS_INVOKE_TRAITS_HPP
#define BSL_DETAILS_INVOKE_TRAITS_HPP

#include "../bool_constant.hpp"
#include "../conjunction.hpp"
#include "../declval.hpp"
#include "../disjunction.hpp"
#include "../invoke.hpp"
#include "../is_convertible.hpp"
#include "../is_nothrow_convertible.hpp"
#include "../is_void.hpp"
#include "../void_t.hpp"
#include "invoke_type.hpp"

namespace bsl::details
{
    /// @class bsl::details::invoke_traits
    ///
    /// <!-- description -->
    ///   @brief The invoke_traits class is used to determine if a set of
    ///     arguments are invocable and if so, how. To do this, we define
    ///     a default invoke_traits that states the provided args are not
    ///     callable. We then define a specialized version of invoke_traits
    ///     that is only selected if a call to invoke with the provided
    ///     arguments is valid. If this is true, this class defines the
    ///     "type" alias which is used by invoke_result, as well as 4
    ///     bools that define the different ways in which the args are
    ///     callable (based on the APIs that C++ supports) which are all
    ///     used by is_vocable and friends. The reason we define the
    ///     "type" alias is that the invoke_result should be capable of
    ///     acting as is_invocable as well, meaning invoke_result only
    ///     defines the "type" alias when the arguments define a callable.
    ///     If a callable cannot be formed, this alias is not provided,
    ///     allowing invoke_result to be used in SFINAE.
    ///
    /// <!-- template parameters -->
    ///   @tparam ALWAYS_VOID is always "void"
    ///   @tparam FUNC the type that defines the function being called
    ///   @tparam TN the types that define the arguments passed to the
    ///     provided function when called.
    ///
    template<typename ALWAYS_VOID, typename FUNC, typename... TN>
    class invoke_traits
    {
    public:
        /// <!-- description -->
        ///   @brief Returns true if the provided args form a callable
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if the provided args form a callable
        ///
        [[nodiscard]] static constexpr auto
        get_is_invocable() noexcept -> bool
        {
            return false;
        }

        /// <!-- description -->
        ///   @brief Returns true if the provided args form a callable that
        ///     never throws.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if the provided args form a callable that
        ///     never throws.
        ///
        [[nodiscard]] static constexpr auto
        get_is_nothrow_invocable() noexcept -> bool
        {
            return false;
        }

        /// <!-- description -->
        ///   @brief Returns true if the provided args form a callable that
        ///     is convertible to R
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam R the type of function FUNC is convertible to.
        ///   @return Returns true if the provided args form a callable that
        ///     is convertible to R
        ///
        template<typename R>
        [[nodiscard]] static constexpr auto
        get_is_invocable_r() noexcept -> bool
        {
            return false;
        }

        /// <!-- description -->
        ///   @brief Returns true if the provided args form a callable that
        ///     never throws and is convertible to R
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam R the type of function FUNC is convertible to.
        ///   @return Returns true if the provided args form a callable that
        ///     never throws and is convertible to R
        ///
        template<typename R>
        [[nodiscard]] static constexpr auto
        get_is_nothrow_invocable_r() noexcept -> bool
        {
            return false;
        }

        /// <!-- description -->
        ///   @brief Default constructor
        ///
        constexpr invoke_traits() noexcept = default;

    protected:
        /// <!-- description -->
        ///   @brief Destroyes a previously created bsl::invoke_traits
        ///
        constexpr ~invoke_traits() noexcept = default;

        /// <!-- description -->
        ///   @brief copy constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///
        constexpr invoke_traits(invoke_traits const &o) noexcept = default;

        /// <!-- description -->
        ///   @brief move constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_o the object being moved
        ///
        constexpr invoke_traits(invoke_traits &&mut_o) noexcept = default;

        /// <!-- description -->
        ///   @brief copy assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr auto operator=(invoke_traits const &o) &noexcept
            -> invoke_traits & = default;

        /// <!-- description -->
        ///   @brief move assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_o the object being moved
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr auto operator=(invoke_traits &&mut_o) &noexcept
            -> invoke_traits & = default;
    };

    /// @class bsl::details::invoke_traits
    ///
    /// <!-- description -->
    ///   @brief The invoke_traits class is used to determine if a set of
    ///     arguments are invocable and if so, how. To do this, we define
    ///     a default invoke_traits that states the provided args are not
    ///     callable. We then define a specialized version of invoke_traits
    ///     that is only selected if a call to invoke with the provided
    ///     arguments is valid. If this is true, this class defines the
    ///     "type" alias which is used by invoke_result, as well as 4
    ///     bools that define the different ways in which the args are
    ///     callable (based on the APIs that C++ supports) which are all
    ///     used by is_vocable and friends. The reason we define the
    ///     "type" alias is that the invoke_result should be capable of
    ///     acting as is_invocable as well, meaning invoke_result only
    ///     defines the "type" alias when the arguments define a callable.
    ///     If a callable cannot be formed, this alias is not provided,
    ///     allowing invoke_result to be used in SFINAE.
    ///
    /// <!-- template parameters -->
    ///   @tparam FUNC the type that defines the function being called
    ///   @tparam TN the types that define the arguments passed to the
    ///     provided function when called.
    ///
    template<typename FUNC, typename... TN>
    class invoke_traits<void_t<invoke_type<FUNC, TN...>>, FUNC, TN...>
    {
    public:
        /// @brief provides the member typedef "type"
        using type = invoke_type<FUNC, TN...>;

        /// <!-- description -->
        ///   @brief Returns true if the provided args form a callable
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if the provided args form a callable
        ///
        [[nodiscard]] static constexpr auto
        get_is_invocable() noexcept -> bool
        {
            return true;
        }

        /// <!-- description -->
        ///   @brief Returns true if the provided args form a callable that
        ///     never throws.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if the provided args form a callable that
        ///     never throws.
        ///
        [[nodiscard]] static constexpr auto
        get_is_nothrow_invocable() noexcept -> bool
        {
            return noexcept(invoke(declval<FUNC>(), declval<TN>()...));
        }

        /// <!-- description -->
        ///   @brief Returns true if the provided args form a callable that
        ///     is convertible to R
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam R the type of function FUNC is convertible to.
        ///   @return Returns true if the provided args form a callable that
        ///     is convertible to R
        ///
        template<typename R>
        [[nodiscard]] static constexpr auto
        get_is_invocable_r() noexcept -> bool
        {
            return disjunction<is_void<R>, is_convertible<R, type>>::value;
        }

        /// <!-- description -->
        ///   @brief Returns true if the provided args form a callable that
        ///     never throws and is convertible to R
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam R the type of function FUNC is convertible to.
        ///   @return Returns true if the provided args form a callable that
        ///     never throws and is convertible to R
        ///
        template<typename R>
        [[nodiscard]] static constexpr auto
        get_is_nothrow_invocable_r() noexcept -> bool
        {
            return conjunction<
                bool_constant<noexcept(invoke(declval<FUNC>(), declval<TN>()...))>,
                disjunction<is_void<R>, is_nothrow_convertible<R, type>>>::value;
        }

        /// <!-- description -->
        ///   @brief Default constructor
        ///
        constexpr invoke_traits() noexcept = default;

    protected:
        /// <!-- description -->
        ///   @brief Destroyes a previously created bsl::invoke_traits
        ///
        constexpr ~invoke_traits() noexcept = default;

        /// <!-- description -->
        ///   @brief copy constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///
        constexpr invoke_traits(invoke_traits const &o) noexcept = default;

        /// <!-- description -->
        ///   @brief move constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_o the object being moved
        ///
        constexpr invoke_traits(invoke_traits &&mut_o) noexcept = default;

        /// <!-- description -->
        ///   @brief copy assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr auto operator=(invoke_traits const &o) &noexcept
            -> invoke_traits & = default;

        /// <!-- description -->
        ///   @brief move assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_o the object being moved
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr auto operator=(invoke_traits &&mut_o) &noexcept
            -> invoke_traits & = default;
    };
}

#endif
