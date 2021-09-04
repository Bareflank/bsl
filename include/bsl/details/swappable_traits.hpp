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

#ifndef BSL_DETAILS_SWAPPABLE_TRAITS_HPP
#define BSL_DETAILS_SWAPPABLE_TRAITS_HPP

#include "../conjunction.hpp"
#include "../declval.hpp"
#include "../swap.hpp"
#include "../void_t.hpp"
#include "swappable_type.hpp"

namespace bsl::details
{
    /// @class bsl::details::swappable_traits
    ///
    /// <!-- description -->
    ///   @brief The swappable_traits class is used to determine if a set of
    ///     arguments are swappable and if so, how. To do this, we define
    ///     a default swappable_traits that states the provided args are not
    ///     swappable. We then define a specialized version of
    ///     swappable_traits that is only selected if a call to swap with
    ///     the provided arguments is valid. If this is true, this class
    ///     defines the states that T and U are swappable. In addition,
    ///     we use the noexcept operator to determine if T and U are
    ///     nothrow swappable. This design ensures deleting a swap function
    ///     is still supported.
    ///
    /// <!-- template parameters -->
    ///   @tparam ALWAYS_VOID1 is always "void"
    ///   @tparam ALWAYS_VOID2 is always "void"
    ///   @tparam T the first type to query
    ///   @tparam U the second type to query
    ///
    template<typename ALWAYS_VOID1, typename ALWAYS_VOID2, typename T, typename U>
    class swappable_traits
    {
    public:
        /// <!-- description -->
        ///   @brief Returns true if the provided args are swappable
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if the provided args are swappable
        ///
        [[nodiscard]] static constexpr auto
        get_is_swappable_with() noexcept -> bool
        {
            return false;
        }

        /// <!-- description -->
        ///   @brief Returns true if the provided args are swappable without
        ///     throwing an exception.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if the provided args are swappable without
        ///     throwing an exception.
        ///
        [[nodiscard]] static constexpr auto
        get_is_nothrow_swappable_with() noexcept -> bool
        {
            return false;
        }

    protected:
        /// <!-- description -->
        ///   @brief Destroyes a previously created bsl::swappable_traits
        ///
        constexpr ~swappable_traits() noexcept = default;

        /// <!-- description -->
        ///   @brief copy constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///
        constexpr swappable_traits(swappable_traits const &o) noexcept = default;

        /// <!-- description -->
        ///   @brief move constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_o the object being moved
        ///
        constexpr swappable_traits(swappable_traits &&mut_o) noexcept = default;

        /// <!-- description -->
        ///   @brief copy assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr auto operator=(swappable_traits const &o) &noexcept
            -> swappable_traits & = default;

        /// <!-- description -->
        ///   @brief move assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_o the object being moved
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr auto operator=(swappable_traits &&mut_o) &noexcept
            -> swappable_traits & = default;
    };

    /// @class bsl::details::swappable_traits
    ///
    /// <!-- description -->
    ///   @brief The swappable_traits class is used to determine if a set of
    ///     arguments are swappable and if so, how. To do this, we define
    ///     a default swappable_traits that states the provided args are not
    ///     swappable. We then define a specialized version of
    ///     swappable_traits that is only selected if a call to swap with
    ///     the provided arguments is valid. If this is true, this class
    ///     defines the states that T and U are swappable. In addition,
    ///     we use the noexcept operator to determine if T and U are
    ///     nothrow swappable. This design ensures deleting a swap function
    ///     is still supported.
    ///
    /// <!-- template parameters -->
    ///   @tparam T the first type to query
    ///   @tparam U the second type to query
    ///
    template<typename T, typename U>
    class swappable_traits<void_t<swappable_type<T, U>>, void_t<swappable_type<U, T>>, T, U>
    {
    public:
        /// <!-- description -->
        ///   @brief Returns true if the provided args are swappable
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if the provided args are swappable
        ///
        [[nodiscard]] static constexpr auto
        get_is_swappable_with() noexcept -> bool
        {
            return true;
        }

        /// <!-- description -->
        ///   @brief Returns true if the provided args are swappable without
        ///     throwing an exception.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if the provided args are swappable without
        ///     throwing an exception.
        ///
        [[nodiscard]] static constexpr auto
        get_is_nothrow_swappable_with() noexcept -> bool
        {
            return conjunction<
                bool_constant<noexcept(swap(declval<T>(), declval<U>()))>,
                bool_constant<noexcept(swap(declval<U>(), declval<T>()))>>::value;
        }

    protected:
        /// <!-- description -->
        ///   @brief Destroyes a previously created bsl::swappable_traits
        ///
        constexpr ~swappable_traits() noexcept = default;

        /// <!-- description -->
        ///   @brief copy constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///
        constexpr swappable_traits(swappable_traits const &o) noexcept = default;

        /// <!-- description -->
        ///   @brief move constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_o the object being moved
        ///
        constexpr swappable_traits(swappable_traits &&mut_o) noexcept = default;

        /// <!-- description -->
        ///   @brief copy assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr auto operator=(swappable_traits const &o) &noexcept
            -> swappable_traits & = default;

        /// <!-- description -->
        ///   @brief move assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_o the object being moved
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr auto operator=(swappable_traits &&mut_o) &noexcept
            -> swappable_traits & = default;
    };
}

#endif
