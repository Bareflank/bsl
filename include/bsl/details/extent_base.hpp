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

#ifndef BSL_DETAILS_EXTENT_BASE_HPP
#define BSL_DETAILS_EXTENT_BASE_HPP

#include "../cstdint.hpp"
#include "../integral_constant.hpp"

namespace bsl::details
{
    /// @brief defines the number of extents too remove.
    constexpr bsl::uintmax num_extents_to_remove{1U};

    /// @class bsl::details::extent_base
    ///
    /// <!-- description -->
    ///   @brief Implements bsl::extent. This is needed so that bsl::extent
    ///     can be marked as final.
    ///
    /// <!-- template parameters -->
    ///   @tparam T the type to get the extent from
    ///   @tparam N the dimension of T to the the extent from
    ///
    template<typename T, bsl::uintmax N = 0>
    class extent_base : public integral_constant<bsl::uintmax, 0>
    {
    protected:
        /// <!-- description -->
        ///   @brief Destroyes a previously created bsl::extent_base
        ///
        constexpr ~extent_base() noexcept = default;

        /// <!-- description -->
        ///   @brief copy constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///
        constexpr extent_base(extent_base const &o) noexcept = default;

        /// <!-- description -->
        ///   @brief move constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being moved
        ///
        constexpr extent_base(extent_base &&o) noexcept = default;

        /// <!-- description -->
        ///   @brief copy assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr auto operator=(extent_base const &o) &noexcept
            -> extent_base & = default;

        /// <!-- description -->
        ///   @brief move assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being moved
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr auto operator=(extent_base &&o) &noexcept
            -> extent_base & = default;
    };

    template<typename T>
    // This is needed to implement the type traits.
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-c-arrays, hicpp-avoid-c-arrays, modernize-avoid-c-arrays)
    class extent_base<T[], 0> : public integral_constant<bsl::uintmax, 0>
    {
    protected:
        /// <!-- description -->
        ///   @brief Destroyes a previously created bsl::extent_base
        ///
        constexpr ~extent_base() noexcept = default;

        /// <!-- description -->
        ///   @brief copy constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///
        constexpr extent_base(extent_base const &o) noexcept = default;

        /// <!-- description -->
        ///   @brief move constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being moved
        ///
        constexpr extent_base(extent_base &&o) noexcept = default;

        /// <!-- description -->
        ///   @brief copy assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr auto operator=(extent_base const &o) &noexcept
            -> extent_base & = default;

        /// <!-- description -->
        ///   @brief move assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being moved
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr auto operator=(extent_base &&o) &noexcept
            -> extent_base & = default;
    };

    template<typename T, bsl::uintmax N>
    // This is needed to implement the type traits.
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-c-arrays, hicpp-avoid-c-arrays, modernize-avoid-c-arrays)
    class extent_base<T[], N> : public extent_base<T, N - num_extents_to_remove>
    {
    protected:
        /// <!-- description -->
        ///   @brief Destroyes a previously created bsl::extent_base
        ///
        constexpr ~extent_base() noexcept = default;

        /// <!-- description -->
        ///   @brief copy constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///
        constexpr extent_base(extent_base const &o) noexcept = default;

        /// <!-- description -->
        ///   @brief move constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being moved
        ///
        constexpr extent_base(extent_base &&o) noexcept = default;

        /// <!-- description -->
        ///   @brief copy assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr auto operator=(extent_base const &o) &noexcept
            -> extent_base & = default;

        /// <!-- description -->
        ///   @brief move assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being moved
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr auto operator=(extent_base &&o) &noexcept
            -> extent_base & = default;
    };

    template<typename T, bsl::uintmax I>
    // This is needed to implement the type traits.
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-c-arrays, hicpp-avoid-c-arrays, modernize-avoid-c-arrays)
    class extent_base<T[I], 0> : public integral_constant<bsl::uintmax, I>
    {
    protected:
        /// <!-- description -->
        ///   @brief Destroyes a previously created bsl::extent_base
        ///
        constexpr ~extent_base() noexcept = default;

        /// <!-- description -->
        ///   @brief copy constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///
        constexpr extent_base(extent_base const &o) noexcept = default;

        /// <!-- description -->
        ///   @brief move constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being moved
        ///
        constexpr extent_base(extent_base &&o) noexcept = default;

        /// <!-- description -->
        ///   @brief copy assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr auto operator=(extent_base const &o) &noexcept
            -> extent_base & = default;

        /// <!-- description -->
        ///   @brief move assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being moved
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr auto operator=(extent_base &&o) &noexcept
            -> extent_base & = default;
    };

    template<typename T, bsl::uintmax I, bsl::uintmax N>
    // This is needed to implement the type traits.
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-c-arrays, hicpp-avoid-c-arrays, modernize-avoid-c-arrays)
    class extent_base<T[I], N> : public extent_base<T, N - num_extents_to_remove>
    {
    protected:
        /// <!-- description -->
        ///   @brief Destroyes a previously created bsl::extent_base
        ///
        constexpr ~extent_base() noexcept = default;

        /// <!-- description -->
        ///   @brief copy constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///
        constexpr extent_base(extent_base const &o) noexcept = default;

        /// <!-- description -->
        ///   @brief move constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being moved
        ///
        constexpr extent_base(extent_base &&o) noexcept = default;

        /// <!-- description -->
        ///   @brief copy assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr auto operator=(extent_base const &o) &noexcept
            -> extent_base & = default;

        /// <!-- description -->
        ///   @brief move assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being moved
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr auto operator=(extent_base &&o) &noexcept
            -> extent_base & = default;
    };
}

#endif
