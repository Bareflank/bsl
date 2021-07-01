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
/// @file in_place_index_t.hpp
///

#ifndef BSL_IN_PLACE_INDEX_T_HPP
#define BSL_IN_PLACE_INDEX_T_HPP

#include "cstdint.hpp"

namespace bsl
{
    /// @class bsl::in_place_index_t
    ///
    /// <!-- description -->
    ///   @brief bsl::in_place, bsl::in_place_type, and bsl::in_place_index
    ///     are disambiguation tags that can be passed to the constructors of
    ///     classes like bls::result to indicate that the contained object
    ///     should be constructed in-place. In addition, bsl::in_place_type
    ///     and bsl::in_place_index provide type and indiex information
    ///     as well.
    ///
    /// <!-- template parameters -->
    ///   @tparam I the index to construct in place at
    ///
    template<bsl::uintmax I>
    class in_place_index_t final
    {
    public:
        /// <!-- description -->
        ///   @brief Default constructor that ensures construction of
        ///     this type must be explicit
        ///
        explicit constexpr in_place_index_t() noexcept = default;

        /// <!-- description -->
        ///   @brief Destroyes a previously created bsl::in_place_index_t
        ///
        constexpr ~in_place_index_t() noexcept = default;

        /// <!-- description -->
        ///   @brief copy constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///
        constexpr in_place_index_t(in_place_index_t const &o) noexcept = default;

        /// <!-- description -->
        ///   @brief move constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_o the object being moved
        ///
        constexpr in_place_index_t(in_place_index_t &&mut_o) noexcept = default;

        /// <!-- description -->
        ///   @brief copy assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr auto operator=(in_place_index_t const &o) &noexcept
            -> in_place_index_t & = default;

        /// <!-- description -->
        ///   @brief move assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_o the object being moved
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr auto operator=(in_place_index_t &&mut_o) &noexcept
            -> in_place_index_t & = default;
    };
}

#endif
