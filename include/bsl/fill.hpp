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
/// @file fill.hpp
///

#ifndef BSL_FILL_HPP
#define BSL_FILL_HPP

#include "cstdint.hpp"
#include "cstring.hpp"
#include "enable_if.hpp"
#include "is_constant_evaluated.hpp"
#include "is_fundamental.hpp"
#include "is_copy_assignable.hpp"
#include "is_nothrow_copy_assignable.hpp"

namespace bsl
{
    namespace details
    {
        /// <!-- description -->
        ///   @brief Provides the internal implementation of the fill
        ///     function. Specifically, this is the non-optimized version.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam VIEW the type of view to fill
        ///   @tparam T the type to fill the view with
        ///   @param v the view to fill
        ///   @param value what to fill the view with
        ///
        template<typename VIEW, typename T>
        constexpr void
        fill_impl(VIEW &v, T const &value) noexcept(    // --
            is_nothrow_copy_assignable<T>::value)
        {
            for (bsl::uintmax i{}; i < v.size(); ++i) {
                *v.at_if(i) = value;
            }
        }
    }

    /// <!-- description -->
    ///   @brief Sets all elements of a view to "value". T must be
    ///     copy assignable.
    ///   @include example_fill_overview.hpp
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type that defines the values being filled
    ///   @param v the view to fill
    ///   @param value the value to set the view's elements to
    ///   @return return's void
    ///
    /// <!-- inputs/outputs -->
    ///   @throw throws if the copy assignment of T throws
    ///
    template<typename VIEW, typename T>
    constexpr enable_if_t<is_copy_assignable<T>::value>
    fill(VIEW &v, T const &value) noexcept(    // --
        is_nothrow_copy_assignable<T>::value)
    {
        if (is_fundamental<T>::value && !is_constant_evaluated()) {
            if (T{} == value) {
                bsl::builtin_memset(v.data(), 0, v.size_bytes());
            }
            else {
                details::fill_impl(v, value);
            }
        }
        else {
            details::fill_impl(v, value);
        }
    }

    /// <!-- description -->
    ///   @brief Sets all elements of a view to "value". T must be
    ///     copy assignable.
    ///   @include example_fill_overview.hpp
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type that defines the values being filled
    ///   @param first the position to start the loop
    ///   @param last the position to end the loop
    ///   @param value the value to set the view's elements to
    ///   @return return's void
    ///
    /// <!-- inputs/outputs -->
    ///   @throw throws if the copy assignment of T throws
    ///
    template<typename ITER, typename T>
    constexpr enable_if_t<is_copy_assignable<T>::value>
    fill(ITER first, ITER last, T const &value) noexcept(    // --
        is_nothrow_copy_assignable<T>::value)
    {
        for (; first < last; ++first) {
            *first.get_if() = value;
        }
    }
}

#endif
