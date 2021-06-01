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
/// @file addressof.hpp
///

#ifndef BSL_SORT_HPP
#define BSL_SORT_HPP

#include "safe_integral.hpp"
#include "swap.hpp"

namespace bsl
{
    namespace details
    {
        /// <!-- description -->
        ///   @brief Implements sort's comparison function
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T the type of element to compare
        ///   @param a the first element to compare
        ///   @param b the second element to compare
        ///   @return Returns true if a is less b, false otherwise
        ///
        template<typename T>
        [[nodiscard]] constexpr auto
        sort_cmp(T const &a, T const &b) noexcept -> bool
        {
            return a < b;
        };
    }

    /// <!-- description -->
    ///   @brief Sorts the elements in a container in non-descending
    ///     order. This is similar to std::sort, with the following
    ///     exceptions:
    ///     - The time-complexity is O(x^2) for the worst case and O(n) for
    ///       the best case as the insertion sort algorithm is used
    ///       specifically to keep the space-complexity to O(1). Faster
    ///       algorithms have space-complexity algorithms that might consume
    ///       too much stack space for applications with limited resources
    ///       like a hypervisor, or embedded system.
    ///     - The sort algorithm also doesn't take an iterator, but instead
    ///       take the container itself. So long as the container implements
    ///       at_if() and size(), this function will work.
    ///   @include example_sort_overview.hpp
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of container to sort
    ///   @tparam COMPARE the type of comparison function to use
    ///   @param container the container to sort
    ///   @param cmp the comparison function to use
    ///
    template<typename T, typename COMPARE>
    constexpr void
    sort(T &container, COMPARE &&cmp) noexcept
    {
        for (safe_uintmax i{ONE_UMAX}; i < container.size(); ++i) {
            for (safe_uintmax j{i}; j > ZERO_UMAX; --j) {
                auto &elem1{*container.at_if(j)};
                auto &elem2{*container.at_if(j - ONE_UMAX)};

                if (!cmp(elem1, elem2)) {
                    break;
                }

                swap(elem1, elem2);
            }
        }
    }

    /// <!-- description -->
    ///   @brief Sorts the elements in a container in non-descending
    ///     order. This is similar to std::sort, with the following
    ///     exceptions:
    ///     - The time-complexity is O(x^2) for the worst case and O(n) for
    ///       the best case as the insertion sort algorithm is used
    ///       specifically to keep the space-complexity to O(1). Faster
    ///       algorithms have space-complexity algorithms that might consume
    ///       too much stack space for applications with limited resources
    ///       like a hypervisor, or embedded system.
    ///     - The sort algorithm also doesn't take an iterator, but instead
    ///       take the container itself. So long as the container implements
    ///       at_if() and size(), this function will work.
    ///   @include example_sort_overview.hpp
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of container to sort
    ///   @param container the container to sort
    ///
    template<typename T>
    constexpr void
    sort(T &container) noexcept
    {
        return sort(container, &details::sort_cmp<typename T::value_type>);
    }
}

#endif
