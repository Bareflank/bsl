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

#include "bsl/safe_idx.hpp"
#include "bsl/swap.hpp"

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
    ///   @param udm_container the container to sort
    ///   @param pudm_udm_cmp the comparison function to use
    ///
    template<typename T, typename COMPARE>
    constexpr void
    sort(T &udm_container, COMPARE &&pudm_udm_cmp) noexcept
    {
        for (safe_idx mut_i{safe_idx::magic_1()}; mut_i < udm_container.size(); ++mut_i) {
            for (safe_idx mut_j{mut_i}; mut_j > safe_idx::magic_0(); --mut_j) {
                auto &mut_elem1{*udm_container.at_if(mut_j)};
                auto &mut_elem2{*udm_container.at_if(mut_j - safe_idx::magic_1())};

                if (!pudm_udm_cmp(mut_elem1, mut_elem2)) {
                    break;
                }

                swap(mut_elem1, mut_elem2);
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
    ///   @param udm_container the container to sort
    ///
    template<typename T>
    constexpr void
    sort(T &udm_container) noexcept
    {
        return sort(udm_container, &details::sort_cmp<typename T::value_type>);
    }
}

#endif
