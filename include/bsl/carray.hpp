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
/// @file carray.hpp
///

#ifndef BSL_CARRAY_HPP
#define BSL_CARRAY_HPP

#include "cstdint.hpp"
#include "touch.hpp"
#include "unlikely.hpp"

namespace bsl
{
    /// @class bsl::carray
    ///
    /// <!-- description -->
    ///   @brief Provides a limited version of bsl::array with almost no
    ///     dependencies which can be used to help implement platform
    ///     features as needed.
    ///
    /// <!-- template parameters -->
    ///   @tparam T the type of element being encapsulated.
    ///   @tparam N the total number of elements in the array. Cannot be 0
    ///
    template<typename T, bsl::uintmx N>
    class carray final
    {
        static_assert(static_cast<bsl::uintmx>(0) != N, "arrays of size 0 are not supported");

    public:
        /// @brief stores the array being wrapped
        T m_data[N];    // NOLINT

        /// @brief alias for: T
        using value_type = T;
        /// @brief alias for: bsl::uintmx
        using size_type = bsl::uintmx;
        /// @brief alias for: bsl::uintmx
        using index_type = bsl::uintmx;
        /// @brief alias for: bsl::uintmx
        using difference_type = bsl::uintmx;
        /// @brief alias for: T &
        using reference_type = T &;
        /// @brief alias for: T const &
        using const_reference_type = T const &;
        /// @brief alias for: T *
        using pointer_type = T *;
        /// @brief alias for: T const *
        using const_pointer_type = T const *;

        /// <!-- description -->
        ///   @brief Returns a pointer to the instance of T stored at index
        ///     "index". If the index is out of bounds, or the array is invalid,
        ///     this function returns a nullptr.
        ///   @include array/example_array_at_if.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param index the index of the instance to return
        ///   @return Returns a pointer to the instance of T stored at index
        ///     "index". If the index is out of bounds, or the array is invalid,
        ///     this function returns a nullptr.
        ///
        [[nodiscard]] constexpr auto
        // NOLINTNEXTLINE(bsl-non-safe-integral-types-are-forbidden)
        at_if(index_type const &index) &noexcept -> pointer_type
        {
            if (unlikely(index >= N)) {
                return nullptr;
            }

            // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index)
            return &m_data[index];
        }

        /// <!-- description -->
        ///   @brief Returns a pointer to the instance of T stored at index
        ///     "index". If the index is out of bounds, or the array is invalid,
        ///     this function returns a nullptr.
        ///   @include array/example_array_at_if.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param index the index of the instance to return
        ///   @return Returns a pointer to the instance of T stored at index
        ///     "index". If the index is out of bounds, or the array is invalid,
        ///     this function returns a nullptr.
        ///
        [[nodiscard]] constexpr auto
        // NOLINTNEXTLINE(bsl-non-safe-integral-types-are-forbidden)
        at_if(index_type const &index) const &noexcept -> const_pointer_type
        {
            if (unlikely(index >= N)) {
                return nullptr;
            }

            // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index)
            return &m_data[index];
        }

        /// <!-- description -->
        ///   @brief Returns a pointer to the array being encapsulated.
        ///   @include array/example_array_data.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a pointer to the array being encapsulated.
        ///
        [[nodiscard]] constexpr auto
        data() &noexcept -> pointer_type
        {
            return static_cast<pointer_type>(m_data);
        }
        // GRCOV_EXCLUDE - no idea why this is needed but it is

        /// <!-- description -->
        ///   @brief Returns a pointer to the array being encapsulated.
        ///   @include array/example_array_data.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a pointer to the array being encapsulated.
        ///
        [[nodiscard]] constexpr auto
        data() const &noexcept -> const_pointer_type
        {
            return static_cast<const_pointer_type>(m_data);
        }
        // GRCOV_EXCLUDE - no idea why this is needed but it is

        /// <!-- description -->
        ///   @brief Returns the number of elements in the array being
        ///     encapsulated.
        ///   @include array/example_array_size.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the number of elements in the array being
        ///     encapsulated.
        ///
        [[nodiscard]] static constexpr auto
        size() noexcept -> size_type
        {
            return size_type{N};
        }

        /// <!-- description -->
        ///   @brief Returns size() * sizeof(T)
        ///   @include array/example_array_size_bytes.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns size() * sizeof(T)
        ///
        [[nodiscard]] static constexpr auto
        size_bytes() noexcept -> size_type
        {
            // NOLINTNEXTLINE(bsl-types-fixed-width-ints-arithmetic-check)
            return size_type{N} * sizeof(T);
        }
    };

    /// @brief deduction guideline for bsl::array
    template<typename T, typename... U>
    // NOLINTNEXTLINE(bsl-types-fixed-width-ints-arithmetic-check, bsl-non-safe-integral-types-are-forbidden)
    carray(T, U...) noexcept->carray<T, static_cast<bsl::uintmx>(1) + sizeof...(U)>;

    /// <!-- description -->
    ///   @brief Returns true if two arrays contain the same contents.
    ///     Returns false otherwise.
    ///   @include array/example_array_equals.hpp
    ///   @related bsl::array
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of element being encapsulated.
    ///   @tparam N the total number of elements in the array. Cannot be 0
    ///   @param lhs the left hand side of the operation
    ///   @param rhs the right hand side of the operation
    ///   @return Returns true if two arrays contain the same contents.
    ///     Returns false otherwise.
    ///
    template<typename T, bsl::uintmx N>
    [[nodiscard]] constexpr auto
    operator==(bsl::carray<T, N> const &lhs, bsl::carray<T, N> const &rhs) noexcept -> bool
    {
        // NOLINTNEXTLINE(bsl-non-safe-integral-types-are-forbidden)
        for (bsl::uintmx mut_i{}; mut_i < lhs.size(); ++mut_i) {
            if (*lhs.at_if(mut_i) != *rhs.at_if(mut_i)) {
                return false;
            }

            bsl::touch();
        }

        return true;
    }

    /// <!-- description -->
    ///   @brief Returns false if two arrays contain the same contents.
    ///     Returns true otherwise.
    ///   @include array/example_array_not_equals.hpp
    ///   @related bsl::array
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of element being encapsulated.
    ///   @tparam N the total number of elements in the array. Cannot be 0
    ///   @param lhs the left hand side of the operation
    ///   @param rhs the right hand side of the operation
    ///   @return Returns true if two arrays have the same size and contain
    ///     the same contents. Returns false otherwise.
    ///
    template<typename T, bsl::uintmx N>
    [[nodiscard]] constexpr auto
    operator!=(bsl::carray<T, N> const &lhs, bsl::carray<T, N> const &rhs) noexcept -> bool
    {
        return !(lhs == rhs);
    }
}

#endif
