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

#include "../convert.hpp"
#include "../cstdint.hpp"
#include "../safe_integral.hpp"

namespace bsl::details
{
    /// @class bsl::carray
    ///
    /// <!-- description -->
    ///   @brief For internal use only. This wraps a c-style array which is
    ///     needed internally in situations where a bsl::array cannot be used
    ///     instead. Do not use this directly and instead use a bsl::array.
    ///
    /// <!-- template parameters -->
    ///   @tparam T the type of element being encapsulated.
    ///   @tparam N the total number of elements in the carray. Cannot be 0
    ///
    template<typename T, bsl::uintmax N>
    // This triggers on ArrayToPointerDecay which is needed
    // NOLINTNEXTLINE(bsl-implicit-conversions-forbidden)
    class carray final
    {
        static_assert(N != static_cast<bsl::uintmax>(0), "carrays of size 0 are not supported");

    public:
        /// @brief stores the carray being wrapped
        // The *-c-arrays tests wants you to use a std::array, which is what
        // this class is implementing (chicken/egg issue). The non-private
        // member check is complaining about the use of non-private member
        // variables. In this case, std::array should be an aggregate type
        // which means that the array must be made public.
        // NOLINTNEXTLINE(cppcoreguidelines-avoid-c-arrays, hicpp-avoid-c-arrays, modernize-avoid-c-arrays, misc-non-private-member-variables-in-classes, bsl-non-pod-classdef)
        T m_data[N];

        /// @brief alias for: T
        using value_type = T;
        /// @brief alias for: safe_uintmax
        using size_type = safe_uintmax;
        /// @brief alias for: safe_uintmax
        using difference_type = safe_uintmax;
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
        ///     "index". If the index is out of bounds, or the carray is invalid,
        ///     this function returns a nullptr.
        ///
        /// <!-- inputs/outputs -->
        ///   @param index the index of the instance to return
        ///   @return Returns a pointer to the instance of T stored at index
        ///     "index". If the index is out of bounds, or the carray is invalid,
        ///     this function returns a nullptr.
        ///
        [[nodiscard]] constexpr auto
        at_if(size_type const &index) &noexcept -> pointer_type
        {
            if (!index) {
                return nullptr;
            }

            if (index < N) {
                // We are implementing std::array here, which is what this test
                // wants you to use instead.
                // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index, bsl-implicit-conversions-forbidden)
                return &m_data[index.get()];
            }

            return nullptr;
        }

        /// <!-- description -->
        ///   @brief Returns a pointer to the instance of T stored at index
        ///     "index". If the index is out of bounds, or the carray is invalid,
        ///     this function returns a nullptr.
        ///
        /// <!-- inputs/outputs -->
        ///   @param index the index of the instance to return
        ///   @return Returns a pointer to the instance of T stored at index
        ///     "index". If the index is out of bounds, or the carray is invalid,
        ///     this function returns a nullptr.
        ///
        [[nodiscard]] constexpr auto
        at_if(size_type const &index) const &noexcept -> const_pointer_type
        {
            if (!index) {
                return nullptr;
            }

            if (index < N) {
                // We are implementing std::array here, which is what this test
                // wants you to use instead.
                // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index, bsl-implicit-conversions-forbidden)
                return &m_data[index.get()];
            }

            return nullptr;
        }

        /// @brief the r-value version of this function is not supported
        [[nodiscard]] constexpr auto at_if(size_type const &index) const &&noexcept
            -> const_pointer_type = delete;

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

        /// @brief the r-value version of this function is not supported
        [[nodiscard]] constexpr auto data() const &&noexcept -> const_pointer_type = delete;

        /// <!-- description -->
        ///   @brief Returns the number of elements in the carray being
        ///     encapsulated.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the number of elements in the carray being
        ///     encapsulated.
        ///
        [[nodiscard]] static constexpr auto
        size() noexcept -> size_type
        {
            return to_umax(N);
        }
    };
}

#endif
