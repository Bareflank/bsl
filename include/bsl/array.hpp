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
/// @file array.hpp
///

#ifndef BSL_ARRAY_HPP
#define BSL_ARRAY_HPP

#include "details/out.hpp"

#include "contiguous_iterator.hpp"
#include "convert.hpp"
#include "cstdint.hpp"
#include "debug.hpp"
#include "reverse_iterator.hpp"
#include "safe_integral.hpp"
#include "touch.hpp"

namespace bsl
{
    /// @class bsl::array
    ///
    /// <!-- description -->
    ///   @brief Provides a safe encapsulation for a C-style array, minicing the
    ///     std::array APIs. This container is an aggregate type, but unlike
    ///     a std::array, a bsl::array does not provide the T[n] syntax as this
    ///     is nither Core Guideline compliant or compliant with AUTOSAR.
    ///     Instead we provide at_if() versions which return a pointer to the
    ///     element being requested. If the element does not exist, a nullptr
    ///     is returned, providing a means to check for logic errors without
    ///     the need for exceptions or failing fast which is not compliant with
    ///     AUTOSAR. We also do not support N==0 type arrays and like other
    ///     BSL classes, we do not support the member version of swap() and
    ///     fill() as they are not compliant with AUTOSAR (due to the name
    ///     reuse). User bsl::swap() and bsl::fill() instead.
    ///   @include example_array_overview.hpp
    ///
    /// <!-- template parameters -->
    ///   @tparam T the type of element being encapsulated.
    ///   @tparam N the total number of elements in the array. Cannot be 0
    ///
    template<typename T, bsl::uintmax N>
    // This triggers on ArrayToPointerDecay which is needed
    // NOLINTNEXTLINE(bsl-implicit-conversions-forbidden)
    class array final
    {
        static_assert(N != static_cast<bsl::uintmax>(0), "arrays of size 0 are not supported");

    public:
        /// @brief stores the array being wrapped
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
        /// @brief alias for: contiguous_iterator<T>
        using iterator_type = contiguous_iterator<T>;
        /// @brief alias for: contiguous_iterator<T const>
        using const_iterator_type = contiguous_iterator<T const>;
        /// @brief alias for: reverse_iterator<iterator>
        using reverse_iterator_type = reverse_iterator<iterator_type>;
        /// @brief alias for: reverse_iterator<const_iterator>
        using const_reverse_iterator_type = reverse_iterator<const_iterator_type>;

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
        at_if(size_type const &index) &noexcept -> pointer_type
        {
            if (!index) {
                bsl::error() << "array: index invalid\n";
                return nullptr;
            }

            if (index < to_umax(N)) {
                // We are implementing std::array here, which is what this test
                // wants you to use instead.
                // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index, bsl-implicit-conversions-forbidden)
                return &m_data[index.get()];
            }

            bsl::error() << "array: index out of range: " << index << '\n';
            return nullptr;
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
        at_if(size_type const &index) const &noexcept -> const_pointer_type
        {
            if (!index) {
                bsl::error() << "array: index invalid\n";
                return nullptr;
            }

            if (index < to_umax(N)) {
                // We are implementing std::array here, which is what this test
                // wants you to use instead.
                // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index, bsl-implicit-conversions-forbidden)
                return &m_data[index.get()];
            }

            bsl::error() << "array: index out of range: " << index << '\n';
            return nullptr;
        }

        /// @brief the r-value version of this function is not supported
        [[nodiscard]] constexpr auto at_if(size_type const &index) const &&noexcept
            -> const_pointer_type = delete;

        /// <!-- description -->
        ///   @brief Returns a reference to the first element in the array.
        ///   @include array/example_array_front.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a reference to the first element in the array.
        ///
        [[nodiscard]] constexpr auto
        front() &noexcept -> reference_type
        {
            return *this->at_if(size_type::zero());
        }

        /// <!-- description -->
        ///   @brief Returns a reference to the first element in the array.
        ///   @include array/example_array_front.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a reference to the first element in the array.
        ///
        [[nodiscard]] constexpr auto
        front() const &noexcept -> const_reference_type
        {
            return *this->at_if(size_type::zero());
        }

        /// @brief the r-value version of this function is not supported
        [[nodiscard]] constexpr auto front() const &&noexcept -> const_reference_type = delete;

        /// <!-- description -->
        ///   @brief Returns a pointer to the first element in the array.
        ///   @include array/example_array_front_if.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a pointer to the first element in the array.
        ///
        [[nodiscard]] constexpr auto
        front_if() &noexcept -> pointer_type
        {
            return this->at_if(size_type::zero());
        }

        /// <!-- description -->
        ///   @brief Returns a pointer to the first element in the array.
        ///   @include array/example_array_front_if.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a pointer to the first element in the array.
        ///
        [[nodiscard]] constexpr auto
        front_if() const &noexcept -> const_pointer_type
        {
            return this->at_if(size_type::zero());
        }

        /// @brief the r-value version of this function is not supported
        [[nodiscard]] constexpr auto front_if() const &&noexcept -> const_pointer_type = delete;

        /// <!-- description -->
        ///   @brief Returns a reference to the last element in the array.
        ///   @include array/example_array_back.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a reference to the last element in the array.
        ///
        [[nodiscard]] constexpr auto
        back() &noexcept -> reference_type
        {
            return *this->at_if(to_umax(N) - size_type::one());
        }

        /// <!-- description -->
        ///   @brief Returns a reference to the last element in the array.
        ///   @include array/example_array_back.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a reference to the last element in the array.
        ///
        [[nodiscard]] constexpr auto
        back() const &noexcept -> const_reference_type
        {
            return *this->at_if(to_umax(N) - size_type::one());
        }

        /// @brief the r-value version of this function is not supported
        [[nodiscard]] constexpr auto back() const &&noexcept -> const_reference_type = delete;

        /// <!-- description -->
        ///   @brief Returns a pointer to the last element in the array.
        ///   @include array/example_array_back_if.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a pointer to the last element in the array.
        ///
        [[nodiscard]] constexpr auto
        back_if() &noexcept -> pointer_type
        {
            return this->at_if(to_umax(N) - size_type::one());
        }

        /// <!-- description -->
        ///   @brief Returns a pointer to the last element in the array.
        ///   @include array/example_array_back_if.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a pointer to the last element in the array.
        ///
        [[nodiscard]] constexpr auto
        back_if() const &noexcept -> const_pointer_type
        {
            return this->at_if(to_umax(N) - size_type::one());
        }

        /// @brief the r-value version of this function is not supported
        [[nodiscard]] constexpr auto back_if() const &&noexcept -> const_pointer_type = delete;

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
        ///   @brief Returns an iterator to the first element of the array.
        ///   @include array/example_array_begin.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns an iterator to the first element of the array.
        ///
        [[nodiscard]] constexpr auto
        begin() &noexcept -> iterator_type
        {
            return iterator_type{this->front_if(), to_umax(N), size_type::zero()};
        }

        /// <!-- description -->
        ///   @brief Returns an iterator to the first element of the array.
        ///   @include array/example_array_begin.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns an iterator to the first element of the array.
        ///
        [[nodiscard]] constexpr auto
        begin() const &noexcept -> const_iterator_type
        {
            return const_iterator_type{this->front_if(), to_umax(N), size_type::zero()};
        }

        /// @brief the r-value version of this function is not supported
        [[nodiscard]] constexpr auto begin() const &&noexcept -> const_iterator_type = delete;

        /// <!-- description -->
        ///   @brief Returns an iterator to the first element of the array.
        ///   @include array/example_array_begin.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns an iterator to the first element of the array.
        ///
        [[nodiscard]] constexpr auto
        cbegin() const &noexcept -> const_iterator_type
        {
            return const_iterator_type{this->front_if(), to_umax(N), size_type::zero()};
        }

        /// @brief the r-value version of this function is not supported
        [[nodiscard]] constexpr auto cbegin() const &&noexcept -> const_iterator_type = delete;

        /// <!-- description -->
        ///   @brief Returns an iterator to the element "i" in the array.
        ///   @include array/example_array_iter.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param i the element in the array to return an iterator for.
        ///   @return Returns an iterator to the element "i" in the array.
        ///
        [[nodiscard]] constexpr auto
        iter(size_type const &i) &noexcept -> iterator_type
        {
            return iterator_type{this->front_if(), to_umax(N), i};
        }

        /// <!-- description -->
        ///   @brief Returns an iterator to the element "i" in the array.
        ///   @include array/example_array_iter.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param i the element in the array to return an iterator for.
        ///   @return Returns an iterator to the element "i" in the array.
        ///
        [[nodiscard]] constexpr auto
        iter(size_type const &i) const &noexcept -> const_iterator_type
        {
            return const_iterator_type{this->front_if(), to_umax(N), i};
        }

        /// @brief the r-value version of this function is not supported
        [[nodiscard]] constexpr auto iter(size_type const &i) const &&noexcept
            -> const_iterator_type = delete;

        /// <!-- description -->
        ///   @brief Returns an iterator to the element "i" in the array.
        ///   @include array/example_array_iter.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param i the element in the array to return an iterator for.
        ///   @return Returns an iterator to the element "i" in the array.
        ///
        [[nodiscard]] constexpr auto
        citer(size_type const &i) const &noexcept -> const_iterator_type
        {
            return const_iterator_type{this->front_if(), to_umax(N), i};
        }

        /// @brief the r-value version of this function is not supported
        [[nodiscard]] constexpr auto citer(size_type const &i) const &&noexcept
            -> const_iterator_type = delete;

        /// <!-- description -->
        ///   @brief Returns an iterator to one past the last element of the
        ///     array. If you attempt to access this iterator, a nullptr will
        ///     always be returned.
        ///   @include array/example_array_end.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns an iterator to one past the last element of the
        ///     array. If you attempt to access this iterator, a nullptr will
        ///     always be returned.
        ///
        [[nodiscard]] constexpr auto
        end() &noexcept -> iterator_type
        {
            return iterator_type{this->front_if(), to_umax(N), to_umax(N)};
        }

        /// <!-- description -->
        ///   @brief Returns an iterator to one past the last element of the
        ///     array. If you attempt to access this iterator, a nullptr will
        ///     always be returned.
        ///   @include array/example_array_end.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns an iterator to one past the last element of the
        ///     array. If you attempt to access this iterator, a nullptr will
        ///     always be returned.
        ///
        [[nodiscard]] constexpr auto
        end() const &noexcept -> const_iterator_type
        {
            return const_iterator_type{this->front_if(), to_umax(N), to_umax(N)};
        }

        /// @brief the r-value version of this function is not supported
        [[nodiscard]] constexpr auto end() const &&noexcept -> const_iterator_type = delete;

        /// <!-- description -->
        ///   @brief Returns an iterator to one past the last element of the
        ///     array. If you attempt to access this iterator, a nullptr will
        ///     always be returned.
        ///   @include array/example_array_end.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns an iterator to one past the last element of the
        ///     array. If you attempt to access this iterator, a nullptr will
        ///     always be returned.
        ///
        [[nodiscard]] constexpr auto
        cend() const &noexcept -> const_iterator_type
        {
            return const_iterator_type{this->front_if(), to_umax(N), to_umax(N)};
        }

        /// @brief the r-value version of this function is not supported
        [[nodiscard]] constexpr auto cend() const &&noexcept -> const_iterator_type = delete;

        /// <!-- description -->
        ///   @brief Returns a reverse iterator to one past the last element
        ///     of the array. When accessing the iterator, the iterator will
        ///     always return the element T[internal index - 1], providing
        ///     access to the range [N - 1, 0) while internally storing the
        ///     range [N, 1) with element 0 representing the end(). For more
        ///     information, see the bsl::reverse_iterator documentation.
        ///   @include array/example_array_rbegin.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a reverse iterator to the last element of the
        ///     array.
        ///
        [[nodiscard]] constexpr auto
        rbegin() &noexcept -> reverse_iterator_type
        {
            return reverse_iterator_type{this->end()};
        }

        /// <!-- description -->
        ///   @brief Returns a reverse iterator to one past the last element
        ///     of the array. When accessing the iterator, the iterator will
        ///     always return the element T[internal index - 1], providing
        ///     access to the range [N - 1, 0) while internally storing the
        ///     range [N, 1) with element 0 representing the end(). For more
        ///     information, see the bsl::reverse_iterator documentation.
        ///   @include array/example_array_rbegin.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a reverse iterator to the last element of the
        ///     array.
        ///
        [[nodiscard]] constexpr auto
        rbegin() const &noexcept -> const_reverse_iterator_type
        {
            return const_reverse_iterator_type{this->end()};
        }

        /// @brief the r-value version of this function is not supported
        [[nodiscard]] constexpr auto rbegin() const &&noexcept
            -> const_reverse_iterator_type = delete;

        /// <!-- description -->
        ///   @brief Returns a reverse iterator to one past the last element
        ///     of the array. When accessing the iterator, the iterator will
        ///     always return the element T[internal index - 1], providing
        ///     access to the range [N - 1, 0) while internally storing the
        ///     range [N, 1) with element 0 representing the end(). For more
        ///     information, see the bsl::reverse_iterator documentation.
        ///   @include array/example_array_rbegin.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a reverse iterator to the last element of the
        ///     array.
        ///
        [[nodiscard]] constexpr auto
        crbegin() const &noexcept -> const_reverse_iterator_type
        {
            return const_reverse_iterator_type{this->cend()};
        }

        /// @brief the r-value version of this function is not supported
        [[nodiscard]] constexpr auto crbegin() const &&noexcept
            -> const_reverse_iterator_type = delete;

        /// <!-- description -->
        ///   @brief Returns a reverse iterator element "i" in the
        ///     array. When accessing the iterator, the iterator will
        ///     always return the element T[internal index - 1], providing
        ///     access to the range [N - 1, 0) while internally storing the
        ///     range [N, 1) with element 0 representing the end(). For more
        ///     information, see the bsl::reverse_iterator documentation.
        ///   @include array/example_array_riter.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param i the element in the array to return an iterator for.
        ///   @return Returns a reverse iterator element "i" in the
        ///     array.
        ///
        [[nodiscard]] constexpr auto
        riter(size_type const &i) &noexcept -> reverse_iterator_type
        {
            if (!i) {
                return reverse_iterator_type{this->iter(size_type::zero())};
            }

            if (i < to_umax(N)) {
                return reverse_iterator_type{this->iter(i + size_type::one())};
            }

            return reverse_iterator_type{this->iter(size_type::zero())};
        }

        /// <!-- description -->
        ///   @brief Returns a reverse iterator element "i" in the
        ///     array. When accessing the iterator, the iterator will
        ///     always return the element T[internal index - 1], providing
        ///     access to the range [N - 1, 0) while internally storing the
        ///     range [N, 1) with element 0 representing the end(). For more
        ///     information, see the bsl::reverse_iterator documentation.
        ///   @include array/example_array_riter.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param i the element in the array to return an iterator for.
        ///   @return Returns a reverse iterator element "i" in the
        ///     array.
        ///
        [[nodiscard]] constexpr auto
        riter(size_type const &i) const &noexcept -> const_reverse_iterator_type
        {
            if (!i) {
                return const_reverse_iterator_type{this->iter(size_type::zero())};
            }

            if (i < to_umax(N)) {
                return const_reverse_iterator_type{this->iter(i + size_type::one())};
            }

            return const_reverse_iterator_type{this->iter(size_type::zero())};
        }

        /// @brief the r-value version of this function is not supported
        [[nodiscard]] constexpr auto riter(size_type const &i) const &&noexcept
            -> const_reverse_iterator_type = delete;

        /// <!-- description -->
        ///   @brief Returns a reverse iterator element "i" in the
        ///     array. When accessing the iterator, the iterator will
        ///     always return the element T[internal index - 1], providing
        ///     access to the range [N - 1, 0) while internally storing the
        ///     range [N, 1) with element 0 representing the end(). For more
        ///     information, see the bsl::reverse_iterator documentation.
        ///   @include array/example_array_riter.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param i the element in the array to return an iterator for.
        ///   @return Returns a reverse iterator element "i" in the
        ///     array.
        ///
        [[nodiscard]] constexpr auto
        criter(size_type const &i) const &noexcept -> const_reverse_iterator_type
        {
            if (!i) {
                return const_reverse_iterator_type{this->iter(size_type::zero())};
            }

            if (i < to_umax(N)) {
                return const_reverse_iterator_type{this->iter(i + size_type::one())};
            }

            return const_reverse_iterator_type{this->iter(size_type::zero())};
        }

        /// @brief the r-value version of this function is not supported
        [[nodiscard]] constexpr auto criter(size_type const &i) const &&noexcept
            -> const_reverse_iterator_type = delete;

        /// <!-- description -->
        ///   @brief Returns a reverse iterator first element of the
        ///     array. When accessing the iterator, the iterator will
        ///     always return the element T[internal index - 1], providing
        ///     access to the range [N - 1, 0) while internally storing the
        ///     range [N, 1) with element 0 representing the end(). For more
        ///     information, see the bsl::reverse_iterator documentation.
        ///   @include array/example_array_rend.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a reverse iterator first element of the
        ///     array.
        ///
        [[nodiscard]] constexpr auto
        rend() &noexcept -> reverse_iterator_type
        {
            return reverse_iterator_type{this->begin()};
        }

        /// <!-- description -->
        ///   @brief Returns a reverse iterator first element of the
        ///     array. When accessing the iterator, the iterator will
        ///     always return the element T[internal index - 1], providing
        ///     access to the range [N - 1, 0) while internally storing the
        ///     range [N, 1) with element 0 representing the end(). For more
        ///     information, see the bsl::reverse_iterator documentation.
        ///   @include array/example_array_rend.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a reverse iterator first element of the
        ///     array.
        ///
        [[nodiscard]] constexpr auto
        rend() const &noexcept -> const_reverse_iterator_type
        {
            return const_reverse_iterator_type{this->begin()};
        }

        /// @brief the r-value version of this function is not supported
        [[nodiscard]] constexpr auto rend() const &&noexcept
            -> const_reverse_iterator_type = delete;

        /// <!-- description -->
        ///   @brief Returns a reverse iterator first element of the
        ///     array. When accessing the iterator, the iterator will
        ///     always return the element T[internal index - 1], providing
        ///     access to the range [N - 1, 0) while internally storing the
        ///     range [N, 1) with element 0 representing the end(). For more
        ///     information, see the bsl::reverse_iterator documentation.
        ///   @include array/example_array_rend.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a reverse iterator first element of the
        ///     array.
        ///
        [[nodiscard]] constexpr auto
        crend() const &noexcept -> const_reverse_iterator_type
        {
            return const_reverse_iterator_type{this->cbegin()};
        }

        /// @brief the r-value version of this function is not supported
        [[nodiscard]] constexpr auto crend() const &&noexcept
            -> const_reverse_iterator_type = delete;

        /// <!-- description -->
        ///   @brief Since arrays of size 0 are not allowed, always returns
        ///     false.
        ///   @include array/example_array_empty.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Since arrays of size 0 are not allowed, always returns
        ///     false.
        ///
        [[nodiscard]] static constexpr auto
        empty() noexcept -> bool
        {
            return false;
        }

        /// <!-- description -->
        ///   @brief Returns !empty()
        ///   @include array/example_array_operator_bool.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns !empty()
        ///
        [[nodiscard]] constexpr explicit operator bool() const noexcept
        {
            return !this->empty();
        }

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
            return to_umax(N);
        }

        /// <!-- description -->
        ///   @brief Returns the max number of elements the BSL supports.
        ///   @include array/example_array_max_size.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the max number of elements the BSL supports.
        ///
        [[nodiscard]] static constexpr auto
        max_size() noexcept -> size_type
        {
            return size_type::max() / to_umax(sizeof(T));
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
            return to_umax(N) * to_umax(sizeof(T));
        }
    };

    /// @brief deduction guideline for bsl::array
    template<typename T, typename... U>
    array(T, U...) -> array<T, safe_uintmax::one().get() + sizeof...(U)>;

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
    template<typename T, bsl::uintmax N>
    [[nodiscard]] constexpr auto
    operator==(bsl::array<T, N> const &lhs, bsl::array<T, N> const &rhs) noexcept -> bool
    {
        for (safe_uintmax i{}; i < lhs.size(); ++i) {
            if (*lhs.at_if(i) != *rhs.at_if(i)) {
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
    template<typename T, bsl::uintmax N>
    [[nodiscard]] constexpr auto
    operator!=(bsl::array<T, N> const &lhs, bsl::array<T, N> const &rhs) noexcept -> bool
    {
        return !(lhs == rhs);
    }

    /// <!-- description -->
    ///   @brief Outputs the provided bsl::array to the provided
    ///     output type.
    ///   @related bsl::array
    ///   @include array/example_array_ostream.hpp
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T1 the type of outputter provided
    ///   @tparam T2 the type of element being encapsulated.
    ///   @tparam N the total number of elements in the array. Cannot be 0
    ///   @param o the instance of the outputter used to output the value.
    ///   @param val the array to output
    ///   @return return o
    ///
    template<typename T1, typename T2, bsl::uintmax N>
    [[maybe_unused]] constexpr auto
    operator<<(out<T1> const o, bsl::array<T2, N> const &val) noexcept -> out<T1>
    {
        if constexpr (!o) {
            return o;
        }

        for (safe_uintmax i{}; i < val.size(); ++i) {
            if (i.is_zero()) {
                o << "[" << *val.at_if(i);
            }
            else {
                o << ", " << *val.at_if(i);
            }
        }

        return o << ']';
    }
}

#endif
