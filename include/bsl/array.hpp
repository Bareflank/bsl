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

#include "bsl/contiguous_iterator.hpp"    // IWYU pragma: export
#include "bsl/details/out.hpp"
#include "bsl/ensures.hpp"
#include "bsl/expects.hpp"
#include "bsl/is_constant_evaluated.hpp"
#include "bsl/reverse_iterator.hpp"    // IWYU pragma: export
#include "bsl/safe_idx.hpp"
#include "bsl/safe_integral.hpp"
#include "bsl/touch.hpp"
#include "bsl/unlikely.hpp"

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
    template<typename T, bsl::uintmx N>
    class array final
    {
        static_assert(static_cast<bsl::uintmx>(0) != N, "arrays of size 0 are not supported");

    public:
        /// @brief stores the array being wrapped
        T m_data[N];    // NOLINT

        /// @brief alias for: T
        using value_type = T;
        /// @brief alias for: safe_umx
        using size_type = safe_umx;
        /// @brief alias for: safe_idx
        using index_type = safe_idx;
        /// @brief alias for: safe_umx
        using difference_type = safe_umx;
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
        at_if(index_type const &index) &noexcept -> pointer_type
        {
            expects(index.is_valid());

            if (unlikely(index >= N)) {
                return nullptr;
            }

            // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index)
            return &m_data[index.get()];
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
        at_if(index_type const &index) const &noexcept -> const_pointer_type
        {
            expects(index.is_valid());

            if (unlikely(index >= N)) {
                return nullptr;
            }

            // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index)
            return &m_data[index.get()];
        }

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
            return *this->at_if({});
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
            return *this->at_if({});
        }

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
            return this->at_if({});
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
            return this->at_if({});
        }

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
            /// NOTE:
            /// - Since N cannot be 0, the following will never overflow
            ///   which is why it is marked as checked().
            ///

            constexpr index_type index{(N - size_type::magic_1()).checked().get()};
            return *this->at_if(index);
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
            /// NOTE:
            /// - Since N cannot be 0, the following will never overflow
            ///   which is why it is marked as checked().
            ///

            constexpr index_type index{(N - size_type::magic_1()).checked().get()};
            return *this->at_if(index);
        }

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
            /// NOTE:
            /// - Since N cannot be 0, the following will never overflow
            ///   which is why it is marked as checked().
            ///

            constexpr index_type index{(N - size_type::magic_1()).checked().get()};
            return this->at_if(index);
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
            /// NOTE:
            /// - Since N cannot be 0, the following will never overflow
            ///   which is why it is marked as checked().
            ///

            constexpr index_type index{(N - size_type::magic_1()).checked().get()};
            return this->at_if(index);
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
            return iterator_type{this->front_if(), size_type{N}, {}};
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
            return const_iterator_type{this->front_if(), size_type{N}, {}};
        }

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
            return const_iterator_type{this->front_if(), size_type{N}, {}};
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
        end() &noexcept -> iterator_type
        {
            return iterator_type{this->front_if(), size_type{N}, index_type{N}};
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
            return const_iterator_type{this->front_if(), size_type{N}, index_type{N}};
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
        cend() const &noexcept -> const_iterator_type
        {
            return const_iterator_type{this->front_if(), size_type{N}, index_type{N}};
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

        /// <!-- description -->
        ///   @brief Returns false
        ///   @include array/example_array_empty.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns false
        ///
        [[nodiscard]] static constexpr auto
        empty() noexcept -> bool
        {
            return false;
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
            // ensures(N.is_valid_and_checked());
            return size_type{N};
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
            constexpr auto val{(size_type::max_value() / sizeof(T)).checked()};

            /// NOTE:
            /// - An error is not possible because the denominator is
            ///   always positive, so the result of max_size() is marked
            ///   as checked.
            ///

            ensures(val.is_valid_and_checked());
            return val;
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
            constexpr auto val{(size_type{N} * sizeof(T)).checked()};

            /// NOTE:
            /// - An error is not possible because the denominator is
            ///   always positive, so the result of size_bytes() is marked
            ///   as checked.
            ///

            ensures(val.is_valid_and_checked());
            return val;
        }
    };

    /// @brief deduction guideline for bsl::array
    template<typename T, typename... U>
    // NOLINTNEXTLINE(bsl-types-fixed-width-ints-arithmetic-check)
    array(T, U...) noexcept->array<T, static_cast<bsl::uintmx>(1) + sizeof...(U)>;

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
    operator==(bsl::array<T, N> const &lhs, bsl::array<T, N> const &rhs) noexcept -> bool
    {
        for (safe_idx mut_i{}; mut_i < lhs.size(); ++mut_i) {
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
    template<typename T1, typename T2, bsl::uintmx N>
    [[maybe_unused]] constexpr auto
    operator<<(out<T1> const o, bsl::array<T2, N> const &val) noexcept -> out<T1>
    {
        if (is_constant_evaluated()) {
            return o;
        }

        if constexpr (o.empty()) {
            return o;
        }

        if constexpr (N == safe_umx::magic_1()) {
            o << "[" << *val.front_if();
        }
        else {
            for (safe_idx mut_i{}; mut_i < val.size(); ++mut_i) {
                if (mut_i.is_zero()) {
                    o << "[" << *val.at_if(mut_i);
                }
                else {
                    o << ", " << *val.at_if(mut_i);
                }
            }
        }

        return o << ']';
    }
}

#endif
