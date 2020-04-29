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

#include "contiguous_iterator.hpp"
#include "convert.hpp"
#include "cstdint.hpp"
#include "debug.hpp"
#include "reverse_iterator.hpp"
#include "safe_integral.hpp"

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
    class array final
    {
        static_assert(N != 0, "arrays of size 0 are not supported");

    public:
        /// @brief stores the array being wrapped
        T m_data[N];    // NOLINT

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
        ///   SUPPRESSION: PRQA 4024 - false positive
        ///   - We suppress this because A9-3-1 states that we should
        ///     not provide a non-const reference or pointer to private
        ///     member function, unless the class mimics a smart pointer or
        ///     a containter. This class mimics a container.
        ///
        /// <!-- inputs/outputs -->
        ///   @param index the index of the instance to return
        ///   @return Returns a pointer to the instance of T stored at index
        ///     "index". If the index is out of bounds, or the array is invalid,
        ///     this function returns a nullptr.
        ///
        [[nodiscard]] constexpr pointer_type
        at_if(size_type const &index) noexcept
        {
            if ((!index) || (index >= to_umax(N))) {
                bsl::error() << "array: index out of range: " << index << '\n';
                return nullptr;
            }

            return &m_data[index.get()];    // PRQA S 4024 // NOLINT
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
        [[nodiscard]] constexpr const_pointer_type
        at_if(size_type const &index) const noexcept
        {
            if ((!index) || (index >= to_umax(N))) {
                bsl::error() << "array: index out of range: " << index << '\n';
                return nullptr;
            }

            return &m_data[index.get()];    // NOLINT
        }

        /// <!-- description -->
        ///   @brief Returns a reference to the first element in the array.
        ///   @include array/example_array_front.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a reference to the first element in the array.
        ///
        [[nodiscard]] constexpr reference_type
        front() noexcept
        {
            return *this->at_if(to_umax(0));
        }

        /// <!-- description -->
        ///   @brief Returns a reference to the first element in the array.
        ///   @include array/example_array_front.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a reference to the first element in the array.
        ///
        [[nodiscard]] constexpr const_reference_type
        front() const noexcept
        {
            return *this->at_if(to_umax(0));
        }

        /// <!-- description -->
        ///   @brief Returns a pointer to the first element in the array.
        ///   @include array/example_array_front_if.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a pointer to the first element in the array.
        ///
        [[nodiscard]] constexpr pointer_type
        front_if() noexcept
        {
            return this->at_if(to_umax(0));
        }

        /// <!-- description -->
        ///   @brief Returns a pointer to the first element in the array.
        ///   @include array/example_array_front_if.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a pointer to the first element in the array.
        ///
        [[nodiscard]] constexpr const_pointer_type
        front_if() const noexcept
        {
            return this->at_if(to_umax(0));
        }

        /// <!-- description -->
        ///   @brief Returns a reference to the last element in the array.
        ///   @include array/example_array_back.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a reference to the last element in the array.
        ///
        [[nodiscard]] constexpr reference_type
        back() noexcept
        {
            return *this->at_if(to_umax(N) - to_umax(1));
        }

        /// <!-- description -->
        ///   @brief Returns a reference to the last element in the array.
        ///   @include array/example_array_back.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a reference to the last element in the array.
        ///
        [[nodiscard]] constexpr const_reference_type
        back() const noexcept
        {
            return *this->at_if(to_umax(N) - to_umax(1));
        }

        /// <!-- description -->
        ///   @brief Returns a pointer to the last element in the array.
        ///   @include array/example_array_back_if.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a pointer to the last element in the array.
        ///
        [[nodiscard]] constexpr pointer_type
        back_if() noexcept
        {
            return this->at_if(to_umax(N) - to_umax(1));
        }

        /// <!-- description -->
        ///   @brief Returns a pointer to the last element in the array.
        ///   @include array/example_array_back_if.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a pointer to the last element in the array.
        ///
        [[nodiscard]] constexpr const_pointer_type
        back_if() const noexcept
        {
            return this->at_if(to_umax(N) - to_umax(1));
        }

        /// <!-- description -->
        ///   @brief Returns a pointer to the array being encapsulated.
        ///   @include array/example_array_data.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a pointer to the array being encapsulated.
        ///
        [[nodiscard]] constexpr pointer_type
        data() noexcept
        {
            return m_data;    // NOLINT
        }

        /// <!-- description -->
        ///   @brief Returns a pointer to the array being encapsulated.
        ///   @include array/example_array_data.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a pointer to the array being encapsulated.
        ///
        [[nodiscard]] constexpr const_pointer_type
        data() const noexcept
        {
            return m_data;    // NOLINT
        }

        /// <!-- description -->
        ///   @brief Returns an iterator to the first element of the array.
        ///   @include array/example_array_begin.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns an iterator to the first element of the array.
        ///
        [[nodiscard]] constexpr iterator_type
        begin() noexcept
        {
            return iterator_type{this->front_if(), to_umax(N), to_umax(0)};
        }

        /// <!-- description -->
        ///   @brief Returns an iterator to the first element of the array.
        ///   @include array/example_array_begin.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns an iterator to the first element of the array.
        ///
        [[nodiscard]] constexpr const_iterator_type
        begin() const noexcept
        {
            return const_iterator_type{this->front_if(), to_umax(N), to_umax(0)};
        }

        /// <!-- description -->
        ///   @brief Returns an iterator to the first element of the array.
        ///   @include array/example_array_begin.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns an iterator to the first element of the array.
        ///
        [[nodiscard]] constexpr const_iterator_type
        cbegin() const noexcept
        {
            return const_iterator_type{this->front_if(), to_umax(N), to_umax(0)};
        }

        /// <!-- description -->
        ///   @brief Returns an iterator to the element "i" in the array.
        ///   @include array/example_array_iter.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param i the element in the array to return an iterator for.
        ///   @return Returns an iterator to the element "i" in the array.
        ///
        [[nodiscard]] constexpr iterator_type
        iter(size_type const &i) noexcept
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
        [[nodiscard]] constexpr const_iterator_type
        iter(size_type const &i) const noexcept
        {
            return const_iterator_type{this->front_if(), to_umax(N), i};
        }

        /// <!-- description -->
        ///   @brief Returns an iterator to the element "i" in the array.
        ///   @include array/example_array_iter.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param i the element in the array to return an iterator for.
        ///   @return Returns an iterator to the element "i" in the array.
        ///
        [[nodiscard]] constexpr const_iterator_type
        citer(size_type const &i) const noexcept
        {
            return const_iterator_type{this->front_if(), to_umax(N), i};
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
        [[nodiscard]] constexpr iterator_type
        end() noexcept
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
        [[nodiscard]] constexpr const_iterator_type
        end() const noexcept
        {
            return const_iterator_type{this->front_if(), to_umax(N), to_umax(N)};
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
        [[nodiscard]] constexpr const_iterator_type
        cend() const noexcept
        {
            return const_iterator_type{this->front_if(), to_umax(N), to_umax(N)};
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
        [[nodiscard]] constexpr reverse_iterator_type
        rbegin() noexcept
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
        [[nodiscard]] constexpr const_reverse_iterator_type
        rbegin() const noexcept
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
        [[nodiscard]] constexpr const_reverse_iterator_type
        crbegin() const noexcept
        {
            return const_reverse_iterator_type{this->cend()};
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
        [[nodiscard]] constexpr reverse_iterator_type
        riter(size_type const &i) noexcept
        {
            if ((!!i) && (i >= to_umax(N))) {
                return reverse_iterator_type{this->iter(to_umax(N))};
            }

            return reverse_iterator_type{this->iter(i + to_umax(1))};
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
        [[nodiscard]] constexpr const_reverse_iterator_type
        riter(size_type const &i) const noexcept
        {
            if ((!!i) && (i >= to_umax(N))) {
                return const_reverse_iterator_type{this->iter(to_umax(N))};
            }

            return const_reverse_iterator_type{this->iter(i + to_umax(1))};
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
        [[nodiscard]] constexpr const_reverse_iterator_type
        criter(size_type const &i) const noexcept
        {
            if ((!!i) && (i >= to_umax(N))) {
                return const_reverse_iterator_type{this->citer(to_umax(N))};
            }

            return const_reverse_iterator_type{this->citer(i + to_umax(1))};
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
        [[nodiscard]] constexpr reverse_iterator_type
        rend() noexcept
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
        [[nodiscard]] constexpr const_reverse_iterator_type
        rend() const noexcept
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
        [[nodiscard]] constexpr const_reverse_iterator_type
        crend() const noexcept
        {
            return const_reverse_iterator_type{this->cbegin()};
        }

        /// <!-- description -->
        ///   @brief Since arrays of size 0 are not allowed, always returns
        ///     false.
        ///   @include array/example_array_empty.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Since arrays of size 0 are not allowed, always returns
        ///     false.
        ///
        [[nodiscard]] static constexpr bool
        empty() noexcept
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
        [[nodiscard]] static constexpr size_type
        size() noexcept
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
        [[nodiscard]] static constexpr size_type
        max_size() noexcept
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
        [[nodiscard]] static constexpr size_type
        size_bytes() noexcept
        {
            return to_umax(N) * to_umax(sizeof(T));
        }
    };

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
    constexpr bool
    operator==(bsl::array<T, N> const &lhs, bsl::array<T, N> const &rhs) noexcept
    {
        for (safe_uintmax i{}; i < lhs.size(); ++i) {
            if (*lhs.at_if(i) != *rhs.at_if(i)) {
                return false;
            }
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
    constexpr bool
    operator!=(bsl::array<T, N> const &lhs, bsl::array<T, N> const &rhs) noexcept
    {
        return !(lhs == rhs);
    }

    /// @brief deduction guideline for bsl::array
    template<typename T, typename... U>
    array(T, U...) -> array<T, 1 + sizeof...(U)>;

    /// <!-- description -->
    ///   @brief Outputs the provided bsl::array to the provided
    ///     output type.
    ///   @related bsl::array
    ///   @include array/example_array_ostream.hpp
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T1 the type of outputter provided
    ///   @tparam T2 the type of element being encapsulated.
    ///   @param o the instance of the outputter used to output the value.
    ///   @param val the array to output
    ///   @return return o
    ///
    template<typename T1, typename T2, bsl::uintmax N>
    [[maybe_unused]] constexpr out<T1>
    operator<<(out<T1> const o, bsl::array<T2, N> const &val) noexcept
    {
        if constexpr (!o) {
            return o;
        }

        for (safe_uintmax i{}; i < val.size(); ++i) {
            o << (i.is_zero() ? "[" : ", ") << *val.at_if(i);
        }

        return o << ']';
    }
}

#endif
