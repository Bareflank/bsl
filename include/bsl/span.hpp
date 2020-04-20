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
/// @file span.hpp
///

#ifndef BSL_SPAN_HPP
#define BSL_SPAN_HPP

#include "contiguous_iterator.hpp"
#include "convert.hpp"
#include "debug.hpp"
#include "npos.hpp"
#include "reverse_iterator.hpp"
#include "safe_integral.hpp"

namespace bsl
{
    /// @class bsl::span
    ///
    /// <!-- description -->
    ///   @brief A bsl::span is a non-owning view of an array type. Unlike
    ///     a bsl::array, the bsl::span does not own the memory it accesses
    ///     and therefore cannot outlive whatever array you give it. The
    ///     bsl::span is also very similar to a gsl::span and a std::span
    ///     with some key differences.
    ///     - We do not provide the conversion constructors for array types as
    ///       they are not compliant with AUTOSAR. If you need an array, use
    ///       a bsl::array.
    ///     - We do not provide any of the accessor functions as defined by
    ///       the standard library. Instead we provide _if() versions which
    ///       return a pointer to the element being requested. If the element
    ///       does not exist, a nullptr is returned, providing a means to
    ///       check for logic errors without the need for exceptions or
    ///       failing fast which is not compliant with AUTOSAR.
    ///     - We provide the iter() function which is similar to begin() and
    ///       end(), but allowing you to get an iterator from any position in
    ///       the view.
    ///     - As noted in the documentation for the contiguous_iterator,
    ///       iterators are not allowed to go beyond their bounds which the
    ///       Standard Library does not ensure. It is still possible for an
    ///       iterator to be invalid as you cannot dereference end() (fixing
    ///       this would break compatiblity with existing APIs when AUTOSAR
    ///       compliance is disabled), but you can be rest assured that an
    ///       iterator's index is always within bounds or == end(). Note
    ///       that for invalid views, begin() and friends always return an
    ///       interator to end().
    ///     - We do not provide any of the as_byte helper functions as they
    ///       would all require a reinterpret_cast which is not allowed
    ///       by AUTOSAR.
    ///     - A bsl::span is always a dynamic_extent type. The reason the
    ///       dynamic_extent type exists in a std::span is to optimize away
    ///       the need to store the size of the array the span is viewing.
    ///       This is only useful for C-style arrays which are not supported
    ///       as they are not compliant with AUTOSAR. If you need a C-style
    ///       array, use a bsl::array, in which case you have no need for a
    ///       bsl::span. Instead, a bsl::span is useful when you have an
    ///       array in memory that is not in your control (for example, a
    ///       device's memory).
    ///   @include example_span_overview.hpp
    ///
    /// <!-- template parameters -->
    ///   @tparam T the type of element being viewed.
    ///
    template<typename T>
    class span final    // NOLINT
    {
    public:
        /// @brief alias for: T
        using value_type = T;
        /// @brief alias for: safe_uintmax
        using size_type = safe_uintmax;
        /// @brief alias for: safe_uintmax
        using difference_type = safe_uintmax;
        /// @brief alias for: T &
        using reference_type = T &;
        /// @brief alias for: T &
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
        ///   @brief Default constructor that creates a span with
        ///     data() == nullptr and size() == 0. All accessors
        ///     will return a nullptr if used. Note that like other view types
        ///     in the BSL, the bsl::span is a POD type. This
        ///     means that when declaring a global, default constructed
        ///     bsl::span, DO NOT include the {} for
        ///     initialization. Instead, remove the {} and the global
        ///     bsl::span will be included in the BSS section of
        ///     the executable, and initialized to 0 for you. All other
        ///     instantiations of a bsl::span (or any POD
        ///     type), should be initialized using {} to ensure the POD is
        ///     properly initialized. Using the above method for global
        ///     initialization ensures that global constructors are not
        ///     executed at runtime, which is required by AUTOSAR.
        ///   @include span/example_span_default_constructor.hpp
        ///
        constexpr span() noexcept = default;

        /// <!-- description -->
        ///   @brief Creates a span given a pointer to an array, and the
        ///     number of elements in the array. Note that the array must be
        ///     contiguous in memory and [ptr, ptr + count) must be a valid
        ///     range.
        ///   @include span/example_span_ptr_count_constructor.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param ptr a pointer to the array being spaned.
        ///   @param count the number of elements in the array being spaned.
        ///
        constexpr span(pointer_type const ptr, size_type const count) noexcept    // --
            : m_ptr{ptr}, m_count{count}
        {
            if ((nullptr == m_ptr) || m_count.is_zero()) {
                *this = span{};
            }
        }

        /// <!-- description -->
        ///   @brief Returns a pointer to the instance of T stored at index
        ///     "index". If the index is out of bounds, or the view is invalid,
        ///     this function returns a nullptr.
        ///   @include span/example_span_at_if.hpp
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
        ///     "index". If the index is out of bounds, or the view is invalid,
        ///     this function returns a nullptr.
        ///
        [[nodiscard]] constexpr pointer_type
        at_if(size_type const index) noexcept
        {
            if ((nullptr == m_ptr) || (index >= m_count)) {
                bsl::error() << "span: index out of range: " << index << '\n';
                return nullptr;
            }

            return &m_ptr[index.get()];    // PRQA S 4024 // NOLINT
        }

        /// <!-- description -->
        ///   @brief Returns a pointer to the instance of T stored at index
        ///     "index". If the index is out of bounds, or the view is invalid,
        ///     this function returns a nullptr.
        ///   @include span/example_span_at_if.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param index the index of the instance to return
        ///   @return Returns a pointer to the instance of T stored at index
        ///     "index". If the index is out of bounds, or the view is invalid,
        ///     this function returns a nullptr.
        ///
        [[nodiscard]] constexpr const_pointer_type
        at_if(size_type const index) const noexcept
        {
            if ((nullptr == m_ptr) || (index >= m_count)) {
                bsl::error() << "span: index out of range: " << index << '\n';
                return nullptr;
            }

            return &m_ptr[index.get()];    // NOLINT
        }

        /// <!-- description -->
        ///   @brief Returns a pointer to the instance of T stored at index
        ///     "0". If the index is out of bounds, or the view is invalid,
        ///     this function returns a nullptr.
        ///   @include span/example_span_front_if.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a pointer to the instance of T stored at index
        ///     "0". If the index is out of bounds, or the view is invalid,
        ///     this function returns a nullptr.
        ///
        [[nodiscard]] constexpr pointer_type
        front_if() noexcept
        {
            return this->at_if(to_umax(0));
        }

        /// <!-- description -->
        ///   @brief Returns a pointer to the instance of T stored at index
        ///     "0". If the index is out of bounds, or the view is invalid,
        ///     this function returns a nullptr.
        ///   @include span/example_span_front_if.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a pointer to the instance of T stored at index
        ///     "0". If the index is out of bounds, or the view is invalid,
        ///     this function returns a nullptr.
        ///
        [[nodiscard]] constexpr const_pointer_type
        front_if() const noexcept
        {
            return this->at_if(to_umax(0));
        }

        /// <!-- description -->
        ///   @brief Returns a pointer to the instance of T stored at index
        ///     "size() - 1". If the index is out of bounds, or the view is
        ///     invalid, this function returns a nullptr.
        ///   @include span/example_span_back_if.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a pointer to the instance of T stored at index
        ///     "size() - 1". If the index is out of bounds, or the view is
        ///     invalid, this function returns a nullptr.
        ///
        [[nodiscard]] constexpr pointer_type
        back_if() noexcept
        {
            return this->at_if(m_count.is_pos() ? (m_count - to_umax(1)) : to_umax(0));
        }

        /// <!-- description -->
        ///   @brief Returns a pointer to the instance of T stored at index
        ///     "size() - 1". If the index is out of bounds, or the view is
        ///     invalid, this function returns a nullptr.
        ///   @include span/example_span_back_if.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a pointer to the instance of T stored at index
        ///     "size() - 1". If the index is out of bounds, or the view is
        ///     invalid, this function returns a nullptr.
        ///
        [[nodiscard]] constexpr const_pointer_type
        back_if() const noexcept
        {
            return this->at_if(m_count.is_pos() ? (m_count - to_umax(1)) : to_umax(0));
        }

        /// <!-- description -->
        ///   @brief Returns a pointer to the array being viewed. If this is
        ///     a default constructed view, or the view was constructed in
        ///     error, this will return a nullptr.
        ///   @include span/example_span_data.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a pointer to the array being viewed. If this is
        ///     a default constructed view, or the view was constructed in
        ///     error, this will return a nullptr.
        ///
        [[nodiscard]] constexpr pointer_type
        data() noexcept
        {
            return m_ptr;
        }

        /// <!-- description -->
        ///   @brief Returns a pointer to the array being viewed. If this is
        ///     a default constructed view, or the view was constructed in
        ///     error, this will return a nullptr.
        ///   @include span/example_span_data.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a pointer to the array being viewed. If this is
        ///     a default constructed view, or the view was constructed in
        ///     error, this will return a nullptr.
        ///
        [[nodiscard]] constexpr const_pointer_type
        data() const noexcept
        {
            return m_ptr;
        }

        /// <!-- description -->
        ///   @brief Returns an iterator to the first element of the view.
        ///   @include span/example_span_begin.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns an iterator to the first element of the view.
        ///
        [[nodiscard]] constexpr iterator_type
        begin() noexcept
        {
            return iterator_type{m_ptr, m_count, to_umax(0)};
        }

        /// <!-- description -->
        ///   @brief Returns an iterator to the first element of the view.
        ///   @include span/example_span_begin.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns an iterator to the first element of the view.
        ///
        [[nodiscard]] constexpr const_iterator_type
        begin() const noexcept
        {
            return const_iterator_type{m_ptr, m_count, to_umax(0)};
        }

        /// <!-- description -->
        ///   @brief Returns an iterator to the first element of the view.
        ///   @include span/example_span_begin.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns an iterator to the first element of the view.
        ///
        [[nodiscard]] constexpr const_iterator_type
        cbegin() const noexcept
        {
            return const_iterator_type{m_ptr, m_count, to_umax(0)};
        }

        /// <!-- description -->
        ///   @brief Returns an iterator to the element "i" in the view.
        ///   @include span/example_span_iter.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param i the element in the array to return an iterator for.
        ///   @return Returns an iterator to the element "i" in the view.
        ///
        [[nodiscard]] constexpr iterator_type
        iter(size_type const i) noexcept
        {
            return iterator_type{m_ptr, m_count, i};
        }

        /// <!-- description -->
        ///   @brief Returns an iterator to the element "i" in the view.
        ///   @include span/example_span_iter.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param i the element in the array to return an iterator for.
        ///   @return Returns an iterator to the element "i" in the view.
        ///
        [[nodiscard]] constexpr const_iterator_type
        iter(size_type const i) const noexcept
        {
            return const_iterator_type{m_ptr, m_count, i};
        }

        /// <!-- description -->
        ///   @brief Returns an iterator to the element "i" in the view.
        ///   @include span/example_span_iter.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param i the element in the array to return an iterator for.
        ///   @return Returns an iterator to the element "i" in the view.
        ///
        [[nodiscard]] constexpr const_iterator_type
        citer(size_type const i) const noexcept
        {
            return const_iterator_type{m_ptr, m_count, i};
        }

        /// <!-- description -->
        ///   @brief Returns an iterator to one past the last element of the
        ///     view. If you attempt to access this iterator, a nullptr will
        ///     always be returned.
        ///   @include span/example_span_end.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns an iterator to one past the last element of the
        ///     view. If you attempt to access this iterator, a nullptr will
        ///     always be returned.
        ///
        [[nodiscard]] constexpr iterator_type
        end() noexcept
        {
            return iterator_type{m_ptr, m_count, m_count};
        }

        /// <!-- description -->
        ///   @brief Returns an iterator to one past the last element of the
        ///     view. If you attempt to access this iterator, a nullptr will
        ///     always be returned.
        ///   @include span/example_span_end.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns an iterator to one past the last element of the
        ///     view. If you attempt to access this iterator, a nullptr will
        ///     always be returned.
        ///
        [[nodiscard]] constexpr const_iterator_type
        end() const noexcept
        {
            return const_iterator_type{m_ptr, m_count, m_count};
        }

        /// <!-- description -->
        ///   @brief Returns an iterator to one past the last element of the
        ///     view. If you attempt to access this iterator, a nullptr will
        ///     always be returned.
        ///   @include span/example_span_end.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns an iterator to one past the last element of the
        ///     view. If you attempt to access this iterator, a nullptr will
        ///     always be returned.
        ///
        [[nodiscard]] constexpr const_iterator_type
        cend() const noexcept
        {
            return const_iterator_type{m_ptr, m_count, m_count};
        }

        /// <!-- description -->
        ///   @brief Returns a reverse iterator to one past the last element
        ///     of the view. When accessing the iterator, the iterator will
        ///     always return the element T[internal index - 1], providing
        ///     access to the range [size() - 1, 0) while internally storing the
        ///     range [size(), 1) with element 0 representing the end(). For more
        ///     information, see the bsl::reverse_iterator documentation.
        ///   @include span/example_span_rbegin.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a reverse iterator to the last element of the
        ///     view.
        ///
        [[nodiscard]] constexpr reverse_iterator_type
        rbegin() noexcept
        {
            return reverse_iterator_type{this->end()};
        }

        /// <!-- description -->
        ///   @brief Returns a reverse iterator to one past the last element
        ///     of the view. When accessing the iterator, the iterator will
        ///     always return the element T[internal index - 1], providing
        ///     access to the range [size() - 1, 0) while internally storing the
        ///     range [size(), 1) with element 0 representing the end(). For more
        ///     information, see the bsl::reverse_iterator documentation.
        ///   @include span/example_span_rbegin.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a reverse iterator to the last element of the
        ///     view.
        ///
        [[nodiscard]] constexpr const_reverse_iterator_type
        rbegin() const noexcept
        {
            return const_reverse_iterator_type{this->end()};
        }

        /// <!-- description -->
        ///   @brief Returns a reverse iterator to one past the last element
        ///     of the view. When accessing the iterator, the iterator will
        ///     always return the element T[internal index - 1], providing
        ///     access to the range [size() - 1, 0) while internally storing the
        ///     range [size(), 1) with element 0 representing the end(). For more
        ///     information, see the bsl::reverse_iterator documentation.
        ///   @include span/example_span_rbegin.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a reverse iterator to the last element of the
        ///     view.
        ///
        [[nodiscard]] constexpr const_reverse_iterator_type
        crbegin() const noexcept
        {
            return const_reverse_iterator_type{this->cend()};
        }

        /// <!-- description -->
        ///   @brief Returns a reverse iterator element "i" in the
        ///     view. When accessing the iterator, the iterator will
        ///     always return the element T[internal index - 1], providing
        ///     access to the range [size() - 1, 0) while internally storing the
        ///     range [size(), 1) with element 0 representing the end(). For more
        ///     information, see the bsl::reverse_iterator documentation.
        ///   @include span/example_span_riter.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param i the element in the array to return an iterator for.
        ///   @return Returns a reverse iterator element "i" in the
        ///     view.
        ///
        [[nodiscard]] constexpr reverse_iterator_type
        riter(size_type const i) noexcept
        {
            if (i >= m_count) {
                return reverse_iterator_type{this->iter(m_count)};
            }

            return reverse_iterator_type{this->iter(i + to_umax(1))};
        }

        /// <!-- description -->
        ///   @brief Returns a reverse iterator element "i" in the
        ///     view. When accessing the iterator, the iterator will
        ///     always return the element T[internal index - 1], providing
        ///     access to the range [size() - 1, 0) while internally storing the
        ///     range [size(), 1) with element 0 representing the end(). For more
        ///     information, see the bsl::reverse_iterator documentation.
        ///   @include span/example_span_riter.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param i the element in the array to return an iterator for.
        ///   @return Returns a reverse iterator element "i" in the
        ///     view.
        ///
        [[nodiscard]] constexpr const_reverse_iterator_type
        riter(size_type const i) const noexcept
        {
            if (i >= m_count) {
                return const_reverse_iterator_type{this->iter(m_count)};
            }

            return const_reverse_iterator_type{this->iter(i + to_umax(1))};
        }

        /// <!-- description -->
        ///   @brief Returns a reverse iterator element "i" in the
        ///     view. When accessing the iterator, the iterator will
        ///     always return the element T[internal index - 1], providing
        ///     access to the range [size() - 1, 0) while internally storing the
        ///     range [size(), 1) with element 0 representing the end(). For more
        ///     information, see the bsl::reverse_iterator documentation.
        ///   @include span/example_span_riter.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param i the element in the array to return an iterator for.
        ///   @return Returns a reverse iterator element "i" in the
        ///     view.
        ///
        [[nodiscard]] constexpr const_reverse_iterator_type
        criter(size_type const i) const noexcept
        {
            if (i >= m_count) {
                return const_reverse_iterator_type{this->citer(m_count)};
            }

            return const_reverse_iterator_type{this->citer(i + to_umax(1))};
        }

        /// <!-- description -->
        ///   @brief Returns a reverse iterator first element of the
        ///     view. When accessing the iterator, the iterator will
        ///     always return the element T[internal index - 1], providing
        ///     access to the range [size() - 1, 0) while internally storing the
        ///     range [size(), 1) with element 0 representing the end(). For more
        ///     information, see the bsl::reverse_iterator documentation.
        ///   @include span/example_span_rend.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a reverse iterator first element of the
        ///     view.
        ///
        [[nodiscard]] constexpr reverse_iterator_type
        rend() noexcept
        {
            return reverse_iterator_type{this->begin()};
        }

        /// <!-- description -->
        ///   @brief Returns a reverse iterator first element of the
        ///     view. When accessing the iterator, the iterator will
        ///     always return the element T[internal index - 1], providing
        ///     access to the range [size() - 1, 0) while internally storing the
        ///     range [size(), 1) with element 0 representing the end(). For more
        ///     information, see the bsl::reverse_iterator documentation.
        ///   @include span/example_span_rend.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a reverse iterator first element of the
        ///     view.
        ///
        [[nodiscard]] constexpr const_reverse_iterator_type
        rend() const noexcept
        {
            return const_reverse_iterator_type{this->begin()};
        }

        /// <!-- description -->
        ///   @brief Returns a reverse iterator first element of the
        ///     view. When accessing the iterator, the iterator will
        ///     always return the element T[internal index - 1], providing
        ///     access to the range [size() - 1, 0) while internally storing the
        ///     range [size(), 1) with element 0 representing the end(). For more
        ///     information, see the bsl::reverse_iterator documentation.
        ///   @include span/example_span_rend.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a reverse iterator first element of the
        ///     view.
        ///
        [[nodiscard]] constexpr const_reverse_iterator_type
        crend() const noexcept
        {
            return const_reverse_iterator_type{this->cbegin()};
        }

        /// <!-- description -->
        ///   @brief Returns size() == 0
        ///   @include span/example_span_empty.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns size() == 0
        ///
        [[nodiscard]] constexpr bool
        empty() const noexcept
        {
            return m_count.is_zero();
        }

        /// <!-- description -->
        ///   @brief Returns the number of elements in the array being
        ///     viewed. If this is a default constructed view, or the view
        ///     was constructed in error, this will return 0.
        ///   @include span/example_span_size.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the number of elements in the array being
        ///     viewed. If this is a default constructed view, or the view
        ///     was constructed in error, this will return 0.
        ///
        [[nodiscard]] constexpr size_type
        size() const noexcept
        {
            return m_count;
        }

        /// <!-- description -->
        ///   @brief Returns the max number of elements the BSL supports.
        ///   @include span/example_span_max_size.hpp
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
        ///   @include span/example_span_size_bytes.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns size() * sizeof(T)
        ///
        [[nodiscard]] constexpr size_type
        size_bytes() const noexcept
        {
            return m_count * to_umax(sizeof(T));
        }

        /// <!-- description -->
        ///   @brief Returns subspan(0, count). If count is 0, an invalid
        ///     span is returned.
        ///   @include span/example_span_first.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param count the number of elements of the new subspan
        ///   @return Returns subspan(0, count). If count is 0, an invalid
        ///     span is returned.
        ///
        [[nodiscard]] constexpr span<T>
        first(size_type const count = npos) const noexcept
        {
            return this->subspan(to_umax(0), count);
        }

        /// <!-- description -->
        ///   @brief Returns subspan(this->size() - count, count). If count
        ///     is greater than the size of the current span, a copy of the
        ///     current span is returned. If the count is 0, an invalid span
        ///     is returned.
        ///   @include span/example_span_last.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param count the number of elements of the new subspan
        ///   @return Returns subspan(this->size() - count, count). If count
        ///     is greater than the size of the current span, a copy of the
        ///     current span is returned. If the count is 0, an invalid span
        ///     is returned.
        ///
        [[nodiscard]] constexpr span<T>
        last(size_type count = npos) const noexcept
        {
            if (count > this->size()) {
                count = this->size();
            }

            return this->subspan(this->size() - count, count);
        }

        /// <!-- description -->
        ///   @brief Returns span{at_if(pos), count.min(size() - pos)}. If
        ///     the provided "pos" is greater than or equal to the size of
        ///     the current span, an invalid span is returned.
        ///   @include span/example_span_subspan.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param pos the starting position of the new span
        ///   @param count the number of elements of the new subspan
        ///   @return Returns span{at_if(pos), count.min(size() - pos)}. If
        ///     the provided "pos" is greater than or equal to the size of
        ///     the current span, an invalid span is returned.
        ///
        [[nodiscard]] constexpr span<T>
        subspan(size_type const pos, size_type const count = npos) const noexcept
        {
            if ((nullptr == m_ptr) || (pos >= m_count)) {
                return {};
            }

            return span<T>{&m_ptr[pos.get()], count.min(m_count - pos)};    // NOLINT
        }

    private:
        /// @brief stores a pointer to the array being viewed
        pointer_type m_ptr;
        /// @brief stores the number of elements in the array being viewed
        size_type m_count;
    };

    /// <!-- description -->
    ///   @brief Returns true if two spans have the same size and contain
    ///     the same contents. Returns false otherwise.
    ///   @include span/example_span_equals.hpp
    ///   @related bsl::span
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of elements in the span
    ///   @param lhs the left hand side of the operation
    ///   @param rhs the right hand side of the operation
    ///   @return Returns true if two spans have the same size and contain
    ///     the same contents. Returns false otherwise.
    ///
    template<typename T>
    constexpr bool
    operator==(span<T> const &lhs, span<T> const &rhs) noexcept
    {
        if (lhs.size() != rhs.size()) {
            return false;
        }

        for (safe_uintmax i{}; i < lhs.size(); ++i) {
            if (*lhs.at_if(i) != *rhs.at_if(i)) {
                return false;
            }
        }

        return true;
    }

    /// <!-- description -->
    ///   @brief Returns false if two spans have the same size and contain
    ///     the same contents. Returns true otherwise.
    ///   @include span/example_span_not_equals.hpp
    ///   @related bsl::span
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of elements in the span
    ///   @param lhs the left hand side of the operation
    ///   @param rhs the right hand side of the operation
    ///   @return Returns true if two spans have the same size and contain
    ///     the same contents. Returns false otherwise.
    ///
    template<typename T>
    constexpr bool
    operator!=(span<T> const &lhs, span<T> const &rhs) noexcept
    {
        return !(lhs == rhs);
    }

    /// <!-- description -->
    ///   @brief Outputs the provided bsl::span to the provided
    ///     output type.
    ///   @related bsl::span
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T1 the type of outputter provided
    ///   @tparam T2 the type of element being encapsulated.
    ///   @param o the instance of the outputter used to output the value.
    ///   @param val the span to output
    ///   @return return o
    ///
    template<typename T1, typename T2>
    [[maybe_unused]] constexpr out<T1>
    operator<<(out<T1> const o, bsl::span<T2> const &val) noexcept
    {
        if (val.empty()) {
            return o << "[]";
        }

        for (safe_uintmax i{}; i < val.size(); ++i) {
            o << (i.is_zero() ? "[" : ", ") << *val.at_if(i);
        }

        return o << ']';
    }
}

#endif
