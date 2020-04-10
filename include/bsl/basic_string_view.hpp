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
/// @file basic_string_view.hpp
///

#ifndef BSL_BASIC_STRING_VIEW_HPP
#define BSL_BASIC_STRING_VIEW_HPP

#include "char_traits.hpp"
#include "contiguous_iterator.hpp"
#include "cstdint.hpp"
#include "debug.hpp"
#include "min_of.hpp"
#include "npos.hpp"
#include "numeric_limits.hpp"
#include "reverse_iterator.hpp"

// TODO:
// - Need to implement the find functions. These need the safe_int class as
//   there is a lot of math that could result in overflow that needs to be
//   accounted for.
//

namespace bsl
{
    /// @class bsl::basic_string_view
    ///
    /// <!-- description -->
    ///   @brief A bsl::basic_string_view is a non-owning, encapsulation of a
    ///     string, providing helper functions for working with strings.
    ///   @include example_basic_string_view_overview.hpp
    ///
    /// <!-- template parameters -->
    ///   @tparam CharT the type of characters in the string
    ///   @tparam Traits the traits class used to work with the string
    ///
    template<typename CharT, typename Traits = char_traits<CharT>>
    class basic_string_view final    // NOLINT
    {
    public:
        /// @brief alias for: CharT const
        using value_type = CharT const;
        /// @brief alias for: bsl::uintmax
        using size_type = bsl::uintmax;
        /// @brief alias for: bsl::uintmax
        using difference_type = bsl::uintmax;
        /// @brief alias for: CharT const &
        using reference_type = CharT const &;
        /// @brief alias for: CharT const &
        using const_reference_type = CharT const &;
        /// @brief alias for: CharT const *
        using pointer_type = CharT const *;
        /// @brief alias for: CharT const const *
        using const_pointer_type = CharT const *;
        /// @brief alias for: contiguous_iterator<CharT const>
        using iterator_type = contiguous_iterator<CharT const>;
        /// @brief alias for: contiguous_iterator<CharT const const>
        using const_iterator_type = contiguous_iterator<CharT const>;
        /// @brief alias for: reverse_iterator<iterator>
        using reverse_iterator_type = reverse_iterator<iterator_type>;
        /// @brief alias for: reverse_iterator<const_iterator>
        using const_reverse_iterator_type = reverse_iterator<const_iterator_type>;

        /// <!-- description -->
        ///   @brief Default constructor that creates a basic_string_view with
        ///     data() == nullptr and size() == 0. All accessors
        ///     will return a nullptr if used. Note that like other view types
        ///     in the BSL, the bsl::basic_string_view is a POD type. This
        ///     means that when declaring a global, default constructed
        ///     bsl::basic_string_view, DO NOT include the {} for
        ///     initialization. Instead, remove the {} and the global
        ///     bsl::basic_string_view will be included in the BSS section of
        ///     the executable, and initialized to 0 for you. All other
        ///     instantiations of a bsl::basic_string_view (or any POD
        ///     type), should be initialized using {} to ensure the POD is
        ///     properly initialized. Using the above method for global
        ///     initialization ensures that global constructors are not
        ///     executed at runtime, which is required by AUTOSAR.
        ///   @include basic_string_view/example_basic_string_view_default_constructor.hpp
        ///
        constexpr basic_string_view() noexcept = default;

        /// <!-- description -->
        ///   @brief ptr constructor. This creates a bsl::basic_string_view
        ///     given a pointer to a string. The number of characters in the
        ///     string is determined using Traits<CharT>::length,
        ///     which scans for '\0'.
        ///   @include basic_string_view/example_basic_string_view_s_constructor.hpp
        ///
        ///   SUPPRESSION: PRQA 2180 - false positive
        ///   - We suppress this because A12-1-4 states that all constructors
        ///     that are callable from a fundamental type should be marked as
        ///     explicit. This is not a fundamental type and there for does
        ///     not apply (as pointers are not fundamental types).
        ///
        /// <!-- inputs/outputs -->
        ///   @param s a pointer to the string
        ///
        constexpr basic_string_view(pointer_type const s) noexcept    // PRQA S 2180 // NOLINT
            : m_ptr{s}, m_count{Traits::length(s)}
        {
            if ((nullptr == m_ptr) || (0U == m_count)) {
                *this = basic_string_view{};
            }
        }

        /// <!-- description -->
        ///   @brief ptr assignment. This assigns a bsl::basic_string_view
        ///     a pointer to a string. The number of characters in the
        ///     string is determined using Traits<CharT>::length,
        ///     which scans for '\0'.
        ///   @include basic_string_view/example_basic_string_view_s_assignment.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param s a pointer to the string
        ///   @return Returns *this
        ///
        constexpr basic_string_view &
        operator=(pointer_type const s) &noexcept
        {
            *this = basic_string_view{s};
            return *this;
        }

        /// <!-- description -->
        ///   @brief Returns a pointer to the instance of T stored at index
        ///     "index". If the index is out of bounds, or the view is invalid,
        ///     this function returns a nullptr.
        ///   @include basic_string_view/example_basic_string_view_at_if.hpp
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
                return nullptr;
            }

            return &m_ptr[index];    // PRQA S 4024 // NOLINT
        }

        /// <!-- description -->
        ///   @brief Returns a pointer to the instance of T stored at index
        ///     "index". If the index is out of bounds, or the view is invalid,
        ///     this function returns a nullptr.
        ///   @include basic_string_view/example_basic_string_view_at_if.hpp
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
                return nullptr;
            }

            return &m_ptr[index];    // NOLINT
        }

        /// <!-- description -->
        ///   @brief Returns a pointer to the instance of T stored at index
        ///     "0". If the index is out of bounds, or the view is invalid,
        ///     this function returns a nullptr.
        ///   @include basic_string_view/example_basic_string_view_front_if.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a pointer to the instance of T stored at index
        ///     "0". If the index is out of bounds, or the view is invalid,
        ///     this function returns a nullptr.
        ///
        [[nodiscard]] constexpr pointer_type
        front_if() noexcept
        {
            return this->at_if(0U);
        }

        /// <!-- description -->
        ///   @brief Returns a pointer to the instance of T stored at index
        ///     "0". If the index is out of bounds, or the view is invalid,
        ///     this function returns a nullptr.
        ///   @include basic_string_view/example_basic_string_view_front_if.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a pointer to the instance of T stored at index
        ///     "0". If the index is out of bounds, or the view is invalid,
        ///     this function returns a nullptr.
        ///
        [[nodiscard]] constexpr const_pointer_type
        front_if() const noexcept
        {
            return this->at_if(0U);
        }

        /// <!-- description -->
        ///   @brief Returns a pointer to the instance of T stored at index
        ///     "size() - 1". If the index is out of bounds, or the view is
        ///     invalid, this function returns a nullptr.
        ///   @include basic_string_view/example_basic_string_view_back_if.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a pointer to the instance of T stored at index
        ///     "size() - 1". If the index is out of bounds, or the view is
        ///     invalid, this function returns a nullptr.
        ///
        [[nodiscard]] constexpr pointer_type
        back_if() noexcept
        {
            return this->at_if((m_count > 0U) ? (m_count - 1U) : 0U);
        }

        /// <!-- description -->
        ///   @brief Returns a pointer to the instance of T stored at index
        ///     "size() - 1". If the index is out of bounds, or the view is
        ///     invalid, this function returns a nullptr.
        ///   @include basic_string_view/example_basic_string_view_back_if.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a pointer to the instance of T stored at index
        ///     "size() - 1". If the index is out of bounds, or the view is
        ///     invalid, this function returns a nullptr.
        ///
        [[nodiscard]] constexpr const_pointer_type
        back_if() const noexcept
        {
            return this->at_if((m_count > 0U) ? (m_count - 1U) : 0U);
        }

        /// <!-- description -->
        ///   @brief Returns a pointer to the string being viewed. If this is
        ///     a default constructed view, or the view was constructed in
        ///     error, this will return a nullptr.
        ///   @include basic_string_view/example_basic_string_view_data.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a pointer to the string being viewed. If this is
        ///     a default constructed view, or the view was constructed in
        ///     error, this will return a nullptr.
        ///
        [[nodiscard]] constexpr pointer_type
        data() noexcept
        {
            return m_ptr;
        }

        /// <!-- description -->
        ///   @brief Returns a pointer to the string being viewed. If this is
        ///     a default constructed view, or the view was constructed in
        ///     error, this will return a nullptr.
        ///   @include basic_string_view/example_basic_string_view_data.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a pointer to the string being viewed. If this is
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
        ///   @include basic_string_view/example_basic_string_view_begin.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns an iterator to the first element of the view.
        ///
        [[nodiscard]] constexpr iterator_type
        begin() noexcept
        {
            return iterator_type{m_ptr, m_count, 0U};
        }

        /// <!-- description -->
        ///   @brief Returns an iterator to the first element of the view.
        ///   @include basic_string_view/example_basic_string_view_begin.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns an iterator to the first element of the view.
        ///
        [[nodiscard]] constexpr const_iterator_type
        begin() const noexcept
        {
            return const_iterator_type{m_ptr, m_count, 0U};
        }

        /// <!-- description -->
        ///   @brief Returns an iterator to the first element of the view.
        ///   @include basic_string_view/example_basic_string_view_begin.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns an iterator to the first element of the view.
        ///
        [[nodiscard]] constexpr const_iterator_type
        cbegin() const noexcept
        {
            return const_iterator_type{m_ptr, m_count, 0U};
        }

        /// <!-- description -->
        ///   @brief Returns an iterator to the element "i" in the view.
        ///   @include basic_string_view/example_basic_string_view_iter.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param i the element in the string to return an iterator for.
        ///   @return Returns an iterator to the element "i" in the view.
        ///
        [[nodiscard]] constexpr iterator_type
        iter(size_type const i) noexcept
        {
            return iterator_type{m_ptr, m_count, i};
        }

        /// <!-- description -->
        ///   @brief Returns an iterator to the element "i" in the view.
        ///   @include basic_string_view/example_basic_string_view_iter.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param i the element in the string to return an iterator for.
        ///   @return Returns an iterator to the element "i" in the view.
        ///
        [[nodiscard]] constexpr const_iterator_type
        iter(size_type const i) const noexcept
        {
            return const_iterator_type{m_ptr, m_count, i};
        }

        /// <!-- description -->
        ///   @brief Returns an iterator to the element "i" in the view.
        ///   @include basic_string_view/example_basic_string_view_iter.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param i the element in the string to return an iterator for.
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
        ///   @include basic_string_view/example_basic_string_view_end.hpp
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
        ///   @include basic_string_view/example_basic_string_view_end.hpp
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
        ///   @include basic_string_view/example_basic_string_view_end.hpp
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
        ///   @include basic_string_view/example_basic_string_view_rbegin.hpp
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
        ///   @include basic_string_view/example_basic_string_view_rbegin.hpp
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
        ///   @include basic_string_view/example_basic_string_view_rbegin.hpp
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
        ///   @include basic_string_view/example_basic_string_view_riter.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param i the element in the string to return an iterator for.
        ///   @return Returns a reverse iterator element "i" in the
        ///     view.
        ///
        [[nodiscard]] constexpr reverse_iterator_type
        riter(size_type const i) noexcept
        {
            size_type const ai{(i >= m_count) ? m_count : (i + 1U)};
            return reverse_iterator_type{this->iter(ai)};
        }

        /// <!-- description -->
        ///   @brief Returns a reverse iterator element "i" in the
        ///     view. When accessing the iterator, the iterator will
        ///     always return the element T[internal index - 1], providing
        ///     access to the range [size() - 1, 0) while internally storing the
        ///     range [size(), 1) with element 0 representing the end(). For more
        ///     information, see the bsl::reverse_iterator documentation.
        ///   @include basic_string_view/example_basic_string_view_riter.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param i the element in the string to return an iterator for.
        ///   @return Returns a reverse iterator element "i" in the
        ///     view.
        ///
        [[nodiscard]] constexpr const_reverse_iterator_type
        riter(size_type const i) const noexcept
        {
            size_type const ai{(i >= m_count) ? m_count : (i + 1U)};
            return const_reverse_iterator_type{this->iter(ai)};
        }

        /// <!-- description -->
        ///   @brief Returns a reverse iterator element "i" in the
        ///     view. When accessing the iterator, the iterator will
        ///     always return the element T[internal index - 1], providing
        ///     access to the range [size() - 1, 0) while internally storing the
        ///     range [size(), 1) with element 0 representing the end(). For more
        ///     information, see the bsl::reverse_iterator documentation.
        ///   @include basic_string_view/example_basic_string_view_riter.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param i the element in the string to return an iterator for.
        ///   @return Returns a reverse iterator element "i" in the
        ///     view.
        ///
        [[nodiscard]] constexpr const_reverse_iterator_type
        criter(size_type const i) const noexcept
        {
            size_type const ai{(i >= m_count) ? m_count : (i + 1U)};
            return const_reverse_iterator_type{this->citer(ai)};
        }

        /// <!-- description -->
        ///   @brief Returns a reverse iterator first element of the
        ///     view. When accessing the iterator, the iterator will
        ///     always return the element T[internal index - 1], providing
        ///     access to the range [size() - 1, 0) while internally storing the
        ///     range [size(), 1) with element 0 representing the end(). For more
        ///     information, see the bsl::reverse_iterator documentation.
        ///   @include basic_string_view/example_basic_string_view_rend.hpp
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
        ///   @include basic_string_view/example_basic_string_view_rend.hpp
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
        ///   @include basic_string_view/example_basic_string_view_rend.hpp
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
        ///   @include basic_string_view/example_basic_string_view_empty.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns size() == 0
        ///
        [[nodiscard]] constexpr bool
        empty() const noexcept
        {
            return 0U == m_count;
        }

        /// <!-- description -->
        ///   @brief Returns the number of elements in the string being
        ///     viewed. If this is a default constructed view, or the view
        ///     was constructed in error, this will return 0.
        ///   @include basic_string_view/example_basic_string_view_size.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the number of elements in the string being
        ///     viewed. If this is a default constructed view, or the view
        ///     was constructed in error, this will return 0.
        ///
        [[nodiscard]] constexpr size_type
        size() const noexcept
        {
            return m_count;
        }

        /// <!-- description -->
        ///   @brief Returns the length of the string being viewed. This is
        ///     the same as bsl::basic_string_view::size(). Note that the
        ///     length refers to the total number of characters in the
        ///     string and not the number of bytes in the string. For the
        ///     total number of bytes, use bsl::basic_string_view::size_bytes().
        ///   @include basic_string_view/example_basic_string_view_length.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the length of the string being viewed.
        ///
        [[nodiscard]] constexpr size_type
        length() const noexcept
        {
            return this->size();
        }

        /// <!-- description -->
        ///   @brief Returns the max number of elements the BSL supports.
        ///   @include basic_string_view/example_basic_string_view_max_size.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the max number of elements the BSL supports.
        ///
        [[nodiscard]] static constexpr size_type
        max_size() noexcept
        {
            return numeric_limits<size_type>::max() / sizeof(CharT);
        }

        /// <!-- description -->
        ///   @brief Returns size() * sizeof(T)
        ///   @include basic_string_view/example_basic_string_view_size_bytes.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns size() * sizeof(T)
        ///
        [[nodiscard]] constexpr size_type
        size_bytes() const noexcept
        {
            return m_count * sizeof(CharT);
        }

        /// <!-- description -->
        ///   @brief Moves the start of the view forward by n characters. If
        ///     n >= size(), the bsl::basic_string_view is reset to a NULL
        ///     string, with data() returning a nullptr, and size() returning 0.
        ///   @include basic_string_view/example_basic_string_view_remove_prefix.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param n the number of character to remove from the start of
        ///     the string.
        ///   @return returns *this
        ///
        [[maybe_unused]] constexpr basic_string_view &
        remove_prefix(size_type const n) noexcept
        {
            if (n >= this->size()) {
                *this = basic_string_view{};
            }

            *this = basic_string_view{this->at_if(n), this->size() - n};
            return *this;
        }

        /// <!-- description -->
        ///   @brief Moves the end of the view back by n characters. If
        ///     n >= size(), the bsl::basic_string_view is reset to a NULL
        ///     string, with data() returning a nullptr, and size() returning 0.
        ///   @include basic_string_view/example_basic_string_view_remove_suffix.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param n the number of character to remove from the end of
        ///     the string.
        ///   @return returns *this
        ///
        [[maybe_unused]] constexpr basic_string_view &
        remove_suffix(size_type const n) noexcept
        {
            if (n >= this->size()) {
                *this = basic_string_view{};
            }

            *this = basic_string_view{this->at_if(0U), this->size() - n};
            return *this;
        }

        /// <!-- description -->
        ///   @brief Returns a new bsl::basic_string_view that is a
        ///     substring view of the original. The substring starts at "pos"
        ///     and ends at "pos" + "count". Note that this does not copy
        ///     the string, it simply changes the internal pointer and size
        ///     of the same string that is currently being viewed (meaning
        ///     the lifetime of the new substring cannot outlive the lifetime
        ///     of the string being viewed by the original
        ///     bsl::basic_string_view). If the provided "pos" or "count"
        ///     are invalid, this function returns an empty string view.
        ///   @include basic_string_view/example_basic_string_view_substr.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param pos the starting position of the new substring.
        ///   @param count the length of the new bsl::basic_string_view
        ///   @return Returns a new bsl::basic_string_view that is a
        ///     substring view of the original. The substring starts at "pos"
        ///     and ends at "pos" + "count".
        ///
        [[nodiscard]] constexpr basic_string_view
        substr(size_type const pos = 0U, size_type const count = npos) const noexcept
        {
            if (pos >= this->size()) {
                return basic_string_view{};
            }

            return basic_string_view{this->at_if(pos), min_of(count, this->size() - pos)};
        }

        /// <!-- description -->
        ///   @brief Compares two strings.
        ///   @include basic_string_view/example_basic_string_view_compare.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param str the bsl::basic_string_view to compare with
        ///   @return Returns the same results as std::strncmp
        ///
        [[nodiscard]] constexpr bsl::int32
        compare(basic_string_view const &str) const noexcept
        {
            return Traits::compare(this->data(), str.data(), min_of(this->size(), str.size()));
        }

        /// <!-- description -->
        ///   @brief Same as substr(pos, count).compare(v)
        ///   @include basic_string_view/example_basic_string_view_compare.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param pos the starting position of "this" to compare from
        ///   @param count the number of characters of "this" to compare
        ///   @param str the bsl::basic_string_view to compare with
        ///   @return Returns the same results as std::strncmp
        ///
        [[nodiscard]] constexpr bsl::int32
        compare(                      // --
            size_type const pos,      // --
            size_type const count,    // --
            basic_string_view const &str) const noexcept
        {
            return this->substr(pos, count).compare(str);
        }

        /// <!-- description -->
        ///   @brief Same as substr(pos1, count1).compare(v.substr(pos2, count2))
        ///   @include basic_string_view/example_basic_string_view_compare.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param pos1 the starting position of "this" to compare from
        ///   @param count1 the number of characters of "this" to compare
        ///   @param str the bsl::basic_string_view to compare with
        ///   @param pos2 the starting position of "v" to compare from
        ///   @param count2 the number of characters of "v" to compare
        ///   @return Returns the same results as std::strncmp
        ///
        [[nodiscard]] constexpr bsl::int32
        compare(                             // --
            size_type pos1,                  // --
            size_type count1,                // --
            basic_string_view const &str,    // --
            size_type pos2,                  // --
            size_type count2) const noexcept
        {
            return this->substr(pos1, count1).compare(str.substr(pos2, count2));
        }

        /// <!-- description -->
        ///   @brief Same as compare(basic_string_view{s})
        ///   @include basic_string_view/example_basic_string_view_compare.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param str a pointer to a string to compare with "this"
        ///   @return Returns the same results as std::strncmp
        ///
        [[nodiscard]] constexpr bsl::int32
        compare(pointer_type const str) const noexcept
        {
            return this->compare(basic_string_view{str});
        }

        /// <!-- description -->
        ///   @brief Same as substr(pos, count).compare(basic_string_view{s})
        ///   @include basic_string_view/example_basic_string_view_compare.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param pos the starting position of "this" to compare from
        ///   @param count the number of characters of "this" to compare
        ///   @param str a pointer to a string to compare with "this"
        ///   @return Returns the same results as std::strncmp
        ///
        [[nodiscard]] constexpr bsl::int32
        compare(size_type pos, size_type count, pointer_type const str) const noexcept
        {
            return this->substr(pos, count).compare(basic_string_view{str});
        }

        /// <!-- description -->
        ///   @brief Same as substr(pos, count1).compare(basic_string_view{s, count2})
        ///   @include basic_string_view/example_basic_string_view_compare.hpp
        ///
        /// <!-- notes -->
        ///   @note Unlike the standard library version of this function, the
        ///     BSL implements this function as the following to prevent
        ///     potential corruption:
        ///     compare(pos, count1, basic_string_view{s}, 0, count2)
        ///
        /// <!-- inputs/outputs -->
        ///   @param pos the starting position of "this" to compare from
        ///   @param count1 the number of characters of "this" to compare
        ///   @param str a pointer to a string to compare with "this"
        ///   @param count2 the number of characters of "s" to compare
        ///   @return Returns the same results as std::strncmp
        ///
        [[nodiscard]] constexpr bsl::int32
        compare(                       // --
            size_type pos,             // --
            size_type count1,          // --
            pointer_type const str,    // --
            size_type count2) const noexcept
        {
            return this->compare(pos, count1, basic_string_view{str}, 0, count2);
        }

        /// <!-- description -->
        ///   @brief Checks if the string begins with the given prefix
        ///   @include basic_string_view/example_basic_string_view_starts_with.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param str the bsl::basic_string_view to compare with
        ///   @return Returns true if the string begins with the given prefix,
        ///     false otherwise.
        ///
        [[nodiscard]] constexpr bool
        starts_with(basic_string_view const &str) const noexcept
        {
            if (this->size() < str.size()) {
                return false;
            }

            return this->substr(0U, str.size()) == str;
        }

        /// <!-- description -->
        ///   @brief Checks if the string begins with the given prefix
        ///   @include basic_string_view/example_basic_string_view_starts_with.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param c the value_type to compare with
        ///   @return Returns true if the string begins with the given prefix,
        ///     false otherwise.
        ///
        [[nodiscard]] constexpr bool
        starts_with(value_type const c) const noexcept
        {
            if (auto *const ptr = this->front_if()) {
                return Traits::eq(*ptr, c);
            }

            return false;
        }

        /// <!-- description -->
        ///   @brief Checks if the string begins with the given prefix
        ///   @include basic_string_view/example_basic_string_view_starts_with.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param str the string to compare with
        ///   @return Returns true if the string begins with the given prefix,
        ///     false otherwise.
        ///
        [[nodiscard]] constexpr bool
        starts_with(pointer_type const str) const noexcept
        {
            return this->starts_with(basic_string_view{str});
        }

        /// <!-- description -->
        ///   @brief Checks if the string ends with the given suffix
        ///   @include basic_string_view/example_basic_string_view_ends_with.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param str the bsl::basic_string_view to compare with
        ///   @return Returns true if the string ends with the given suffix,
        ///     false otherwise.
        ///
        [[nodiscard]] constexpr bool
        ends_with(basic_string_view const &str) const noexcept
        {
            if (this->size() < str.size()) {
                return false;
            }

            return this->compare(this->size() - str.size(), npos, str) == 0;
        }

        /// <!-- description -->
        ///   @brief Checks if the string ends with the given suffix
        ///   @include basic_string_view/example_basic_string_view_ends_with.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param c the value_type to compare with
        ///   @return Returns true if the string ends with the given suffix,
        ///     false otherwise.
        ///
        [[nodiscard]] constexpr bool
        ends_with(value_type const c) const noexcept
        {
            if (auto *const ptr = this->back_if()) {
                return Traits::eq(*ptr, c);
            }

            return false;
        }

        /// <!-- description -->
        ///   @brief Checks if the string ends with the given suffix
        ///   @include basic_string_view/example_basic_string_view_ends_with.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param str the string to compare with
        ///   @return Returns true if the string ends with the given suffix,
        ///     false otherwise.
        ///
        [[nodiscard]] constexpr bool
        ends_with(pointer_type const str) const noexcept
        {
            return this->ends_with(basic_string_view{str});
        }

    private:
        /// <!-- description -->
        ///   @brief ptr/count constructor. Creates a bsl::basic_string_view
        ///     given a pointer to a string and the number of characters in
        ///     the string.
        ///   @include basic_string_view/example_basic_string_view_s_count_constructor.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param s a pointer to the string
        ///   @param count the number of characters in the string
        ///
        constexpr basic_string_view(pointer_type const s, size_type const count) noexcept
            : m_ptr{s}, m_count{count}
        {
            if ((nullptr == m_ptr) || (0U == m_count)) {
                *this = basic_string_view{};
            }
        }

        /// @brief stores a pointer to the string being viewed
        pointer_type m_ptr;
        /// @brief stores the number of elements in the string being viewed
        size_type m_count;
    };

    /// <!-- description -->
    ///   @brief Returns true if two strings have the same length (which is
    ///     different from compare() which uses the minimum size between the
    ///     two provided strings), and contain the same characters. Returns
    ///     false otherwise.
    ///   @include basic_string_view/example_basic_string_view_equals.hpp
    ///   @related bsl::basic_string_view
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam CharT the type of characters in the string
    ///   @tparam Traits the traits class used to work with the string
    ///   @param lhs the left hand side of the operation
    ///   @param rhs the right hand side of the operation
    ///   @return Returns true if two strings have the same length (which is
    ///     different from compare() which uses the minimum size between the
    ///     two provided strings), and contain the same characters. Returns
    ///     false otherwise.
    ///
    template<typename CharT, typename Traits>
    constexpr bool
    operator==(
        bsl::basic_string_view<CharT, Traits> const &lhs,
        bsl::basic_string_view<CharT, Traits> const &rhs) noexcept
    {
        if (lhs.size() != rhs.size()) {
            return false;
        }

        return lhs.compare(rhs) == 0;
    }

    /// <!-- description -->
    ///   @brief Returns true if two strings have the same length (which is
    ///     different from compare() which uses the minimum size between the
    ///     two provided strings), and contain the same characters. Returns
    ///     false otherwise.
    ///   @include basic_string_view/example_basic_string_view_equals.hpp
    ///   @related bsl::basic_string_view
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam CharT the type of characters in the string
    ///   @tparam Traits the traits class used to work with the string
    ///   @param lhs the left hand side of the operation
    ///   @param rhs the right hand side of the operation
    ///   @return Returns true if two strings have the same length (which is
    ///     different from compare() which uses the minimum size between the
    ///     two provided strings), and contain the same characters. Returns
    ///     false otherwise.
    ///
    template<typename CharT, typename Traits>
    constexpr bool
    operator==(bsl::basic_string_view<CharT, Traits> const &lhs, CharT const *const rhs) noexcept
    {
        return lhs == bsl::basic_string_view<CharT, Traits>{rhs};
    }

    /// <!-- description -->
    ///   @brief Returns true if two strings have the same length (which is
    ///     different from compare() which uses the minimum size between the
    ///     two provided strings), and contain the same characters. Returns
    ///     false otherwise.
    ///   @include basic_string_view/example_basic_string_view_equals.hpp
    ///   @related bsl::basic_string_view
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam CharT the type of characters in the string
    ///   @tparam Traits the traits class used to work with the string
    ///   @param lhs the left hand side of the operation
    ///   @param rhs the right hand side of the operation
    ///   @return Returns true if two strings have the same length (which is
    ///     different from compare() which uses the minimum size between the
    ///     two provided strings), and contain the same characters. Returns
    ///     false otherwise.
    ///
    template<typename CharT, typename Traits>
    constexpr bool
    operator==(CharT const *const lhs, bsl::basic_string_view<CharT, Traits> const &rhs) noexcept
    {
        return bsl::basic_string_view<CharT, Traits>{lhs} == rhs;
    }

    /// <!-- description -->
    ///   @brief Returns true if two strings are not the same length (which is
    ///     different from compare() which uses the minimum size between the
    ///     two provided strings), or contain different characters. Returns
    ///     false otherwise.
    ///   @include basic_string_view/example_basic_string_view_not_equals.hpp
    ///   @related bsl::basic_string_view
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam CharT the type of characters in the string
    ///   @tparam Traits the traits class used to work with the string
    ///   @param lhs the left hand side of the operation
    ///   @param rhs the right hand side of the operation
    ///   @return Returns true if two strings are not the same length (which is
    ///     different from compare() which uses the minimum size between the
    ///     two provided strings), or contain different characters. Returns
    ///     false otherwise.
    ///
    template<typename CharT, typename Traits>
    constexpr bool
    operator!=(
        bsl::basic_string_view<CharT, Traits> const &lhs,
        bsl::basic_string_view<CharT, Traits> const &rhs) noexcept
    {
        return !(lhs == rhs);
    }

    /// <!-- description -->
    ///   @brief Returns true if two strings are not the same length (which is
    ///     different from compare() which uses the minimum size between the
    ///     two provided strings), or contain different characters. Returns
    ///     false otherwise.
    ///   @include basic_string_view/example_basic_string_view_not_equals.hpp
    ///   @related bsl::basic_string_view
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam CharT the type of characters in the string
    ///   @tparam Traits the traits class used to work with the string
    ///   @param lhs the left hand side of the operation
    ///   @param rhs the right hand side of the operation
    ///   @return Returns true if two strings are not the same length (which is
    ///     different from compare() which uses the minimum size between the
    ///     two provided strings), or contain different characters. Returns
    ///     false otherwise.
    ///
    template<typename CharT, typename Traits>
    constexpr bool
    operator!=(bsl::basic_string_view<CharT, Traits> const &lhs, CharT const *const rhs) noexcept
    {
        return !(lhs == rhs);
    }

    /// <!-- description -->
    ///   @brief Returns true if two strings are not the same length (which is
    ///     different from compare() which uses the minimum size between the
    ///     two provided strings), or contain different characters. Returns
    ///     false otherwise.
    ///   @include basic_string_view/example_basic_string_view_not_equals.hpp
    ///   @related bsl::basic_string_view
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam CharT the type of characters in the string
    ///   @tparam Traits the traits class used to work with the string
    ///   @param lhs the left hand side of the operation
    ///   @param rhs the right hand side of the operation
    ///   @return Returns true if two strings are not the same length (which is
    ///     different from compare() which uses the minimum size between the
    ///     two provided strings), or contain different characters. Returns
    ///     false otherwise.
    ///
    template<typename CharT, typename Traits>
    constexpr bool
    operator!=(CharT const *const lhs, bsl::basic_string_view<CharT, Traits> const &rhs) noexcept
    {
        return !(lhs == rhs);
    }

    /// <!-- description -->
    ///   @brief This function is responsible for implementing bsl::fmt
    ///     for string_view types. For strings, the only fmt options
    ///     that are available are alignment, fill and width, all of which
    ///     are handled by the fmt_impl_align_xxx functions.
    ///   @related bsl::basic_string_view
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam OUT the type of out (i.e., debug, alert, etc)
    ///   @param o the instance of out<T> to output to
    ///   @param ops ops the fmt options used to format the output
    ///   @param str the string_view being outputted
    ///
    template<typename OUT, typename CharT>
    constexpr void
    fmt_impl(OUT &&o, fmt_options const &ops, basic_string_view<CharT> const &str) noexcept
    {
        details::fmt_impl_align_pre(o, ops, str.length(), true);
        o.write(str.data());
        details::fmt_impl_align_suf(o, ops, str.length(), true);
    }

    /// <!-- description -->
    ///   @brief Outputs the provided string_view to the provided
    ///     output type.
    ///   @related bsl::basic_string_view
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of outputter provided
    ///   @param o the instance of the outputter used to output the value.
    ///   @param str the string_view to output
    ///   @return return o
    ///
    template<typename T, typename CharT>
    [[maybe_unused]] constexpr out<T>
    operator<<(out<T> const o, basic_string_view<CharT> const &str) noexcept
    {
        if constexpr (o.empty()) {
            return o;
        }

        o.write(str.data());
        return o;
    }
}

#endif
