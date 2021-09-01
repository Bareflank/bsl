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
#include "ensures.hpp"
#include "expects.hpp"
#include "npos.hpp"
#include "reverse_iterator.hpp"
#include "safe_integral.hpp"
#include "touch.hpp"
#include "unlikely.hpp"

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
    ///   @tparam CHAR_T the type of characters in the string
    ///   @tparam TRAITS the traits class used to work with the string
    ///
    template<typename CHAR_T, typename TRAITS = char_traits<CHAR_T>>
    class basic_string_view final
    {
    public:
        /// @brief alias for: CHAR_T const
        using value_type = CHAR_T const;
        /// @brief alias for: safe_umx
        using size_type = safe_umx;
        /// @brief alias for: safe_umx
        using difference_type = safe_umx;
        /// @brief alias for: safe_idx
        using index_type = safe_idx;
        /// @brief alias for: CHAR_T const &
        using reference_type = CHAR_T const &;
        /// @brief alias for: CHAR_T const &
        using const_reference_type = CHAR_T const &;
        /// @brief alias for: CHAR_T const *
        using pointer_type = CHAR_T const *;
        /// @brief alias for: CHAR_T const const *
        using const_pointer_type = CHAR_T const *;
        /// @brief alias for: contiguous_iterator<CHAR_T const>
        using iterator_type = contiguous_iterator<CHAR_T const>;
        /// @brief alias for: contiguous_iterator<CHAR_T const const>
        using const_iterator_type = contiguous_iterator<CHAR_T const>;
        /// @brief alias for: reverse_iterator<iterator>
        using reverse_iterator_type = reverse_iterator<iterator_type>;
        /// @brief alias for: reverse_iterator<const_iterator>
        using const_reverse_iterator_type = reverse_iterator<const_iterator_type>;

        /// <!-- description -->
        ///   @brief Default constructor.
        ///   @include basic_string_view/example_basic_string_view_default_constructor.hpp
        ///
        constexpr basic_string_view() noexcept    // --
            : m_ptr{}, m_count{}
        {}

        /// <!-- description -->
        ///   @brief ptr constructor. This creates a bsl::basic_string_view
        ///     given a pointer to a string. The number of characters in the
        ///     string is determined using TRAITS<CHAR_T>::length,
        ///     which scans for '\0'.
        ///   @include basic_string_view/example_basic_string_view_s_constructor.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param s a pointer to the string
        ///
        // We use a deleted single argument template constructor to prevent
        // implicit conversions, so this rule is OBE.
        // NOLINTNEXTLINE(hicpp-explicit-conversions)
        constexpr basic_string_view(pointer_type const s) noexcept
            : m_ptr{s}, m_count{TRAITS::length(s)}
        {
            expects(nullptr != s);
            expects(m_count.is_valid_and_checked());
        }

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
        constexpr basic_string_view(pointer_type const s, size_type const &count) noexcept
            : m_ptr{s}, m_count{count}
        {
            expects(nullptr != s);
            expects(m_count.is_valid_and_checked());
        }

        /// <!-- description -->
        ///   @brief Destroyes a previously created bsl::basic_string_view
        ///
        constexpr ~basic_string_view() noexcept = default;

        /// <!-- description -->
        ///   @brief copy constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///
        constexpr basic_string_view(basic_string_view const &o) noexcept = default;

        /// <!-- description -->
        ///   @brief move constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_o the object being moved
        ///
        constexpr basic_string_view(basic_string_view &&mut_o) noexcept = default;

        /// <!-- description -->
        ///   @brief copy assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr auto operator=(basic_string_view const &o) &noexcept
            -> basic_string_view & = default;

        /// <!-- description -->
        ///   @brief move assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_o the object being moved
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr auto operator=(basic_string_view &&mut_o) &noexcept
            -> basic_string_view & = default;

        /// <!-- description -->
        ///   @brief This constructor allows for single argument constructors
        ///     without the need to mark them as explicit as it will absorb
        ///     any incoming potential implicit conversion and prevent it.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam O the type that could be implicitly converted
        ///   @param mut_val the value that could be implicitly converted
        ///
        template<typename O>
        constexpr basic_string_view(O mut_val) noexcept = delete;

        /// <!-- description -->
        ///   @brief ptr assignment. This assigns a bsl::basic_string_view
        ///     a pointer to a string. The number of characters in the
        ///     string is determined using TRAITS<CHAR_T>::length,
        ///     which scans for '\0'.
        ///   @include basic_string_view/example_basic_string_view_s_assignment.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param s a pointer to the string
        ///   @return Returns *this
        ///
        [[maybe_unused]] constexpr auto
        operator=(pointer_type const s) &noexcept -> basic_string_view &
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
        /// <!-- inputs/outputs -->
        ///   @param index the index of the instance to return
        ///   @return Returns a pointer to the instance of T stored at index
        ///     "index". If the index is out of bounds, or the view is invalid,
        ///     this function returns a nullptr.
        ///
        [[nodiscard]] constexpr auto
        at_if(index_type const &index) noexcept -> pointer_type
        {
            expects(index.is_valid());

            if (unlikely(index >= m_count)) {
                return nullptr;
            }

            // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index)
            return &m_ptr[index.get()];
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
        [[nodiscard]] constexpr auto
        at_if(index_type const &index) const noexcept -> const_pointer_type
        {
            expects(index.is_valid());

            if (unlikely(index >= m_count)) {
                return nullptr;
            }

            // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index)
            return &m_ptr[index.get()];
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
        [[nodiscard]] constexpr auto
        front_if() noexcept -> pointer_type
        {
            return this->at_if({});
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
        [[nodiscard]] constexpr auto
        front_if() const noexcept -> const_pointer_type
        {
            return this->at_if({});
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
        [[nodiscard]] constexpr auto
        back_if() noexcept -> pointer_type
        {
            if (unlikely(m_count.is_zero())) {
                return nullptr;
            }

            /// NOTE:
            /// - We verify above that m_count is not zero. Since m_count
            ///   is unsigned and never modified by this class after the
            ///   constructor is executed, the following must be valid and
            ///   so it is marked as checked.
            ///

            safe_idx const index{(m_count - size_type::magic_1()).checked().get()};
            return this->at_if(index);
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
        [[nodiscard]] constexpr auto
        back_if() const noexcept -> const_pointer_type
        {
            if (unlikely(m_count.is_zero())) {
                return nullptr;
            }

            /// NOTE:
            /// - We verify above that m_count is not zero. Since m_count
            ///   is unsigned and never modified by this class after the
            ///   constructor is executed, the following must be valid and
            ///   so it is marked as checked.
            ///

            safe_idx const index{(m_count - size_type::magic_1()).checked().get()};
            return this->at_if(index);
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
        [[nodiscard]] constexpr auto
        data() noexcept -> pointer_type
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
        [[nodiscard]] constexpr auto
        data() const noexcept -> const_pointer_type
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
        [[nodiscard]] constexpr auto
        begin() noexcept -> iterator_type
        {
            return iterator_type{m_ptr, m_count, {}};
        }

        /// <!-- description -->
        ///   @brief Returns an iterator to the first element of the view.
        ///   @include basic_string_view/example_basic_string_view_begin.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns an iterator to the first element of the view.
        ///
        [[nodiscard]] constexpr auto
        begin() const noexcept -> const_iterator_type
        {
            return const_iterator_type{m_ptr, m_count, {}};
        }

        /// <!-- description -->
        ///   @brief Returns an iterator to the first element of the view.
        ///   @include basic_string_view/example_basic_string_view_begin.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns an iterator to the first element of the view.
        ///
        [[nodiscard]] constexpr auto
        cbegin() const noexcept -> const_iterator_type
        {
            return const_iterator_type{m_ptr, m_count, {}};
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
        [[nodiscard]] constexpr auto
        end() noexcept -> iterator_type
        {
            return iterator_type{m_ptr, m_count, safe_idx{m_count.get()}};
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
        [[nodiscard]] constexpr auto
        end() const noexcept -> const_iterator_type
        {
            return const_iterator_type{m_ptr, m_count, safe_idx{m_count.get()}};
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
        [[nodiscard]] constexpr auto
        cend() const noexcept -> const_iterator_type
        {
            return const_iterator_type{m_ptr, m_count, safe_idx{m_count.get()}};
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
        [[nodiscard]] constexpr auto
        rbegin() noexcept -> reverse_iterator_type
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
        [[nodiscard]] constexpr auto
        rbegin() const noexcept -> const_reverse_iterator_type
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
        [[nodiscard]] constexpr auto
        crbegin() const noexcept -> const_reverse_iterator_type
        {
            return const_reverse_iterator_type{this->cend()};
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
        [[nodiscard]] constexpr auto
        rend() noexcept -> reverse_iterator_type
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
        [[nodiscard]] constexpr auto
        rend() const noexcept -> const_reverse_iterator_type
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
        [[nodiscard]] constexpr auto
        crend() const noexcept -> const_reverse_iterator_type
        {
            return const_reverse_iterator_type{this->cbegin()};
        }

        /// <!-- description -->
        ///   @brief Returns size().is_zero();
        ///   @include basic_string_view/example_basic_string_view_empty.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns size().is_zero();
        ///
        [[nodiscard]] constexpr auto
        empty() const noexcept -> bool
        {
            return m_count.is_zero();
        }

        /// <!-- description -->
        ///   @brief Returns data() != nullptr;
        ///   @include basic_string_view/example_basic_string_view_is_invalid.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns data() != nullptr;
        ///
        [[nodiscard]] constexpr auto
        is_invalid() const noexcept -> bool
        {
            return m_ptr == nullptr;
        }

        /// <!-- description -->
        ///   @brief Returns data() != nullptr;
        ///   @include basic_string_view/example_basic_string_view_is_valid.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns data() != nullptr;
        ///
        [[nodiscard]] constexpr auto
        is_valid() const noexcept -> bool
        {
            return m_ptr != nullptr;
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
        [[nodiscard]] constexpr auto
        size() const noexcept -> size_type const &
        {
            ensures(m_count.is_valid_and_checked());
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
        [[nodiscard]] constexpr auto
        length() const noexcept -> size_type const &
        {
            ensures(m_count.is_valid_and_checked());
            return m_count;
        }

        /// <!-- description -->
        ///   @brief Returns the max number of elements the BSL supports.
        ///   @include basic_string_view/example_basic_string_view_max_size.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the max number of elements the BSL supports.
        ///
        [[nodiscard]] static constexpr auto
        max_size() noexcept -> size_type
        {
            constexpr auto val{(size_type::max_value() / sizeof(CHAR_T)).checked()};

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
        ///   @include basic_string_view/example_basic_string_view_size_bytes.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns size() * sizeof(T)
        ///
        [[nodiscard]] constexpr auto
        size_bytes() const noexcept -> size_type
        {
            auto const val{(m_count * sizeof(CHAR_T)).checked()};

            /// NOTE:
            /// - An error is not possible because the denominator is
            ///   always positive, so the result of max_size() is marked
            ///   as checked.
            ///

            ensures(val.is_valid_and_checked());
            return val;
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
        [[maybe_unused]] constexpr auto
        remove_prefix(index_type const &n) noexcept -> basic_string_view &
        {
            expects(n.is_valid());

            if (unlikely(n >= m_count)) {
                *this = basic_string_view{};
                return *this;
            }

            /// NOTE:
            /// - We verify above that n must be less than m_count, which
            ///   prevents the following from underflowing which is why it is
            ///   marked as checked().
            ///

            *this = basic_string_view{this->at_if(n), (m_count - n.get()).checked()};
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
        [[maybe_unused]] constexpr auto
        remove_suffix(index_type const &n) noexcept -> basic_string_view &
        {
            expects(n.is_valid());

            if (unlikely(n >= m_count)) {
                *this = basic_string_view{};
                return *this;
            }

            /// NOTE:
            /// - We verify above that n must be less than m_count, which
            ///   prevents the following from underflowing which is why it is
            ///   marked as checked().
            ///

            *this = basic_string_view{this->front_if(), (m_count - n.get()).checked()};
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
        [[nodiscard]] constexpr auto
        substr(index_type const &pos = {}, size_type const &count = size_type::max_value())
            const noexcept -> basic_string_view
        {
            expects(pos.is_valid());
            expects(count.is_valid_and_checked());

            if (unlikely(pos >= m_count)) {
                return basic_string_view{};
            }

            /// NOTE:
            /// - The check above makes sure that the math below cannot
            ///   underflow which is why it is marked as checked.
            ///

            auto const adjusted_count{(m_count - pos.get()).checked()};
            return basic_string_view{this->at_if(pos), count.min(adjusted_count)};
        }

        /// <!-- description -->
        ///   @brief Compares two strings. Calculates the minimum size between
        ///     the two strings and compares up to this minimum. If these
        ///     substrings are the same, returns true. Returns false
        ///     otherwise. If either string is empty, also returns true.
        ///   @include basic_string_view/example_basic_string_view_equals.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param str the bsl::basic_string_view to compare with
        ///   @return Compares two strings. Calculates the minimum size between
        ///     the two strings and compares up to this minimum. If these
        ///     substrings are the same, returns true. Returns false
        ///     otherwise. If either string is empty, also returns true.
        ///
        [[nodiscard]] constexpr auto
        equals(basic_string_view const &str) const noexcept -> bool
        {
            if (unlikely(this->empty())) {
                return true;
            }

            if (unlikely(str.empty())) {
                return true;
            }

            auto const count{m_count.min(str.size())};
            for (safe_idx mut_i{}; mut_i < count; ++mut_i) {
                if (*this->at_if(mut_i) != *str.at_if(mut_i)) {
                    return false;
                }

                bsl::touch();
            }

            return true;
        }

        /// <!-- description -->
        ///   @brief Returns this->equals(basic_string_view{str})
        ///   @include basic_string_view/example_basic_string_view_equals.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param str a pointer to a string to compare with "this"
        ///   @return Returns this->equals(basic_string_view{str})
        ///
        [[nodiscard]] constexpr auto
        equals(pointer_type const str) const noexcept -> bool
        {
            return this->equals(basic_string_view{str});
        }

        /// <!-- description -->
        ///   @brief Returns this->substr(pos, count).equals(str)
        ///   @include basic_string_view/example_basic_string_view_equals.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param pos the starting position of "this" to compare from
        ///   @param count the number of characters of "this" to compare
        ///   @param str the bsl::basic_string_view to compare with
        ///   @return Returns this->substr(pos, count).equals(str);
        ///
        [[nodiscard]] constexpr auto
        equals(                        // --
            index_type const &pos,     // --
            size_type const &count,    // --
            basic_string_view const &str) const noexcept -> bool
        {
            return this->substr(pos, count).equals(str);
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
        [[nodiscard]] constexpr auto
        starts_with(basic_string_view const &str) const noexcept -> bool
        {
            if (unlikely(str.empty())) {
                return false;
            }

            if (unlikely(m_count < str.size())) {
                return false;
            }

            return this->equals({}, str.size(), str);
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
        [[nodiscard]] constexpr auto
        starts_with(value_type const c) const noexcept -> bool
        {
            if (unlikely(this->empty())) {
                return false;
            }

            return TRAITS::eq(*this->front_if(), c);
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
        [[nodiscard]] constexpr auto
        starts_with(pointer_type const str) const noexcept -> bool
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
        [[nodiscard]] constexpr auto
        ends_with(basic_string_view const &str) const noexcept -> bool
        {
            if (unlikely(str.empty())) {
                return false;
            }

            if (unlikely(m_count < str.size())) {
                return false;
            }

            /// NOTE:
            /// - The above checks ensure that compare will never return
            ///   an invalid result which is why it is marked as checked.
            ///

            safe_idx const pos{(m_count - str.size()).checked().get()};
            return this->equals(pos, str.size(), str);
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
        [[nodiscard]] constexpr auto
        ends_with(value_type const c) const noexcept -> bool
        {
            if (unlikely(this->empty())) {
                return false;
            }

            return TRAITS::eq(*this->back_if(), c);
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
        [[nodiscard]] constexpr auto
        ends_with(pointer_type const str) const noexcept -> bool
        {
            return this->ends_with(basic_string_view{str});
        }

        /// <!-- description -->
        ///   @brief Returns the index of the first occurrence of the provided
        ///     string. If the string does not occur, bsl::npos is returned.
        ///   @include basic_string_view/example_basic_string_view_find.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param str the string to find the index of
        ///   @param pos the starting position to search from
        ///   @return Returns the index of the first occurrence of the provided
        ///     string. If the string does not occur, bsl::npos is
        ///     returned.
        ///
        [[nodiscard]] constexpr auto
        find(basic_string_view const &str, index_type const &pos = {}) const noexcept -> index_type
        {
            expects(pos.is_valid());

            auto const view{this->substr(pos)};
            if (view.empty()) {
                return npos;
            }

            if (unlikely(str.empty())) {
                return npos;
            }

            if (unlikely(view.length() < str.length())) {
                return npos;
            }

            /// NOTE:
            /// - We verify above that the input string's length is <= to
            ///   this string's length after we have a view that takes into
            ///   account the starting position. Since everything is unsigned,
            ///   the math below must be valid so it is marked as checked.
            ///

            auto const len{((view.length() - str.length()) + size_type::magic_1()).checked()};
            for (index_type mut_i{}; mut_i < len; ++mut_i) {
                if (view.equals(mut_i, size_type::max_value(), str)) {
                    return mut_i + pos;
                }

                bsl::touch();
            }

            return npos;
        }

        /// <!-- description -->
        ///   @brief Returns the index of the first occurrence of the provided
        ///     character. If the character does not occur, bsl::npos is
        ///     returned.
        ///   @include basic_string_view/example_basic_string_view_find.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param ch the character to find the index of
        ///   @param pos the starting position to search from
        ///   @return Returns the index of the first occurrence of the provided
        ///     character. If the character does not occur, bsl::npos is
        ///     returned.
        ///
        [[nodiscard]] constexpr auto
        find(CHAR_T const ch, index_type const &pos = {}) const noexcept -> index_type
        {
            expects(pos.is_valid());

            auto const view{this->substr(pos)};
            if (view.empty()) {
                return npos;
            }

            for (index_type mut_i{}; mut_i < view.length(); ++mut_i) {
                if (*view.at_if(mut_i) == ch) {
                    return mut_i + pos;
                }

                bsl::touch();
            }

            return npos;
        }

        /// <!-- description -->
        ///   @brief Returns the index of the first occurrence of the provided
        ///     string. If the string does not occur, bsl::npos is returned.
        ///   @include basic_string_view/example_basic_string_view_find.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param str the string to find the index of
        ///   @param pos the starting position to search from
        ///   @return Returns the index of the first occurrence of the provided
        ///     string. If the string does not occur, bsl::npos is returned.
        ///
        [[nodiscard]] constexpr auto
        find(pointer_type const str, index_type const &pos = {}) const noexcept -> index_type
        {
            expects(pos.is_valid());
            return this->find(basic_string_view{str}, pos);
        }

    private:
        /// @brief stores a pointer to the string being viewed
        pointer_type m_ptr;
        /// @brief stores the number of elements in the string being viewed
        size_type m_count;
    };

    /// <!-- description -->
    ///   @brief If the two strings are the same length, returns
    ///     lhs.equals(rhs). Otherwise returns false.
    ///   @include basic_string_view/example_basic_string_view_equals.hpp
    ///   @related bsl::basic_string_view
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam CHAR_T the type of characters in the string
    ///   @tparam TRAITS the traits class used to work with the string
    ///   @param lhs the left hand side of the operation
    ///   @param rhs the right hand side of the operation
    ///   @return If the two strings are the same length, returns
    ///     lhs.equals(rhs). Otherwise returns false.
    ///
    template<typename CHAR_T, typename TRAITS>
    [[nodiscard]] constexpr auto
    operator==(
        bsl::basic_string_view<CHAR_T, TRAITS> const &lhs,
        bsl::basic_string_view<CHAR_T, TRAITS> const &rhs) noexcept -> bool
    {
        if (lhs.empty()) {
            return rhs.empty();
        }

        if (lhs.length() != rhs.length()) {
            return false;
        }

        return lhs.equals(rhs);
    }

    /// <!-- description -->
    ///   @brief Returns lhs == bsl::basic_string_view<CHAR_T, TRAITS>{rhs}
    ///   @include basic_string_view/example_basic_string_view_equals.hpp
    ///   @related bsl::basic_string_view
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam CHAR_T the type of characters in the string
    ///   @tparam TRAITS the traits class used to work with the string
    ///   @param lhs the left hand side of the operation
    ///   @param rhs the right hand side of the operation
    ///   @return Returns lhs == bsl::basic_string_view<CHAR_T, TRAITS>{rhs}
    ///
    template<typename CHAR_T, typename TRAITS>
    [[nodiscard]] constexpr auto
    operator==(bsl::basic_string_view<CHAR_T, TRAITS> const &lhs, CHAR_T const *const rhs) noexcept
        -> bool
    {
        return lhs == bsl::basic_string_view<CHAR_T, TRAITS>{rhs};
    }

    /// <!-- description -->
    ///   @brief Returns bsl::basic_string_view<CHAR_T, TRAITS>{lhs} == rhs
    ///   @include basic_string_view/example_basic_string_view_equals.hpp
    ///   @related bsl::basic_string_view
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam CHAR_T the type of characters in the string
    ///   @tparam TRAITS the traits class used to work with the string
    ///   @param lhs the left hand side of the operation
    ///   @param rhs the right hand side of the operation
    ///   @return Returns bsl::basic_string_view<CHAR_T, TRAITS>{lhs} == rhs
    ///
    template<typename CHAR_T, typename TRAITS>
    [[nodiscard]] constexpr auto
    operator==(CHAR_T const *const lhs, bsl::basic_string_view<CHAR_T, TRAITS> const &rhs) noexcept
        -> bool
    {
        return bsl::basic_string_view<CHAR_T, TRAITS>{lhs} == rhs;
    }

    /// <!-- description -->
    ///   @brief Returns !(lhs == rhs)
    ///   @include basic_string_view/example_basic_string_view_not_equals.hpp
    ///   @related bsl::basic_string_view
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam CHAR_T the type of characters in the string
    ///   @tparam TRAITS the traits class used to work with the string
    ///   @param lhs the left hand side of the operation
    ///   @param rhs the right hand side of the operation
    ///   @return Returns !(lhs == rhs)
    ///
    template<typename CHAR_T, typename TRAITS>
    [[nodiscard]] constexpr auto
    operator!=(
        bsl::basic_string_view<CHAR_T, TRAITS> const &lhs,
        bsl::basic_string_view<CHAR_T, TRAITS> const &rhs) noexcept -> bool
    {
        return !(lhs == rhs);
    }

    /// <!-- description -->
    ///   @brief Returns !(lhs == rhs)
    ///   @include basic_string_view/example_basic_string_view_not_equals.hpp
    ///   @related bsl::basic_string_view
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam CHAR_T the type of characters in the string
    ///   @tparam TRAITS the traits class used to work with the string
    ///   @param lhs the left hand side of the operation
    ///   @param rhs the right hand side of the operation
    ///   @return Returns !(lhs == rhs)
    ///
    template<typename CHAR_T, typename TRAITS>
    [[nodiscard]] constexpr auto
    operator!=(bsl::basic_string_view<CHAR_T, TRAITS> const &lhs, CHAR_T const *const rhs) noexcept
        -> bool
    {
        return !(lhs == rhs);
    }

    /// <!-- description -->
    ///   @brief Returns !(lhs == rhs)
    ///   @include basic_string_view/example_basic_string_view_not_equals.hpp
    ///   @related bsl::basic_string_view
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam CHAR_T the type of characters in the string
    ///   @tparam TRAITS the traits class used to work with the string
    ///   @param lhs the left hand side of the operation
    ///   @param rhs the right hand side of the operation
    ///   @return Returns !(lhs == rhs)
    ///
    template<typename CHAR_T, typename TRAITS>
    [[nodiscard]] constexpr auto
    operator!=(CHAR_T const *const lhs, bsl::basic_string_view<CHAR_T, TRAITS> const &rhs) noexcept
        -> bool
    {
        return !(lhs == rhs);
    }
}

#endif
