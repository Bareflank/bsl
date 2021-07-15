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
#include "likely.hpp"
#include "npos.hpp"
#include "reverse_iterator.hpp"
#include "safe_integral.hpp"
#include "touch.hpp"
#include "unlikely.hpp"

// TODO:
// - Need to finish implementing the find functions.
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
    ///   @tparam CHAR_T the type of characters in the string
    ///   @tparam TRAITS the traits class used to work with the string
    ///
    template<typename CHAR_T, typename TRAITS = char_traits<CHAR_T>>
    class basic_string_view final
    {
    public:
        /// @brief alias for: CHAR_T const
        using value_type = CHAR_T const;
        /// @brief alias for: safe_uintmax
        using size_type = safe_uintmax;
        /// @brief alias for: safe_uintmax
        using difference_type = safe_uintmax;
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
            if (unlikely(nullptr == m_ptr)) {
                unlikely_invalid_argument_failure();
                *this = basic_string_view{};
                return;
            }

            bsl::touch();
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
            if (unlikely(nullptr == m_ptr)) {
                unlikely_invalid_argument_failure();
                *this = basic_string_view{};
                return;
            }

            if (unlikely(!m_count)) {
                unlikely_invalid_argument_failure();
                *this = basic_string_view{};
                return;
            }

            bsl::touch();
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
        at_if(size_type const &index) noexcept -> pointer_type
        {
            if (unlikely(!index)) {
                unlikely_invalid_argument_failure();
                return nullptr;
            }

            if (likely(index < m_count)) {
                // We are implementing std::array here, which is what this test
                // wants you to use instead.
                // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index)
                return &m_ptr[index.get()];
            }

            return nullptr;
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
        at_if(size_type const &index) const noexcept -> const_pointer_type
        {
            if (unlikely(!index)) {
                unlikely_invalid_argument_failure();
                return nullptr;
            }

            if (likely(index < m_count)) {
                // We are implementing std::array here, which is what this test
                // wants you to use instead.
                // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index)
                return &m_ptr[index.get()];
            }

            return nullptr;
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
            constexpr safe_uintmax zero{static_cast<bsl::uintmax>(0)};
            return this->at_if(zero);
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
            constexpr safe_uintmax zero{static_cast<bsl::uintmax>(0)};
            return this->at_if(zero);
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
            constexpr safe_uintmax one{static_cast<bsl::uintmax>(1)};
            constexpr safe_uintmax zero{static_cast<bsl::uintmax>(0)};

            if (unlikely(m_count.is_zero())) {
                unlikely_precondition_failure();
                return this->at_if(zero);
            }

            return this->at_if(m_count - one);
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
            constexpr safe_uintmax one{static_cast<bsl::uintmax>(1)};
            constexpr safe_uintmax zero{static_cast<bsl::uintmax>(0)};

            if (unlikely(m_count.is_zero())) {
                unlikely_precondition_failure();
                return this->at_if(zero);
            }

            return this->at_if(m_count - one);
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
            constexpr safe_uintmax zero{static_cast<bsl::uintmax>(0)};
            return iterator_type{m_ptr, m_count, zero};
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
            constexpr safe_uintmax zero{static_cast<bsl::uintmax>(0)};
            return const_iterator_type{m_ptr, m_count, zero};
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
            constexpr safe_uintmax zero{static_cast<bsl::uintmax>(0)};
            return const_iterator_type{m_ptr, m_count, zero};
        }

        /// <!-- description -->
        ///   @brief Returns an iterator to the element "i" in the view.
        ///   @include basic_string_view/example_basic_string_view_iter.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param i the element in the string to return an iterator for.
        ///   @return Returns an iterator to the element "i" in the view.
        ///
        [[nodiscard]] constexpr auto
        iter(size_type const &i) noexcept -> iterator_type
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
        [[nodiscard]] constexpr auto
        iter(size_type const &i) const noexcept -> const_iterator_type
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
        [[nodiscard]] constexpr auto
        citer(size_type const &i) const noexcept -> const_iterator_type
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
        [[nodiscard]] constexpr auto
        end() noexcept -> iterator_type
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
        [[nodiscard]] constexpr auto
        end() const noexcept -> const_iterator_type
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
        [[nodiscard]] constexpr auto
        cend() const noexcept -> const_iterator_type
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
        [[nodiscard]] constexpr auto
        riter(size_type const &i) noexcept -> reverse_iterator_type
        {
            constexpr safe_uintmax one{static_cast<bsl::uintmax>(1)};
            constexpr safe_uintmax zero{static_cast<bsl::uintmax>(0)};

            if (unlikely(!i)) {
                unlikely_invalid_argument_failure();
                return reverse_iterator_type{this->iter(zero)};
            }

            if (likely(i < m_count)) {
                return reverse_iterator_type{this->iter(i + one)};
            }

            return reverse_iterator_type{this->iter(zero)};
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
        [[nodiscard]] constexpr auto
        riter(size_type const &i) const noexcept -> const_reverse_iterator_type
        {
            constexpr safe_uintmax one{static_cast<bsl::uintmax>(1)};
            constexpr safe_uintmax zero{static_cast<bsl::uintmax>(0)};

            if (unlikely(!i)) {
                unlikely_invalid_argument_failure();
                return const_reverse_iterator_type{this->iter(zero)};
            }

            if (likely(i < m_count)) {
                return const_reverse_iterator_type{this->iter(i + one)};
            }

            return const_reverse_iterator_type{this->iter(zero)};
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
        [[nodiscard]] constexpr auto
        criter(size_type const &i) const noexcept -> const_reverse_iterator_type
        {
            constexpr safe_uintmax one{static_cast<bsl::uintmax>(1)};
            constexpr safe_uintmax zero{static_cast<bsl::uintmax>(0)};

            if (unlikely(!i)) {
                unlikely_invalid_argument_failure();
                return const_reverse_iterator_type{this->iter(zero)};
            }

            if (likely(i < m_count)) {
                return const_reverse_iterator_type{this->iter(i + one)};
            }

            return const_reverse_iterator_type{this->iter(zero)};
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
            return this->size().is_zero();
        }

        /// <!-- description -->
        ///   @brief Returns data() != nullptr;
        ///   @include basic_string_view/example_basic_string_view_operator_bool.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns data() != nullptr;
        ///
        [[nodiscard]] explicit constexpr operator bool() const noexcept
        {
            return this->data() != nullptr;
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
            return this->size();
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
            constexpr safe_uintmax size_of_chart{static_cast<bsl::uintmax>(sizeof(CHAR_T))};
            return size_type::max() / size_of_chart;
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
            constexpr safe_uintmax size_of_chart{static_cast<bsl::uintmax>(sizeof(CHAR_T))};
            return m_count * size_of_chart;
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
        remove_prefix(size_type const &n) noexcept -> basic_string_view &
        {
            if (unlikely(!n)) {
                unlikely_invalid_argument_failure();
                *this = basic_string_view{};
                return *this;
            }

            if (likely(n < this->size())) {
                *this = basic_string_view{this->at_if(n), this->size() - n};
                return *this;
            }

            *this = basic_string_view{};
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
        remove_suffix(size_type const &n) noexcept -> basic_string_view &
        {
            if (unlikely(!n)) {
                unlikely_invalid_argument_failure();
                *this = basic_string_view{};
                return *this;
            }

            if (likely(n < this->size())) {
                *this = basic_string_view{this->front_if(), this->size() - n};
                return *this;
            }

            *this = basic_string_view{};
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
        substr(size_type const &pos = {}, size_type const &count = npos) const noexcept
            -> basic_string_view
        {
            if (unlikely(!pos)) {
                unlikely_invalid_argument_failure();
                return basic_string_view{};
            }

            if (unlikely(!count)) {
                unlikely_invalid_argument_failure();
                return basic_string_view{};
            }

            if (likely(pos < this->size())) {
                return basic_string_view{this->at_if(pos), count.min(this->size() - pos)};
            }

            return basic_string_view{};
        }

        /// <!-- description -->
        ///   @brief Compares two strings.
        ///   @include basic_string_view/example_basic_string_view_compare.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param str the bsl::basic_string_view to compare with
        ///   @return Returns the same results as std::strncmp
        ///
        [[nodiscard]] constexpr auto
        compare(basic_string_view const &str) const noexcept -> safe_int32
        {
            return TRAITS::compare(this->data(), str.data(), this->size().min(str.size()));
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
        [[nodiscard]] constexpr auto
        compare(                       // --
            size_type const &pos,      // --
            size_type const &count,    // --
            basic_string_view const &str) const noexcept -> safe_int32
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
        [[nodiscard]] constexpr auto
        compare(                             // --
            size_type const &pos1,           // --
            size_type const &count1,         // --
            basic_string_view const &str,    // --
            size_type const &pos2,           // --
            size_type const &count2) const noexcept -> safe_int32
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
        [[nodiscard]] constexpr auto
        compare(pointer_type const str) const noexcept -> safe_int32
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
        [[nodiscard]] constexpr auto
        compare(size_type const &pos, size_type const &count, pointer_type const str) const noexcept
            -> safe_int32
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
        [[nodiscard]] constexpr auto
        compare(                        // --
            size_type const &pos,       // --
            size_type const &count1,    // --
            pointer_type const str,     // --
            size_type const &count2) const noexcept -> safe_int32
        {
            constexpr safe_uintmax zero{static_cast<bsl::uintmax>(0)};
            return this->compare(pos, count1, basic_string_view{str}, zero, count2);
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

            if (this->size() < str.size()) {
                return false;
            }

            return this->compare({}, str.size(), str) == 0;
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

            if (this->size() < str.size()) {
                return false;
            }

            return this->compare(this->size() - str.size(), str.size(), str) == 0;
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
        ///     string. If the string does not occur, bsl::npos is returned.
        ///
        [[nodiscard]] constexpr auto
        find(basic_string_view const &str, size_type const &pos = {}) const noexcept -> size_type
        {
            constexpr safe_uintmax one{static_cast<bsl::uintmax>(1)};

            auto const view{this->substr(pos)};
            if (view.empty()) {
                unlikely_invalid_argument_failure();
                return size_type::failure();
            }

            if (unlikely(str.empty())) {
                unlikely_invalid_argument_failure();
                return size_type::failure();
            }

            if (unlikely(str.length() > view.length())) {
                return npos;
            }

            auto const len{(view.length() - str.length()) + one};
            for (size_type mut_i{}; mut_i < len; ++mut_i) {
                if (view.compare(mut_i, npos, str) == 0) {
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
        find(CHAR_T const ch, size_type const &pos = {}) const noexcept -> size_type
        {
            auto const view{this->substr(pos)};
            if (view.empty()) {
                unlikely_invalid_argument_failure();
                return size_type::failure();
            }

            for (size_type mut_i{}; mut_i < view.length(); ++mut_i) {
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
        find(pointer_type const str, size_type const &pos = {}) const noexcept -> size_type
        {
            return this->find(basic_string_view{str}, pos);
        }

    private:
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
    ///   @tparam CHAR_T the type of characters in the string
    ///   @tparam TRAITS the traits class used to work with the string
    ///   @param lhs the left hand side of the operation
    ///   @param rhs the right hand side of the operation
    ///   @return Returns true if two strings have the same length (which is
    ///     different from compare() which uses the minimum size between the
    ///     two provided strings), and contain the same characters. Returns
    ///     false otherwise.
    ///
    template<typename CHAR_T, typename TRAITS>
    [[nodiscard]] constexpr auto
    operator==(
        bsl::basic_string_view<CHAR_T, TRAITS> const &lhs,
        bsl::basic_string_view<CHAR_T, TRAITS> const &rhs) noexcept -> bool
    {
        if (lhs.size() != rhs.size()) {
            return false;
        }

        if (lhs.empty()) {
            return rhs.empty();
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
    ///   @tparam CHAR_T the type of characters in the string
    ///   @tparam TRAITS the traits class used to work with the string
    ///   @param lhs the left hand side of the operation
    ///   @param rhs the right hand side of the operation
    ///   @return Returns true if two strings have the same length (which is
    ///     different from compare() which uses the minimum size between the
    ///     two provided strings), and contain the same characters. Returns
    ///     false otherwise.
    ///
    template<typename CHAR_T, typename TRAITS>
    [[nodiscard]] constexpr auto
    operator==(bsl::basic_string_view<CHAR_T, TRAITS> const &lhs, CHAR_T const *const rhs) noexcept
        -> bool
    {
        if (nullptr == rhs) {
            return !lhs;
        }

        return lhs == bsl::basic_string_view<CHAR_T, TRAITS>{rhs};
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
    ///   @tparam CHAR_T the type of characters in the string
    ///   @tparam TRAITS the traits class used to work with the string
    ///   @param lhs the left hand side of the operation
    ///   @param rhs the right hand side of the operation
    ///   @return Returns true if two strings have the same length (which is
    ///     different from compare() which uses the minimum size between the
    ///     two provided strings), and contain the same characters. Returns
    ///     false otherwise.
    ///
    template<typename CHAR_T, typename TRAITS>
    [[nodiscard]] constexpr auto
    operator==(CHAR_T const *const lhs, bsl::basic_string_view<CHAR_T, TRAITS> const &rhs) noexcept
        -> bool
    {
        if (nullptr == lhs) {
            return !rhs;
        }

        return bsl::basic_string_view<CHAR_T, TRAITS>{lhs} == rhs;
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
    ///   @tparam CHAR_T the type of characters in the string
    ///   @tparam TRAITS the traits class used to work with the string
    ///   @param lhs the left hand side of the operation
    ///   @param rhs the right hand side of the operation
    ///   @return Returns true if two strings are not the same length (which is
    ///     different from compare() which uses the minimum size between the
    ///     two provided strings), or contain different characters. Returns
    ///     false otherwise.
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
    ///   @brief Returns true if two strings are not the same length (which is
    ///     different from compare() which uses the minimum size between the
    ///     two provided strings), or contain different characters. Returns
    ///     false otherwise.
    ///   @include basic_string_view/example_basic_string_view_not_equals.hpp
    ///   @related bsl::basic_string_view
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam CHAR_T the type of characters in the string
    ///   @tparam TRAITS the traits class used to work with the string
    ///   @param lhs the left hand side of the operation
    ///   @param rhs the right hand side of the operation
    ///   @return Returns true if two strings are not the same length (which is
    ///     different from compare() which uses the minimum size between the
    ///     two provided strings), or contain different characters. Returns
    ///     false otherwise.
    ///
    template<typename CHAR_T, typename TRAITS>
    [[nodiscard]] constexpr auto
    operator!=(bsl::basic_string_view<CHAR_T, TRAITS> const &lhs, CHAR_T const *const rhs) noexcept
        -> bool
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
    ///   @tparam CHAR_T the type of characters in the string
    ///   @tparam TRAITS the traits class used to work with the string
    ///   @param lhs the left hand side of the operation
    ///   @param rhs the right hand side of the operation
    ///   @return Returns true if two strings are not the same length (which is
    ///     different from compare() which uses the minimum size between the
    ///     two provided strings), or contain different characters. Returns
    ///     false otherwise.
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
