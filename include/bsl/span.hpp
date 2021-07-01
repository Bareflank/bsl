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

#include "array.hpp"
#include "char_type.hpp"
#include "contiguous_iterator.hpp"
#include "details/out.hpp"
#include "is_constant_evaluated.hpp"
#include "is_same.hpp"
#include "is_standard_layout.hpp"
#include "npos.hpp"
#include "reverse_iterator.hpp"
#include "safe_integral.hpp"
#include "touch.hpp"
#include "unlikely.hpp"

namespace bsl
{
    namespace details
    {
        /// @brief defined the expected size of the pt_t struct
        constexpr bsl::safe_uintmax EXPECTED_SPAN_SIZE{static_cast<bsl::uintmax>(16)};
    }

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
    ///     - A bsl::span is always a dynamic_extent type. The reason the
    ///       dynamic_extent type exists in a std::span is to optimize away
    ///       the need to store the size of the array the span is viewing.
    ///       This is only useful for C style arrays which are not supported
    ///       as they are not compliant with AUTOSAR. If you need a C style
    ///       array, use a bsl::array, in which case you have no need for a
    ///       bsl::span. Instead, a bsl::span is useful when you have an
    ///       array in memory that is not in your control (for example, a
    ///       device's memory).
    ///     - In addition to the above, a bsl::span is a standard layout and
    ///       can be used to interface with C structs.
    ///
    ///   @include example_span_overview.hpp
    ///
    /// <!-- template parameters -->
    ///   @tparam T the type of element being viewed.
    ///
    template<typename T>
    class span final
    {
        static_assert(!is_same<T, char_type>::value, "use bsl::string_view instead");

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
        ///   @brief Default constructor.
        ///   @include span/example_span_default_constructor.hpp
        ///
        constexpr span() noexcept    // --
            : m_ptr{}, m_count{}
        {
            static_assert(sizeof(span<T>) == details::EXPECTED_SPAN_SIZE);
            static_assert(is_standard_layout<span<T>>::value);
        }

        /// <!-- description -->
        ///   @brief Creates a span given a pointer to an array, and the
        ///     number of elements in the array. Note that the array must be
        ///     contiguous in memory and [ptr, ptr + count) must be a valid
        ///     range.
        ///   @include span/example_span_ptr_count_constructor.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param pudm_ptr a pointer to the array being spaned.
        ///   @param count the number of elements in the array being spaned.
        ///
        constexpr span(pointer_type const pudm_ptr, size_type const &count) noexcept    // --
            : m_ptr{pudm_ptr}, m_count{count.get()}
        {
            static_assert(sizeof(span<T>) == details::EXPECTED_SPAN_SIZE);
            static_assert(is_standard_layout<span<T>>::value);

            if (unlikely(nullptr == m_ptr)) {
                unlikely_invalid_argument_failure();
                *this = span{};
                return;
            }

            if (unlikely(!count)) {
                unlikely_invalid_argument_failure();
                *this = span{};
                return;
            }

            if (unlikely(count.is_zero())) {
                *this = span{};
                return;
            }

            bsl::touch();
        }

        /// <!-- description -->
        ///   @brief Creates a span given a a bsl::array
        ///   @include span/example_span_array_constructor.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam U the array's value type
        ///   @tparam N the size of the array
        ///   @param mut_arr the array being spaned.
        ///
        template<typename U, bsl::uintmax N>
        explicit constexpr span(bsl::array<U, N> &mut_arr) noexcept    // --
            : m_ptr{mut_arr.data()}, m_count{N}
        {}

        /// <!-- description -->
        ///   @brief Creates a span given a a bsl::array
        ///   @include span/example_span_array_constructor.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam U the array's value type
        ///   @tparam N the size of the array
        ///   @param arr the array being spaned.
        ///
        template<typename U, bsl::uintmax N>
        explicit constexpr span(bsl::array<U, N> const &arr) noexcept    // --
            : m_ptr{arr.data()}, m_count{N}
        {}

        /// <!-- description -->
        ///   @brief Destroyes a previously created bsl::span
        ///
        constexpr ~span() noexcept = default;

        /// <!-- description -->
        ///   @brief copy constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///
        constexpr span(span const &o) noexcept = default;

        /// <!-- description -->
        ///   @brief move constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_o the object being moved
        ///
        constexpr span(span &&mut_o) noexcept = default;

        /// <!-- description -->
        ///   @brief copy assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr auto operator=(span const &o) &noexcept -> span & = default;

        /// <!-- description -->
        ///   @brief move assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_o the object being moved
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr auto operator=(span &&mut_o) &noexcept -> span & = default;

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
        ///   @include span/example_span_at_if.hpp
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
        ///   @include span/example_span_front_if.hpp
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
        ///   @include span/example_span_front_if.hpp
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
        ///   @include span/example_span_back_if.hpp
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

            if (m_count == zero) {
                return nullptr;
            }

            return this->at_if(m_count - one);
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
        [[nodiscard]] constexpr auto
        back_if() const noexcept -> const_pointer_type
        {
            constexpr safe_uintmax one{static_cast<bsl::uintmax>(1)};
            constexpr safe_uintmax zero{static_cast<bsl::uintmax>(0)};

            if (m_count == zero) {
                return nullptr;
            }

            return this->at_if(m_count - one);
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
        [[nodiscard]] constexpr auto
        data() noexcept -> pointer_type
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
        [[nodiscard]] constexpr auto
        data() const noexcept -> const_pointer_type
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
        [[nodiscard]] constexpr auto
        begin() noexcept -> iterator_type
        {
            constexpr safe_uintmax zero{static_cast<bsl::uintmax>(0)};
            return iterator_type{m_ptr, safe_uintmax{m_count}, zero};
        }

        /// <!-- description -->
        ///   @brief Returns an iterator to the first element of the view.
        ///   @include span/example_span_begin.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns an iterator to the first element of the view.
        ///
        [[nodiscard]] constexpr auto
        begin() const noexcept -> const_iterator_type
        {
            constexpr safe_uintmax zero{static_cast<bsl::uintmax>(0)};
            return const_iterator_type{m_ptr, safe_uintmax{m_count}, zero};
        }

        /// <!-- description -->
        ///   @brief Returns an iterator to the first element of the view.
        ///   @include span/example_span_begin.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns an iterator to the first element of the view.
        ///
        [[nodiscard]] constexpr auto
        cbegin() const noexcept -> const_iterator_type
        {
            constexpr safe_uintmax zero{static_cast<bsl::uintmax>(0)};
            return const_iterator_type{m_ptr, safe_uintmax{m_count}, zero};
        }

        /// <!-- description -->
        ///   @brief Returns an iterator to the element "i" in the view.
        ///   @include span/example_span_iter.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param i the element in the array to return an iterator for.
        ///   @return Returns an iterator to the element "i" in the view.
        ///
        [[nodiscard]] constexpr auto
        iter(size_type const &i) noexcept -> iterator_type
        {
            return iterator_type{m_ptr, safe_uintmax{m_count}, i};
        }

        /// <!-- description -->
        ///   @brief Returns an iterator to the element "i" in the view.
        ///   @include span/example_span_iter.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param i the element in the array to return an iterator for.
        ///   @return Returns an iterator to the element "i" in the view.
        ///
        [[nodiscard]] constexpr auto
        iter(size_type const &i) const noexcept -> const_iterator_type
        {
            return const_iterator_type{m_ptr, safe_uintmax{m_count}, i};
        }

        /// <!-- description -->
        ///   @brief Returns an iterator to the element "i" in the view.
        ///   @include span/example_span_iter.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param i the element in the array to return an iterator for.
        ///   @return Returns an iterator to the element "i" in the view.
        ///
        [[nodiscard]] constexpr auto
        citer(size_type const &i) const noexcept -> const_iterator_type
        {
            return const_iterator_type{m_ptr, safe_uintmax{m_count}, i};
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
        [[nodiscard]] constexpr auto
        end() noexcept -> iterator_type
        {
            return iterator_type{m_ptr, safe_uintmax{m_count}, safe_uintmax{m_count}};
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
        [[nodiscard]] constexpr auto
        end() const noexcept -> const_iterator_type
        {
            return const_iterator_type{m_ptr, safe_uintmax{m_count}, safe_uintmax{m_count}};
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
        [[nodiscard]] constexpr auto
        cend() const noexcept -> const_iterator_type
        {
            return const_iterator_type{m_ptr, safe_uintmax{m_count}, safe_uintmax{m_count}};
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
        ///   @include span/example_span_rbegin.hpp
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
        ///   @include span/example_span_rbegin.hpp
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
        ///   @include span/example_span_riter.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param i the element in the array to return an iterator for.
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
        ///   @include span/example_span_riter.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param i the element in the array to return an iterator for.
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
        ///   @include span/example_span_riter.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param i the element in the array to return an iterator for.
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
        ///   @include span/example_span_rend.hpp
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
        ///   @include span/example_span_rend.hpp
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
        ///   @include span/example_span_rend.hpp
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
        ///   @brief Returns size().is_zero()
        ///   @include span/example_span_empty.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns size().is_zero()
        ///
        [[nodiscard]] constexpr auto
        empty() const noexcept -> bool
        {
            return this->size().is_zero();
        }

        /// <!-- description -->
        ///   @brief Returns data() != nullptr
        ///   @include span/example_span_operator_bool.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns data() != nullptr
        ///
        [[nodiscard]] explicit constexpr operator bool() const noexcept
        {
            return this->data() != nullptr;
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
        [[nodiscard]] constexpr auto
        size() const noexcept -> size_type
        {
            return size_type{m_count};
        }

        /// <!-- description -->
        ///   @brief Returns the max number of elements the BSL supports.
        ///   @include span/example_span_max_size.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the max number of elements the BSL supports.
        ///
        [[nodiscard]] static constexpr auto
        max_size() noexcept -> size_type
        {
            constexpr safe_uintmax size_of_t{static_cast<bsl::uintmax>(sizeof(T))};
            return size_type::max() / size_of_t;
        }

        /// <!-- description -->
        ///   @brief Returns size() * sizeof(T)
        ///   @include span/example_span_size_bytes.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns size() * sizeof(T)
        ///
        [[nodiscard]] constexpr auto
        size_bytes() const noexcept -> size_type
        {
            constexpr safe_uintmax size_of_t{static_cast<bsl::uintmax>(sizeof(T))};
            return m_count * size_of_t;
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
        [[nodiscard]] constexpr auto
        first(size_type const &count = npos) const noexcept -> span<T>
        {
            constexpr safe_uintmax zero{static_cast<bsl::uintmax>(0)};
            return this->subspan(zero, count);
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
        [[nodiscard]] constexpr auto
        last(size_type const &count = npos) const noexcept -> span<T>
        {
            if (count < this->size()) {
                return this->subspan(this->size() - count, count);
            }

            constexpr safe_uintmax zero{static_cast<bsl::uintmax>(0)};
            return this->subspan(zero, count);
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
        [[nodiscard]] constexpr auto
        subspan(size_type const &pos, size_type const &count = npos) const noexcept -> span<T>
        {
            if (unlikely(!pos)) {
                unlikely_invalid_argument_failure();
                return {};
            }

            if (unlikely(!count)) {
                unlikely_invalid_argument_failure();
                return {};
            }

            if (likely(pos < m_count)) {
                return span<T>{&m_ptr[pos.get()], count.min(m_count - pos)};
            }

            return {};
        }

    private:
        /// @brief stores a pointer to the array being viewed
        pointer_type m_ptr;
        /// @brief stores the number of elements in the array being viewed
        bsl::uint64 m_count;
    };

    /// <!-- description -->
    ///   @brief Creates user-defined deduction guide for bsl::array
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam U the array's value type
    ///   @tparam N the size of the array
    ///   @param mut_arr the array being spaned.
    ///
    template<typename U, bsl::uintmax N>
    span(bsl::array<U, N> &mut_arr) -> span<U>;

    /// <!-- description -->
    ///   @brief Creates user-defined deduction guide for bsl::array
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam U the array's value type
    ///   @tparam N the size of the array
    ///   @param arr the array being spaned.
    ///
    template<typename U, bsl::uintmax N>
    span(bsl::array<U, N> const &arr) -> span<U const>;

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
    [[nodiscard]] constexpr auto
    operator==(span<T> const &lhs, span<T> const &rhs) noexcept -> bool
    {
        if (lhs.size() != rhs.size()) {
            return false;
        }

        for (safe_uintmax mut_i{}; mut_i < lhs.size(); ++mut_i) {
            if (*lhs.at_if(mut_i) != *rhs.at_if(mut_i)) {
                return false;
            }

            bsl::touch();
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
    [[nodiscard]] constexpr auto
    operator!=(span<T> const &lhs, span<T> const &rhs) noexcept -> bool
    {
        return !(lhs == rhs);
    }

    /// <!-- description -->
    ///   @brief Outputs the provided bsl::span to the provided
    ///     output type.
    ///   @related bsl::span
    ///   @include span/example_span_ostream.hpp
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T1 the type of outputter provided
    ///   @tparam T2 the type of element being encapsulated.
    ///   @param o the instance of the outputter used to output the value.
    ///   @param val the span to output
    ///   @return return o
    ///
    template<typename T1, typename T2>
    [[maybe_unused]] constexpr auto
    operator<<(out<T1> const o, bsl::span<T2> const &val) noexcept -> out<T1>
    {
        if (is_constant_evaluated()) {
            return o;
        }

        if constexpr (!o) {
            return o;
        }

        if (val.empty()) {
            return o << "[]";
        }

        for (safe_uintmax mut_i{}; mut_i < val.size(); ++mut_i) {
            if (mut_i.is_zero()) {
                o << "[" << *val.at_if(mut_i);
            }
            else {
                o << ", " << *val.at_if(mut_i);
            }
        }

        return o << ']';
    }
}

#endif
