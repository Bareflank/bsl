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

#include "bsl/array.hpp"
#include "bsl/carray.hpp"
#include "bsl/char_type.hpp"
#include "bsl/contiguous_iterator.hpp"    // IWYU pragma: export
#include "bsl/details/out.hpp"
#include "bsl/ensures.hpp"
#include "bsl/expects.hpp"
#include "bsl/is_constant_evaluated.hpp"
#include "bsl/is_pod.hpp"
#include "bsl/is_same.hpp"
#include "bsl/reverse_iterator.hpp"    // IWYU pragma: export
#include "bsl/safe_idx.hpp"
#include "bsl/safe_integral.hpp"
#include "bsl/touch.hpp"
#include "bsl/unlikely.hpp"

namespace bsl
{
    namespace details
    {
        /// @brief defined the expected size of the pt_t struct
        constexpr bsl::safe_umx EXPECTED_SPAN_SIZE{static_cast<bsl::uintmx>(16)};
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
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-member-init, hicpp-member-init)
    class span final
    {
        static_assert(!is_same<T, char_type>::value, "use bsl::string_view instead");

    public:
        /// @brief alias for: T
        using value_type = T;
        /// @brief alias for: safe_umx
        using size_type = safe_umx;
        /// @brief alias for: safe_umx
        using difference_type = safe_umx;
        /// @brief alias for: safe_idx
        using index_type = safe_idx;
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
        constexpr span() noexcept = default;

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
            expects(nullptr != m_ptr);
            expects(count.is_valid_and_checked());
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
        template<typename U, bsl::uintmx N>
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
        template<typename U, bsl::uintmx N>
        explicit constexpr span(bsl::array<U, N> const &arr) noexcept    // --
            : m_ptr{arr.data()}, m_count{N}
        {}

        /// <!-- description -->
        ///   @brief Creates a span given a a bsl::carray
        ///   @include span/example_span_array_constructor.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam U the array's value type
        ///   @tparam N the size of the array
        ///   @param mut_arr the array being spaned.
        ///
        template<typename U, bsl::uintmx N>
        explicit constexpr span(bsl::carray<U, N> &mut_arr) noexcept    // --
            : m_ptr{mut_arr.data()}, m_count{N}
        {}

        /// <!-- description -->
        ///   @brief Creates a span given a a bsl::carray
        ///   @include span/example_span_array_constructor.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam U the array's value type
        ///   @tparam N the size of the array
        ///   @param arr the array being spaned.
        ///
        template<typename U, bsl::uintmx N>
        explicit constexpr span(bsl::carray<U, N> const &arr) noexcept    // --
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
        at_if(index_type const &index) noexcept -> pointer_type
        {
            expects(index.is_valid());

            if (unlikely(index >= m_count)) {
                return nullptr;
            }

            return &m_ptr[index.get()];
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
        at_if(index_type const &index) const noexcept -> const_pointer_type
        {
            expects(index.is_valid());

            if (unlikely(index >= m_count)) {
                return nullptr;
            }

            return &m_ptr[index.get()];
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
            return this->at_if({});
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
            return this->at_if({});
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
            if (unlikely(m_count == size_type::magic_0())) {
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
            if (unlikely(m_count == size_type::magic_0())) {
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
            return iterator_type{m_ptr, size_type{m_count}, {}};
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
            return const_iterator_type{m_ptr, size_type{m_count}, {}};
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
            return const_iterator_type{m_ptr, size_type{m_count}, {}};
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
            return iterator_type{m_ptr, size_type{m_count}, index_type{m_count}};
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
            return const_iterator_type{m_ptr, size_type{m_count}, index_type{m_count}};
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
            return const_iterator_type{m_ptr, size_type{m_count}, index_type{m_count}};
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
        ///   @brief Returns data() == nullptr
        ///   @include span/example_span_is_invalid.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns data() == nullptr
        ///
        [[nodiscard]] constexpr auto
        is_invalid() const noexcept -> bool
        {
            return m_ptr == nullptr;
        }

        /// <!-- description -->
        ///   @brief Returns data() != nullptr
        ///   @include span/example_span_is_valid.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns data() != nullptr
        ///
        [[nodiscard]] constexpr auto
        is_valid() const noexcept -> bool
        {
            return m_ptr != nullptr;
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
            // ensures(m_count.is_valid_and_checked());
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
        ///   @include span/example_span_size_bytes.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns size() * sizeof(T)
        ///
        [[nodiscard]] constexpr auto
        size_bytes() const noexcept -> size_type
        {
            auto const val{(size_type{m_count} * sizeof(T)).checked()};

            /// NOTE:
            /// - An error is not possible because the denominator is
            ///   always positive, so the result of size_bytes() is marked
            ///   as checked.
            ///

            ensures(val.is_valid_and_checked());
            return val;
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
        first(size_type const &count = size_type::max_value()) const noexcept -> span<T>
        {
            expects(count.is_valid_and_checked());
            return this->subspan({}, count);
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
        last(size_type const &count = size_type::max_value()) const noexcept -> span<T>
        {
            expects(count.is_valid_and_checked());

            if (unlikely(count >= this->size())) {
                return this->subspan({}, count);
            }

            /// NOTE:
            /// - Since we validate that count must be <= size(), the math
            ///   below cannot underflow and therefore is marked as checked.
            ///

            safe_idx const pos{(this->size() - count).checked().get()};
            return this->subspan(pos, count);
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
        subspan(index_type const &pos, size_type const &count = size_type::max_value())
            const noexcept -> span
        {
            expects(pos.is_valid());
            expects(count.is_valid_and_checked());

            if (unlikely(pos >= m_count)) {
                return {};
            }

            /// NOTE:
            /// - This function's contract allows for pos to be large. As a
            ///   result we check for overflow above and return early, which
            ///   means that the math below cannot overflow so we mark it
            ///   as checked.
            ///

            auto const adjusted_count{(size_type{m_count} - pos.get()).checked()};
            return span{&m_ptr[pos.get()], count.min(adjusted_count)};
        }

    private:
        /// @brief stores a pointer to the array being viewed
        pointer_type m_ptr;
        /// @brief stores the number of elements in the array being viewed
        bsl::uint64 m_count;
    };

    /// @brief make sure that the span is the size that we expect.
    static_assert(sizeof(span<bool>) == details::EXPECTED_SPAN_SIZE);
    /// @brief make sure that the span is a POD type
    static_assert(is_pod<span<bool>>::value);

    /// <!-- description -->
    ///   @brief Creates user-defined deduction guide for U *
    ///
    template<typename U>
    span(U *, bsl::safe_umx const &) -> span<U>;

    /// <!-- description -->
    ///   @brief Creates user-defined deduction guide for U const *
    ///
    template<typename U>
    span(U const *, bsl::safe_umx const &) -> span<U const>;

    /// <!-- description -->
    ///   @brief Creates user-defined deduction guide for bsl::array
    ///
    template<typename U, bsl::uintmx N>
    span(bsl::array<U, N> &) -> span<U>;

    /// <!-- description -->
    ///   @brief Creates user-defined deduction guide for bsl::array
    ///
    template<typename U, bsl::uintmx N>
    span(bsl::array<U, N> const &) -> span<U const>;

    /// <!-- description -->
    ///   @brief Creates user-defined deduction guide for bsl::carray
    ///
    template<typename U, bsl::uintmx N>
    span(bsl::carray<U, N> &) -> span<U>;

    /// <!-- description -->
    ///   @brief Creates user-defined deduction guide for bsl::carray
    ///
    template<typename U, bsl::uintmx N>
    span(bsl::carray<U, N> const &) -> span<U const>;

    /// <!-- description -->
    ///   @brief Returns true if two spans have the same size and contain
    ///     the same contents. Returns false otherwise.
    ///   @include span/example_span_equals.hpp
    ///   @related bsl::span
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of elements in the span
    ///   @param mut_lhs the left hand side of the operation
    ///   @param mut_rhs the right hand side of the operation
    ///   @return Returns true if two spans have the same size and contain
    ///     the same contents. Returns false otherwise.
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    operator==(span<T> &mut_lhs, span<T> &mut_rhs) noexcept -> bool
    {
        if (mut_lhs.size() != mut_rhs.size()) {
            return false;
        }

        for (safe_idx mut_i{}; mut_i < mut_lhs.size(); ++mut_i) {
            if (*mut_lhs.at_if(mut_i) != *mut_rhs.at_if(mut_i)) {
                return false;
            }

            bsl::touch();
        }

        return true;
    }

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

        for (safe_idx mut_i{}; mut_i < lhs.size(); ++mut_i) {
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
    ///   @param mut_lhs the left hand side of the operation
    ///   @param mut_rhs the right hand side of the operation
    ///   @return Returns true if two spans have the same size and contain
    ///     the same contents. Returns false otherwise.
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    operator!=(span<T> &mut_lhs, span<T> &mut_rhs) noexcept -> bool
    {
        return !(mut_lhs == mut_rhs);
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
    ///   @param mut_val the span to output
    ///   @return return o
    ///
    template<typename T1, typename T2>
    [[maybe_unused]] constexpr auto
    operator<<(out<T1> const o, bsl::span<T2> &mut_val) noexcept -> out<T1>
    {
        if (is_constant_evaluated()) {
            return o;
        }

        if constexpr (o.empty()) {
            return o;
        }

        if (mut_val.empty()) {
            return o << "[]";
        }

        for (safe_idx mut_i{}; mut_i < mut_val.size(); ++mut_i) {
            if (mut_i.is_zero()) {
                o << "[" << *mut_val.at_if(mut_i);
            }
            else {
                o << ", " << *mut_val.at_if(mut_i);
            }
        }

        return o << ']';
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

        if constexpr (o.empty()) {
            return o;
        }

        if (val.empty()) {
            return o << "[]";
        }

        for (safe_idx mut_i{}; mut_i < val.size(); ++mut_i) {
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
