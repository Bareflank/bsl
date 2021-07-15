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
/// @file contiguous_iterator.hpp
///

#ifndef BSL_CONTIGUOUS_ITERATOR_HPP
#define BSL_CONTIGUOUS_ITERATOR_HPP

#include "contiguous_iterator_element.hpp"
#include "safe_integral.hpp"
#include "touch.hpp"
#include "unlikely.hpp"

namespace bsl
{
    /// @class bsl::contiguous_iterator
    ///
    /// <!-- description -->
    ///   @brief Provides a contiguous iterator as defined by the C++
    ///     specification, with the follwing differences:
    ///     - The difference type that we use is unsigned instead of a
    ///       signed type, which causes a lot of problems with AUTOSAR
    ///       compliance as signed/unsigned conversions and overflow are a
    ///       huge problem with the standard library. This iterator type is
    ///       used by all of the "view" type containers including the
    ///       bsl::span, bsl::array and bsl::string_view
    ///     - We do not provide any of the *, -> or [] accessors as none of
    ///       these accessors are compliant with AUTOSAR. Instead, we provide
    ///       a get_if() function, which returns a pointer to the element
    ///       being accessed by the iterator, or a nullptr if the iterator is
    ///       invalid or is the same as end(). As a result, ranged based for
    ///       loops are not supported, and instead, use a view's for_each
    ///       function which will perform the same action, with less overhead,
    ///       and better safety.
    ///     - The iterator is always inbounds, equal to end() or is invalid.
    ///       Traditional iterators can be anything, they can overrun,
    ///       underrun, and everyting in between. If this iterator is valid,
    ///       the index is always bounded by the size of the array it is
    ///       pointing to, or is equal to end(). Wrapping, overruns, and
    ///       underruns are not possible.
    ///     - We don't implement all of the iterator functions that make up
    ///       a contiguous iterator as defined by the C++ spec. Some of these
    ///       can be added in future upon request.
    ///   @include example_contiguous_iterator_overview.hpp
    ///
    /// <!-- template parameters -->
    ///   @tparam T the type of element being iterated.
    ///
    template<typename T>
    class contiguous_iterator final
    {
        /// <!-- description -->
        ///   @brief Default constructor that creates a contiguous iterator
        ///     with get_if() == nullptr.
        ///
        constexpr contiguous_iterator() noexcept    // --
            : m_ptr{}, m_count{}, m_i{}
        {}

    public:
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
        ///   @brief Creates a contiguous iterator given a ptr to an array
        ///     and the total number of elements in the array. Note that you
        ///     should not use this directly but instead, should use the
        ///     container's begin() function.
        ///
        /// <!-- inputs/outputs -->
        ///   @param pudm_cst_ptr a pointer to the array being iterated
        ///   @param count the number of elements in the array being iterated
        ///   @param i the initial index of the iterator
        ///
        constexpr contiguous_iterator(          // --
            pointer_type const pudm_cst_ptr,    // --
            size_type const &count,             // --
            size_type const &i) noexcept
            : m_ptr{pudm_cst_ptr}, m_count{count}, m_i{i}
        {
            if (unlikely(nullptr == m_ptr)) {
                *this = contiguous_iterator{};
                return;
            }

            if (unlikely(!count)) {
                unlikely_invalid_argument_failure();
                *this = contiguous_iterator{};
                return;
            }

            if (unlikely(!i)) {
                unlikely_invalid_argument_failure();
                m_i = count;
                return;
            }

            if (unlikely(i > count)) {
                m_i = count;
                return;
            }

            bsl::touch();
        }

        /// <!-- description -->
        ///   @brief Destroyes a previously created bsl::contiguous_iterator
        ///
        constexpr ~contiguous_iterator() noexcept = default;

        /// <!-- description -->
        ///   @brief copy constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///
        constexpr contiguous_iterator(contiguous_iterator const &o) noexcept = default;

        /// <!-- description -->
        ///   @brief move constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_o the object being moved
        ///
        constexpr contiguous_iterator(contiguous_iterator &&mut_o) noexcept = default;

        /// <!-- description -->
        ///   @brief copy assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr auto operator=(contiguous_iterator const &o) &noexcept
            -> contiguous_iterator & = default;

        /// <!-- description -->
        ///   @brief move assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_o the object being moved
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr auto operator=(contiguous_iterator &&mut_o) &noexcept
            -> contiguous_iterator & = default;

        /// <!-- description -->
        ///   @brief Returns a pointer to the array being iterated
        ///   @include contiguous_iterator/example_contiguous_iterator_data.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a pointer to the array being iterated
        ///
        [[nodiscard]] constexpr auto
        data() noexcept -> pointer_type
        {
            return m_ptr;
        }

        /// <!-- description -->
        ///   @brief Returns a pointer to the array being iterated
        ///   @include contiguous_iterator/example_contiguous_iterator_data.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a pointer to the array being iterated
        ///
        [[nodiscard]] constexpr auto
        data() const noexcept -> const_pointer_type
        {
            return m_ptr;
        }

        /// <!-- description -->
        ///   @brief Returns the number of elements in the array being iterated
        ///   @include contiguous_iterator/example_contiguous_iterator_size.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the number of elements in the array being iterated
        ///
        [[nodiscard]] constexpr auto
        size() const noexcept -> size_type const &
        {
            return m_count;
        }

        /// <!-- description -->
        ///   @brief Returns the iterator's current index. If the iterator is
        ///     at the end, this function returns size().
        ///   @include contiguous_iterator/example_contiguous_iterator_index.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the iterator's current index
        ///
        [[nodiscard]] constexpr auto
        index() const noexcept -> size_type const &
        {
            return m_i;
        }

        /// <!-- description -->
        ///   @brief Returns nullptr == data()
        ///   @include contiguous_iterator/example_contiguous_iterator_empty.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns nullptr == data()
        ///
        [[nodiscard]] constexpr auto
        empty() const noexcept -> bool
        {
            return m_count.is_zero();
        }

        /// <!-- description -->
        ///   @brief Returns !is_end()
        ///   @include contiguous_iterator/example_contiguous_iterator_operator_bool.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns !is_end()
        ///
        [[nodiscard]] explicit constexpr operator bool() const noexcept
        {
            return !this->is_end();
        }

        /// <!-- description -->
        ///   @brief Returns index() == size()
        ///   @include contiguous_iterator/example_contiguous_iterator_is_end.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns index() == size()
        ///
        [[nodiscard]] constexpr auto
        is_end() const noexcept -> bool
        {
            return this->index() == this->size();
        }

        /// <!-- description -->
        ///   @brief Returns a pointer to the instance of T stored at the
        ///     iterator's current index. If the index is out of bounds,
        ///     or the iterator is invalid, this function returns a nullptr.
        ///   @include contiguous_iterator/example_contiguous_iterator_get_if.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a pointer to the instance of T stored at the
        ///     iterator's current index. If the index is out of bounds,
        ///     or the iterator is invalid, this function returns a nullptr.
        ///
        [[nodiscard]] constexpr auto
        get_if() noexcept -> pointer_type
        {
            if (unlikely(nullptr == m_ptr)) {
                return nullptr;
            }

            if (unlikely(m_i == m_count)) {
                return nullptr;
            }

            return &m_ptr[m_i.get()];
        }

        /// <!-- description -->
        ///   @brief Returns a pointer to the instance of T stored at the
        ///     iterator's current index. If the index is out of bounds,
        ///     or the iterator is invalid, this function returns a nullptr.
        ///   @include contiguous_iterator/example_contiguous_iterator_get_if.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a pointer to the instance of T stored at the
        ///     iterator's current index. If the index is out of bounds,
        ///     or the iterator is invalid, this function returns a nullptr.
        ///
        [[nodiscard]] constexpr auto
        get_if() const noexcept -> const_pointer_type
        {
            if (unlikely(nullptr == m_ptr)) {
                return nullptr;
            }

            if (unlikely(m_i == m_count)) {
                return nullptr;
            }

            return &m_ptr[m_i.get()];
        }

        /// <!-- description -->
        ///   @brief Returns contiguous_iterator_element<value_type>{data(), index()};
        ///   @include contiguous_iterator/example_contiguous_iterator_operator_star.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns contiguous_iterator_element<value_type>{data(), index()};
        ///
        [[nodiscard]] constexpr auto
        operator*() noexcept -> contiguous_iterator_element<value_type>
        {
            return {this->get_if(), this->index()};
        }

        /// <!-- description -->
        ///   @brief Returns contiguous_iterator_element<value_type>{data(), index()};
        ///   @include contiguous_iterator/example_contiguous_iterator_operator_star.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns contiguous_iterator_element<value_type>{data(), index()};
        ///
        [[nodiscard]] constexpr auto
        operator*() const noexcept -> contiguous_iterator_element<value_type const>
        {
            return {this->get_if(), this->index()};
        }

        /// <!-- description -->
        ///   @brief Increments the iterator
        ///   @include contiguous_iterator/example_contiguous_iterator_increment.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return returns *this
        ///
        [[maybe_unused]] constexpr auto
        operator++() noexcept -> contiguous_iterator &
        {
            if (unlikely(nullptr == m_ptr)) {
                return *this;
            }

            if (unlikely(m_count == m_i)) {
                return *this;
            }

            ++m_i;
            return *this;
        }

        /// <!-- description -->
        ///   @brief Decrements the iterator
        ///   @include contiguous_iterator/example_contiguous_iterator_decrement.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return returns *this
        ///
        [[maybe_unused]] constexpr auto
        operator--() noexcept -> contiguous_iterator &
        {
            if (unlikely(nullptr == m_ptr)) {
                return *this;
            }

            if (unlikely(m_i.is_zero())) {
                return *this;
            }

            --m_i;
            return *this;
        }

    private:
        /// @brief stores a pointer to the array being iterated
        pointer_type m_ptr;
        /// @brief stores the number of elements in the array being iterated
        size_type m_count;
        /// @brief stores the current index in the array being iterated
        size_type m_i;
    };

    /// <!-- description -->
    ///   @brief Returns true if the provided contiguous iterators point to
    ///     the same array and the same index.
    ///   @include contiguous_iterator/example_contiguous_iterator_equals.hpp
    ///   @related bsl::contiguous_iterator
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of element being iterated.
    ///   @param lhs the left hand side of the operation
    ///   @param rhs the rhs hand side of the operation
    ///   @return Returns true if the provided contiguous iterators point to
    ///     the same array and the same index.
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    operator==(contiguous_iterator<T> const &lhs, contiguous_iterator<T> const &rhs) noexcept
        -> bool
    {
        if (lhs.data() == rhs.data()) {
            if (lhs.index() == rhs.index()) {
                return true;
            }

            bsl::touch();
        }
        else {
            bsl::touch();
        }

        return false;
    }

    /// <!-- description -->
    ///   @brief Returns true if the provided contiguous iterators do not point
    ///     to the same array or the same index.
    ///   @include contiguous_iterator/example_contiguous_iterator_not_equals.hpp
    ///   @related bsl::contiguous_iterator
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of element being iterated.
    ///   @param lhs the left hand side of the operation
    ///   @param rhs the rhs hand side of the operation
    ///   @return Returns true if the provided contiguous iterators do not point
    ///     to the same array or the same index.
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    operator!=(contiguous_iterator<T> const &lhs, contiguous_iterator<T> const &rhs) noexcept
        -> bool
    {
        return !(lhs == rhs);
    }

    /// <!-- description -->
    ///   @brief Returns lhs.index() < rhs.index()
    ///   @include contiguous_iterator/example_contiguous_iterator_lt.hpp
    ///   @related bsl::contiguous_iterator
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of element being iterated.
    ///   @param lhs the left hand side of the operation
    ///   @param rhs the rhs hand side of the operation
    ///   @return Returns lhs.index() < rhs.index()
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    operator<(contiguous_iterator<T> const &lhs, contiguous_iterator<T> const &rhs) noexcept -> bool
    {
        return lhs.index() < rhs.index();
    }

    /// <!-- description -->
    ///   @brief Returns lhs.index() > rhs.index()
    ///   @include contiguous_iterator/example_contiguous_iterator_gt.hpp
    ///   @related bsl::contiguous_iterator
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of element being iterated.
    ///   @param lhs the left hand side of the operation
    ///   @param rhs the rhs hand side of the operation
    ///   @return Returns lhs.index() > rhs.index()
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    operator>(contiguous_iterator<T> const &lhs, contiguous_iterator<T> const &rhs) noexcept -> bool
    {
        return lhs.index() > rhs.index();
    }
}

#endif
