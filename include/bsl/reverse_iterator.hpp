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
/// @file reverse_iterator.hpp
///

#ifndef BSL_REVERSE_ITERATOR_HPP
#define BSL_REVERSE_ITERATOR_HPP

#include "safe_integral.hpp"
#include "unlikely.hpp"

namespace bsl
{
    /// @class bsl::reverse_iterator
    ///
    /// <!-- description -->
    ///   @brief Provides a reverse iterator as defined by the C++
    ///     specification, with the follwing differences:
    ///     - The difference type that we use is a unsigned instead of a
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
    ///     - We do not provide the protected member "current" as this class
    ///       cannot be subclassed.
    ///     - We don't implement all of the iterator functions that make up
    ///       a contiguous iterator as defined by the C++ spec. Some of these
    ///       can be added in future upon request.
    ///   @include example_reverse_iterator_overview.hpp
    ///
    /// <!-- template parameters -->
    ///   @tparam ITER The type of iterator to reverse
    ///
    template<typename ITER>
    class reverse_iterator final
    {
    public:
        /// @brief alias for: typename ITER::value_type
        using value_type = typename ITER::value_type;
        /// @brief alias for: safe_uintmax
        using size_type = safe_uintmax;
        /// @brief alias for: safe_uintmax
        using difference_type = safe_uintmax;
        /// @brief alias for: typename ITER::value_type &
        using reference_type = typename ITER::value_type &;
        /// @brief alias for: typename ITER::value_type const &
        using const_reference_type = typename ITER::value_type const &;
        /// @brief alias for: typename ITER::value_type *
        using pointer_type = typename ITER::value_type *;
        /// @brief alias for: typename ITER::value_type const *
        using const_pointer_type = typename ITER::value_type const *;

        /// <!-- description -->
        ///   @brief Creates a reverse iterator given a an iterator to reverse.
        ///     It should be noted that you should not call this directly,
        ///     but instead should call rbegin() or rend() for your given
        ///     container.
        ///
        /// <!-- inputs/outputs -->
        ///   @param i the iterator to use
        ///
        explicit constexpr reverse_iterator(ITER const &i) noexcept    // --
            : m_i{i}
        {}

        /// <!-- description -->
        ///   @brief Returns a pointer to the array being iterated
        ///   @include reverse_iterator/example_reverse_iterator_data.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a pointer to the array being iterated
        ///
        [[nodiscard]] constexpr auto
        base() const noexcept -> ITER
        {
            return m_i;
        }

        /// <!-- description -->
        ///   @brief Returns a pointer to the array being iterated
        ///   @include reverse_iterator/example_reverse_iterator_data.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a pointer to the array being iterated
        ///
        [[nodiscard]] constexpr auto
        data() noexcept -> pointer_type
        {
            return m_i.data();
        }

        /// <!-- description -->
        ///   @brief Returns a pointer to the array being iterated
        ///   @include reverse_iterator/example_reverse_iterator_data.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a pointer to the array being iterated
        ///
        [[nodiscard]] constexpr auto
        data() const noexcept -> const_pointer_type
        {
            return m_i.data();
        }

        /// <!-- description -->
        ///   @brief Returns the number of elements in the array being iterated
        ///   @include reverse_iterator/example_reverse_iterator_size.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the number of elements in the array being iterated
        ///
        [[nodiscard]] constexpr auto
        size() const noexcept -> size_type const &
        {
            return m_i.size();
        }

        /// <!-- description -->
        ///   @brief Returns the iterator's current index. If the iterator is
        ///     at the end, this function returns size().
        ///   @include reverse_iterator/example_reverse_iterator_index.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the iterator's current index
        ///
        [[nodiscard]] constexpr auto
        index() const noexcept -> size_type
        {
            if (unlikely(m_i.index().is_zero())) {
                return m_i.size();
            }

            constexpr safe_uintmax one{static_cast<bsl::uintmax>(1)};
            return m_i.index() - one;
        }

        /// <!-- description -->
        ///   @brief Returns nullptr == data()
        ///   @include reverse_iterator/example_reverse_iterator_empty.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns nullptr == data()
        ///
        [[nodiscard]] constexpr auto
        empty() const noexcept -> bool
        {
            return m_i.empty();
        }

        /// <!-- description -->
        ///   @brief Returns !is_end()
        ///   @include reverse_iterator/example_reverse_iterator_operator_bool.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns !is_end()
        ///
        [[nodiscard]] explicit constexpr operator bool() const noexcept
        {
            return !this->is_end();
        }

        /// <!-- description -->
        ///   @brief Returns index() == 0
        ///   @include reverse_iterator/example_reverse_iterator_is_end.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns index() == size()
        ///
        [[nodiscard]] constexpr auto
        is_end() const noexcept -> bool
        {
            return m_i.index().is_zero();
        }

        /// <!-- description -->
        ///   @brief Returns a pointer to the instance of T stored at the
        ///     iterator's current index. If the index is out of bounds,
        ///     or the iterator is invalid, this function returns a nullptr.
        ///   @include reverse_iterator/example_reverse_iterator_get_if.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a pointer to the instance of T stored at the
        ///     iterator's current index. If the index is out of bounds,
        ///     or the iterator is invalid, this function returns a nullptr.
        ///
        [[nodiscard]] constexpr auto
        get_if() noexcept -> pointer_type
        {
            if (unlikely(nullptr == m_i.data())) {
                return nullptr;
            }

            if (unlikely(m_i.index().is_zero())) {
                return nullptr;
            }

            constexpr safe_uintmax one{static_cast<bsl::uintmax>(1)};
            return &m_i.data()[(m_i.index() - one).get()];
        }

        /// <!-- description -->
        ///   @brief Returns a pointer to the instance of T stored at the
        ///     iterator's current index. If the index is out of bounds,
        ///     or the iterator is invalid, this function returns a nullptr.
        ///   @include reverse_iterator/example_reverse_iterator_get_if.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a pointer to the instance of T stored at the
        ///     iterator's current index. If the index is out of bounds,
        ///     or the iterator is invalid, this function returns a nullptr.
        ///
        [[nodiscard]] constexpr auto
        get_if() const noexcept -> const_pointer_type
        {
            if (unlikely(nullptr == m_i.data())) {
                return nullptr;
            }

            if (unlikely(m_i.index().is_zero())) {
                return nullptr;
            }

            constexpr safe_uintmax one{static_cast<bsl::uintmax>(1)};
            return &m_i.data()[(m_i.index() - one).get()];
        }

        /// <!-- description -->
        ///   @brief Increments the iterator
        ///   @include reverse_iterator/example_reverse_iterator_increment.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return returns *this
        ///
        [[maybe_unused]] constexpr auto
        operator++() noexcept -> reverse_iterator &
        {
            --m_i;
            return *this;
        }

        /// <!-- description -->
        ///   @brief Decrements the iterator
        ///   @include reverse_iterator/example_reverse_iterator_decrement.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return returns *this
        ///
        [[maybe_unused]] constexpr auto
        operator--() noexcept -> reverse_iterator &
        {
            ++m_i;
            return *this;
        }

    private:
        /// @brief Stores the iterator being reversed.
        ITER m_i;
    };

    /// <!-- description -->
    ///   @brief Returns lhs.base() == rhs.base()
    ///   @include reverse_iterator/example_reverse_iterator_equals.hpp
    ///   @related bsl::reverse_iterator
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of element being iterated.
    ///   @param lhs the left hand side of the operation
    ///   @param rhs the rhs hand side of the operation
    ///   @return Returns lhs.base() == rhs.base()
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    operator==(reverse_iterator<T> const &lhs, reverse_iterator<T> const &rhs) noexcept -> bool
    {
        return lhs.base() == rhs.base();
    }

    /// <!-- description -->
    ///   @brief Returns lhs.base() != rhs.base()
    ///   @include reverse_iterator/example_reverse_iterator_not_equals.hpp
    ///   @related bsl::reverse_iterator
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of element being iterated.
    ///   @param lhs the left hand side of the operation
    ///   @param rhs the rhs hand side of the operation
    ///   @return Returns lhs.base() != rhs.base()
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    operator!=(reverse_iterator<T> const &lhs, reverse_iterator<T> const &rhs) noexcept -> bool
    {
        return !(lhs == rhs);
    }

    /// <!-- description -->
    ///   @brief Returns lhs.base() < rhs.base()
    ///   @include reverse_iterator/example_reverse_iterator_lt.hpp
    ///   @related bsl::reverse_iterator
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of element being iterated.
    ///   @param lhs the left hand side of the operation
    ///   @param rhs the rhs hand side of the operation
    ///   @return Returns lhs.base() < rhs.base()
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    operator<(reverse_iterator<T> const &lhs, reverse_iterator<T> const &rhs) noexcept -> bool
    {
        return lhs.base() > rhs.base();
    }

    /// <!-- description -->
    ///   @brief Returns lhs.base() > rhs.base()
    ///   @include reverse_iterator/example_reverse_iterator_gt.hpp
    ///   @related bsl::reverse_iterator
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of element being iterated.
    ///   @param lhs the left hand side of the operation
    ///   @param rhs the rhs hand side of the operation
    ///   @return Returns lhs.base() > rhs.base()
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    operator>(reverse_iterator<T> const &lhs, reverse_iterator<T> const &rhs) noexcept -> bool
    {
        return lhs.base() < rhs.base();
    }

    /// <!-- description -->
    ///   @brief Constructs a reverse_iterator for a given provided iterator.
    ///   @related bsl::reverse_iterator
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam ITER the type of iterator to make the reverse iterator from.
    ///   @param i the iterator to make the reverse iterator from.
    ///   @return a newly constructed reverse iterator.
    ///
    template<typename ITER>
    [[nodiscard]] constexpr auto
    make_reverse_iterator(ITER const &i) noexcept -> reverse_iterator<ITER>
    {
        return {i};
    }
}

#endif
