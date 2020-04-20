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

#include "convert.hpp"
#include "debug.hpp"
#include "safe_integral.hpp"

// TODO
// - We need to implement the remianing functions that are part of the
//   reverse iterator specification. Specifically, the increment and
//   decrement by "n" functions as they all require the safe_int class
//   to be effective at preventing wrapping, overruns and underruns.
//   Currently we only support the ++/-- functions as those are simple
//   to implement without the need for safe_int. Also note that we would
//   need some extra logic to ensure the iterator stays in-bounds.
//

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
    ///   @tparam Iter The type of iterator to reverse
    ///
    template<typename Iter>
    class reverse_iterator final
    {
    public:
        /// @brief alias for: typename Iter::value_type
        using value_type = typename Iter::value_type;
        /// @brief alias for: safe_uintmax
        using size_type = safe_uintmax;
        /// @brief alias for: safe_uintmax
        using difference_type = safe_uintmax;
        /// @brief alias for: typename Iter::value_type &
        using reference_type = typename Iter::value_type &;
        /// @brief alias for: typename Iter::value_type const &
        using const_reference_type = typename Iter::value_type const &;
        /// @brief alias for: typename Iter::value_type *
        using pointer_type = typename Iter::value_type *;
        /// @brief alias for: typename Iter::value_type const *
        using const_pointer_type = typename Iter::value_type const *;

        /// <!-- description -->
        ///   @brief Creates a reverse iterator given a an iterator to reverse.
        ///     It should be noted that you should not call this directly,
        ///     but instead should call rbegin() or rend() for your given
        ///     container.
        ///
        /// <!-- inputs/outputs -->
        ///   @param i the iterator to use
        ///
        explicit constexpr reverse_iterator(Iter const &i) noexcept    // --
            : m_i{i}
        {}

        /// <!-- description -->
        ///   @brief Returns a pointer to the array being iterated
        ///   @include reverse_iterator/example_reverse_iterator_data.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a pointer to the array being iterated
        ///
        [[nodiscard]] constexpr Iter
        base() const noexcept
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
        [[nodiscard]] constexpr pointer_type
        data() noexcept
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
        [[nodiscard]] constexpr const_pointer_type
        data() const noexcept
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
        [[nodiscard]] constexpr size_type
        size() const noexcept
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
        [[nodiscard]] constexpr size_type
        index() const noexcept
        {
            if (m_i.index().is_zero()) {
                return m_i.size();
            }

            return m_i.index() - to_umax(1);
        }

        /// <!-- description -->
        ///   @brief Returns nullptr == data()
        ///   @include reverse_iterator/example_reverse_iterator_empty.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns nullptr == data()
        ///
        [[nodiscard]] constexpr bool
        empty() const noexcept
        {
            return m_i.empty();
        }

        /// <!-- description -->
        ///   @brief Returns index() == 0
        ///   @include reverse_iterator/example_reverse_iterator_is_end.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns index() == size()
        ///
        [[nodiscard]] constexpr bool
        is_end() const noexcept
        {
            return m_i.index().is_zero();
        }

        /// <!-- description -->
        ///   @brief Returns a pointer to the instance of T stored at the
        ///     iterator's current index. If the index is out of bounds,
        ///     or the iterator is invalid, this function returns a nullptr.
        ///   @include reverse_iterator/example_reverse_iterator_get_if.hpp
        ///
        ///   SUPPRESSION: PRQA 4024 - false positive
        ///   - We suppress this because A9-3-1 states that pointer we should
        ///     not provide a non-const reference or pointer to private
        ///     member function, unless the class mimics a smart pointer or
        ///     a containter. This class mimics a container.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a pointer to the instance of T stored at the
        ///     iterator's current index. If the index is out of bounds,
        ///     or the iterator is invalid, this function returns a nullptr.
        ///
        [[nodiscard]] constexpr pointer_type
        get_if() noexcept
        {
            if (nullptr == m_i.data()) {
                bsl::error() << "reverse_iterator: null iterator\n";
                return nullptr;
            }

            if (m_i.index().is_zero()) {
                bsl::error() << "reverse_iterator: attempt to get value from end() iterator\n";
                return nullptr;
            }

            return &m_i.data()[(m_i.index() - to_umax(1)).get()];    // PRQA S 4024 // NOLINT
        }

        /// <!-- description -->
        ///   @brief Returns a pointer to the instance of T stored at the
        ///     iterator's current index. If the index is out of bounds,
        ///     or the iterator is invalid, this function returns a nullptr.
        ///   @include reverse_iterator/example_reverse_iterator_get_if.hpp
        ///
        ///   SUPPRESSION: PRQA 4024 - false positive
        ///   - We suppress this because A9-3-1 states that pointer we should
        ///     not provide a non-const reference or pointer to private
        ///     member function, unless the class mimics a smart pointer or
        ///     a containter. This class mimics a container.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a pointer to the instance of T stored at the
        ///     iterator's current index. If the index is out of bounds,
        ///     or the iterator is invalid, this function returns a nullptr.
        ///
        [[nodiscard]] constexpr const_pointer_type
        get_if() const noexcept
        {
            if (nullptr == m_i.data()) {
                bsl::error() << "reverse_iterator: null iterator\n";
                return nullptr;
            }

            if (m_i.index().is_zero()) {
                bsl::error() << "reverse_iterator: attempt to get value from end() iterator\n";
                return nullptr;
            }

            return &m_i.data()[(m_i.index() - to_umax(1)).get()];    // PRQA S 4024 // NOLINT
        }

        /// <!-- description -->
        ///   @brief Increments the iterator
        ///   @include reverse_iterator/example_reverse_iterator_increment.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return returns *this
        ///
        [[maybe_unused]] constexpr reverse_iterator &
        operator++() noexcept
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
        [[maybe_unused]] constexpr reverse_iterator &
        operator--() noexcept
        {
            ++m_i;
            return *this;
        }

    private:
        /// @brief Stores the iterator being reversed.
        Iter m_i;
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
    [[nodiscard]] constexpr bool
    operator==(reverse_iterator<T> const &lhs, reverse_iterator<T> const &rhs) noexcept
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
    [[nodiscard]] constexpr bool
    operator!=(reverse_iterator<T> const &lhs, reverse_iterator<T> const &rhs) noexcept
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
    [[nodiscard]] constexpr bool
    operator<(reverse_iterator<T> const &lhs, reverse_iterator<T> const &rhs) noexcept
    {
        return lhs.base() > rhs.base();
    }

    /// <!-- description -->
    ///   @brief Returns lhs.base() <= rhs.base()
    ///   @include reverse_iterator/example_reverse_iterator_lt_equals.hpp
    ///   @related bsl::reverse_iterator
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of element being iterated.
    ///   @param lhs the left hand side of the operation
    ///   @param rhs the rhs hand side of the operation
    ///   @return Returns lhs.base() <= rhs.base()
    ///
    template<typename T>
    [[nodiscard]] constexpr bool
    operator<=(reverse_iterator<T> const &lhs, reverse_iterator<T> const &rhs) noexcept
    {
        return lhs.base() >= rhs.base();
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
    [[nodiscard]] constexpr bool
    operator>(reverse_iterator<T> const &lhs, reverse_iterator<T> const &rhs) noexcept
    {
        return lhs.base() < rhs.base();
    }

    /// <!-- description -->
    ///   @brief Returns lhs.base() >= rhs.base()
    ///   @include reverse_iterator/example_reverse_iterator_gt_equals.hpp
    ///   @related bsl::reverse_iterator
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of element being iterated.
    ///   @param lhs the left hand side of the operation
    ///   @param rhs the rhs hand side of the operation
    ///   @return Returns lhs.base() >= rhs.base()
    ///
    template<typename T>
    [[nodiscard]] constexpr bool
    operator>=(reverse_iterator<T> const &lhs, reverse_iterator<T> const &rhs) noexcept
    {
        return lhs.base() <= rhs.base();
    }

    /// <!-- description -->
    ///   @brief Constructs a reverse_iterator for a given provided iterator.
    ///   @related bsl::reverse_iterator
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam Iter the type of iterator to make the reverse iterator from.
    ///   @param i the iterator to make the reverse iterator from.
    ///   @return a newly constructed reverse iterator.
    ///
    template<typename Iter>
    constexpr reverse_iterator<Iter>
    make_reverse_iterator(Iter const &i) noexcept
    {
        return {i};
    }

    /// <!-- description -->
    ///   @brief Outputs the provided bsl::reverse_iterator to the provided
    ///     output type.
    ///   @related bsl::reverse_iterator
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T1 the type of outputter provided
    ///   @tparam T2 the type of element being encapsulated.
    ///   @param o the instance of the outputter used to output the value.
    ///   @param val the reverse_iterator to output
    ///   @return return o
    ///
    template<typename T1, typename T2>
    [[maybe_unused]] constexpr out<T1>
    operator<<(out<T1> const o, reverse_iterator<T2> const &val) noexcept
    {
        if (val.is_end()) {
            return o << "[null]";
        }

        return o << *val.get_if();
    }
}

#endif
