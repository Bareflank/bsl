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

#include "convert.hpp"
#include "debug.hpp"
#include "safe_integral.hpp"

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
        ///   @param ptr a pointer to the array being iterated
        ///   @param count the number of elements in the array being iterated
        ///   @param i the initial index of the iterator
        ///
        constexpr contiguous_iterator(    // --
            pointer_type const ptr,       // --
            size_type const &count,       // --
            size_type const &i) noexcept
            : m_ptr{ptr}, m_count{count}, m_i{i}
        {
            if ((nullptr == m_ptr) || m_count.is_zero()) {
                bsl::alert() << "contiguous_iterator: invalid constructor args\n";
                bsl::alert() << "  - ptr: " << static_cast<void const *>(ptr) << bsl::endl;
                bsl::alert() << "  - count: " << count << bsl::endl;
                bsl::alert() << "  - i: " << i << bsl::endl;

                *this = contiguous_iterator{};
            }

            if ((!i) || (i > count)) {
                bsl::alert() << "contiguous_iterator: invalid constructor args\n";
                bsl::alert() << "  - ptr: " << static_cast<void const *>(ptr) << bsl::endl;
                bsl::alert() << "  - count: " << count << bsl::endl;
                bsl::alert() << "  - i: " << i << bsl::endl;

                m_i = count;
            }
        }

        /// <!-- description -->
        ///   @brief Returns a pointer to the array being iterated
        ///   @include contiguous_iterator/example_contiguous_iterator_data.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a pointer to the array being iterated
        ///
        [[nodiscard]] constexpr pointer_type
        data() noexcept
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
        [[nodiscard]] constexpr const_pointer_type
        data() const noexcept
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
        [[nodiscard]] constexpr size_type const &
        size() const noexcept
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
        [[nodiscard]] constexpr size_type const &
        index() const noexcept
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
        [[nodiscard]] constexpr bool
        empty() const noexcept
        {
            return nullptr == this->data();
        }

        /// <!-- description -->
        ///   @brief Returns !is_end()
        ///   @include contiguous_iterator/example_contiguous_iterator_operator_bool.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns !is_end()
        ///
        [[nodiscard]] constexpr explicit operator bool() const noexcept
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
        [[nodiscard]] constexpr bool
        is_end() const noexcept
        {
            return this->index() == this->size();
        }

        /// <!-- description -->
        ///   @brief Returns a pointer to the instance of T stored at the
        ///     iterator's current index. If the index is out of bounds,
        ///     or the iterator is invalid, this function returns a nullptr.
        ///   @include contiguous_iterator/example_contiguous_iterator_get_if.hpp
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
            if (nullptr == m_ptr) {
                bsl::error() << "contiguous_iterator: null iterator\n";
                return nullptr;
            }

            if (m_i == m_count) {
                bsl::error() << "contiguous_iterator: attempt to get value from end() iterator\n";
                return nullptr;
            }

            return &m_ptr[m_i.get()];    // PRQA S 4024 // NOLINT
        }

        /// <!-- description -->
        ///   @brief Returns a pointer to the instance of T stored at the
        ///     iterator's current index. If the index is out of bounds,
        ///     or the iterator is invalid, this function returns a nullptr.
        ///   @include contiguous_iterator/example_contiguous_iterator_get_if.hpp
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
            if (nullptr == m_ptr) {
                bsl::error() << "contiguous_iterator: null iterator\n";
                return nullptr;
            }

            if (m_i == m_count) {
                bsl::error() << "contiguous_iterator: attempt to get value from end() iterator\n";
                return nullptr;
            }

            return &m_ptr[m_i.get()];    // PRQA S 4024 // NOLINT
        }

        /// <!-- description -->
        ///   @brief Increments the iterator
        ///   @include contiguous_iterator/example_contiguous_iterator_increment.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return returns *this
        ///
        [[maybe_unused]] constexpr contiguous_iterator &
        operator++() noexcept
        {
            if (nullptr == m_ptr) {
                bsl::error() << "contiguous_iterator: attempt to inc null iterator\n";
                return *this;
            }

            if (m_count == m_i) {
                bsl::error() << "contiguous_iterator: attempt to inc end() iterator\n";
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
        [[maybe_unused]] constexpr contiguous_iterator &
        operator--() noexcept
        {
            if (nullptr == m_ptr) {
                bsl::error() << "contiguous_iterator: attempt to dec null iterator\n";
                return *this;
            }

            if (m_i.is_zero()) {
                bsl::error() << "contiguous_iterator: attempt to inc begin() iterator\n";
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
    [[nodiscard]] constexpr bool
    operator==(contiguous_iterator<T> const &lhs, contiguous_iterator<T> const &rhs) noexcept
    {
        return (lhs.data() == rhs.data()) && (lhs.index() == rhs.index());
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
    [[nodiscard]] constexpr bool
    operator!=(contiguous_iterator<T> const &lhs, contiguous_iterator<T> const &rhs) noexcept
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
    [[nodiscard]] constexpr bool
    operator<(contiguous_iterator<T> const &lhs, contiguous_iterator<T> const &rhs) noexcept
    {
        return lhs.index() < rhs.index();
    }

    /// <!-- description -->
    ///   @brief Returns lhs.index() <= rhs.index()
    ///   @include contiguous_iterator/example_contiguous_iterator_lt_equals.hpp
    ///   @related bsl::contiguous_iterator
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of element being iterated.
    ///   @param lhs the left hand side of the operation
    ///   @param rhs the rhs hand side of the operation
    ///   @return Returns lhs.index() <= rhs.index()
    ///
    template<typename T>
    [[nodiscard]] constexpr bool
    operator<=(contiguous_iterator<T> const &lhs, contiguous_iterator<T> const &rhs) noexcept
    {
        return lhs.index() <= rhs.index();
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
    [[nodiscard]] constexpr bool
    operator>(contiguous_iterator<T> const &lhs, contiguous_iterator<T> const &rhs) noexcept
    {
        return lhs.index() > rhs.index();
    }

    /// <!-- description -->
    ///   @brief Returns lhs.index() >= rhs.index()
    ///   @include contiguous_iterator/example_contiguous_iterator_gt_equals.hpp
    ///   @related bsl::contiguous_iterator
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of element being iterated.
    ///   @param lhs the left hand side of the operation
    ///   @param rhs the rhs hand side of the operation
    ///   @return Returns lhs.index() >= rhs.index()
    ///
    template<typename T>
    [[nodiscard]] constexpr bool
    operator>=(contiguous_iterator<T> const &lhs, contiguous_iterator<T> const &rhs) noexcept
    {
        return lhs.index() >= rhs.index();
    }

    /// <!-- description -->
    ///   @brief Outputs the provided bsl::contiguous_iterator to the provided
    ///     output type.
    ///   @related bsl::contiguous_iterator
    ///   @include contiguous_iterator/example_contiguous_iterator_ostream.hpp
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T1 the type of outputter provided
    ///   @tparam T2 the type of element being encapsulated.
    ///   @param o the instance of the outputter used to output the value.
    ///   @param val the contiguous_iterator to output
    ///   @return return o
    ///
    template<typename T1, typename T2>
    [[maybe_unused]] constexpr out<T1>
    operator<<(out<T1> const o, contiguous_iterator<T2> const &val) noexcept
    {
        if constexpr (!o) {
            return o;
        }

        if (val.is_end()) {
            return o << "[null]";
        }

        return o << *val.get_if();
    }
}

#endif
