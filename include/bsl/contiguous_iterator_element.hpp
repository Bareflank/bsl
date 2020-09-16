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

#ifndef BSL_CONTIGUOUS_ITERATOR_ELEMENT_HPP
#define BSL_CONTIGUOUS_ITERATOR_ELEMENT_HPP

#include "details/out.hpp"

#include "safe_integral.hpp"

namespace bsl
{
    /// @class bsl::contiguous_iterator_element
    ///
    /// <!-- description -->
    ///   @brief Provides the return value of the * operator for the
    ///     contiguous iterator. This is used with ranged for loops so
    ///     that you can get safe access to the data in the iterator, as
    ///     well as access to the current index.
    ///
    /// <!-- template parameters -->
    ///   @tparam T the type of element being iterated.
    ///
    template<typename T>
    struct contiguous_iterator_element final
    {
        /// @brief stores a pointer to the data the iterator points to
        T *data;
        /// @brief stores the current index of the iterator
        safe_uintmax const &index;
    };

    /// <!-- description -->
    ///   @brief Outputs the provided bsl::contiguous_iterator_element to the
    ///     provided output type.
    ///   @related bsl::contiguous_iterator_element
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T1 the type of outputter provided
    ///   @tparam T2 the type of element being encapsulated.
    ///   @param o the instance of the outputter used to output the value.
    ///   @param elem the contiguous_iterator_element to output
    ///   @return return o
    ///
    template<typename T1, typename T2>
    [[maybe_unused]] constexpr auto
    operator<<(out<T1> const o, contiguous_iterator_element<T2> const &elem) noexcept -> out<T1>
    {
        if constexpr (!o) {
            return o;
        }

        if (nullptr != elem.data) {
            return o << *elem.data;
        }

        return o << "[error]";
    }
}

#endif
