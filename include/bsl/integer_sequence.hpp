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
/// @file integer_sequence.hpp
///

#ifndef BSL_INTEGER_SEQUENCE_HPP
#define BSL_INTEGER_SEQUENCE_HPP

#include "bsl/cstdint.hpp"
#include "bsl/details/integer_sequence_max.hpp"
#include "bsl/details/integer_sequence_min.hpp"

namespace bsl
{
    /// @class bsl::integer_sequence
    ///
    /// <!-- description -->
    ///   @brief The class template std::integer_sequence represents a
    ///     compile-time sequence of integers. When used as an argument to a
    ///     function template, the parameter pack Ints can be deduced and used
    ///     in pack expansion.
    ///   @include example_integer_sequence_overview.hpp
    ///
    /// <!-- template parameters -->
    ///   @tparam T the type that defines the sequence of integers
    ///   @tparam INTS the integers that make up the integer sequence
    ///
    template<typename T, T... INTS>
    class integer_sequence final
    {
    public:
        /// @brief provides the member typedef "value_type"
        using value_type = T;

        /// <!-- description -->
        ///   @brief Equivalent to sizeof...(INTS)
        ///   @include integer_sequence/example_integer_sequence_size.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Equivalent to sizeof...(INTS)
        ///
        [[nodiscard]] static constexpr auto
        size() noexcept -> bsl::uintmx
        {
            return sizeof...(INTS);
        }

        /// <!-- description -->
        ///   @brief Returns the max integer in the sequence
        ///   @include integer_sequence/example_integer_sequence_max.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the max integer in the sequence
        ///
        [[nodiscard]] static constexpr auto
        max() noexcept -> T
        {
            return details::integer_sequence_max<T, INTS...>::value;
        }

        /// <!-- description -->
        ///   @brief Returns the min integer in the sequence
        ///   @include integer_sequence/example_integer_sequence_min.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the min integer in the sequence
        ///
        [[nodiscard]] static constexpr auto
        min() noexcept -> T
        {
            return details::integer_sequence_min<T, INTS...>::value;
        }
    };
}

#endif
