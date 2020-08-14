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

#ifndef BSL_INTEGER_SEQUENCE_MIN_HPP
#define BSL_INTEGER_SEQUENCE_MIN_HPP

namespace bsl::details
{
    namespace details
    {
        /// <!-- description -->
        ///   @brief Returns the min of T1 and T2
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T the type of values being compared
        ///   @param T1 the first integer to compare
        ///   @param T2 the second integer to compare
        ///   @return Returns the min of T1 and T2
        ///
        template<typename T>
        [[nodiscard]] constexpr auto
        integer_sequence_min_impl(T const T1, T const T2) noexcept -> T
        {
            if (T1 < T2) {
                return T1;
            }

            return T2;
        }
    }

    /// @class bsl::details::integer_sequence_min
    ///
    /// <!-- description -->
    ///   @brief Returns the min value given an integer sequence. This is
    ///     used to implement integer_sequence::min().
    ///
    /// <!-- template parameters -->
    ///   @tparam T the type that defines the sequence of integers
    ///   @tparam T1 the first integer in the sequence
    ///   @tparam R the remaining integers in the sequence
    ///
    template<typename T, T T1, T... R>
    struct integer_sequence_min final
    {
        static constexpr T T2{integer_sequence_min<T, R...>::value};
        static constexpr T value{details::integer_sequence_min_impl(T1, T2)};
    };

    /// @class bsl::details::integer_sequence_min
    ///
    /// <!-- description -->
    ///   @brief Returns the min value given an integer sequence. This is
    ///     used to implement integer_sequence::min(). Note that this
    ///     provides the case where there are only two integers in the
    ///     sequence.
    ///
    /// <!-- template parameters -->
    ///   @tparam T the type that defines the sequence of integers
    ///   @tparam T1 the first integer in the sequence
    ///   @tparam T2 the second integer in the sequence
    ///
    template<typename T, T T1, T T2>
    struct integer_sequence_min<T, T1, T2> final
    {
        static constexpr T value{details::integer_sequence_min_impl(T1, T2)};
    };

    /// @class bsl::details::integer_sequence_min
    ///
    /// <!-- description -->
    ///   @brief Returns the min value given an integer sequence. This is
    ///     used to implement integer_sequence::min(). Note that this
    ///     provides the case where there is only one integer in the
    ///     sequence.
    ///
    /// <!-- template parameters -->
    ///   @tparam T the type that defines the sequence of integers
    ///   @tparam T1 the first integer in the sequence
    ///
    template<typename T, T T1>
    struct integer_sequence_min<T, T1> final
    {
        static constexpr T value{T1};
    };
}

#endif
