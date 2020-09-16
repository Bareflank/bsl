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

#ifndef BSL_DETAILS_FMT_IMPL_INTEGRAL_INFO_HPP
#define BSL_DETAILS_FMT_IMPL_INTEGRAL_INFO_HPP

#include "carray.hpp"

#include "../char_type.hpp"
#include "../safe_integral.hpp"

namespace bsl::details
{
    /// @brief stores the maximum number of digits.
    constexpr safe_uintmax MAX_NUM_DIGITS{to_umax(64)};

    /// @class bsl::details::fmt_impl_integral_info
    ///
    /// <!-- description -->
    ///   @brief Used to store information about an integral. This is used
    ///     by the fmt logic to output a number. Note that this this is not a
    ///     trivial type, this has to be implemented as a class.
    ///
    /// <!-- template parameters -->
    ///   @tparam T the type of integral to get info from
    ///
    template<typename T>
    struct fmt_impl_integral_info final
    {
        /// @brief stores the total number of extra characters needed
        safe_uintmax extras{};
        /// @brief stores the total number digits that make up the integral
        safe_uintmax digits{};
        /// @brief stores the integral as a string in reverse
        carray<char_type, MAX_NUM_DIGITS.get()> buf{};
    };
}

#endif
