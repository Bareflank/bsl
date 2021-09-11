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

#ifndef BSL_DETAILS_OUT_LINE_STDERR_HPP
#define BSL_DETAILS_OUT_LINE_STDERR_HPP

#include "../carray.hpp"
#include "../char_type.hpp"
#include "../cstdint.hpp"
#include "../source_location.hpp"
#include "out_char.hpp"

namespace bsl::details
{
    /// <!-- description -->
    ///   @brief Outputs a line number to stdout.
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_line the line to output to stdout
    ///
    constexpr void
    out_line(line_type mut_line) noexcept
    {
        constexpr uintmx base{static_cast<line_type>(10)};
        constexpr uintmx max_digits{static_cast<bsl::uintmx>(70)};

        bsl::uintmx mut_digits{};
        carray<char_type, max_digits> mut_buf{};

        if (static_cast<line_type>(0) == mut_line) {
            out_char('0');
            return;
        }

        for (mut_digits = {}; mut_line > static_cast<line_type>(0); ++mut_digits) {
            *mut_buf.at_if(mut_digits) = (static_cast<char_type>(mut_line % base) + '0');
            mut_line /= base;
        }

        for (bsl::uintmx mut_i{mut_digits}; mut_i > static_cast<bsl::uintmx>(0); --mut_i) {
            out_char(*mut_buf.at_if(mut_i - static_cast<bsl::uintmx>(1)));
        }
    }
}

#endif
