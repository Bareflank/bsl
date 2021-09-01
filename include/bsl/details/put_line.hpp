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

#ifndef BSL_DETAILS_PUT_LINE_STDERR_HPP
#define BSL_DETAILS_PUT_LINE_STDERR_HPP

#include "../carray.hpp"
#include "../cstdint.hpp"
#include "../source_location.hpp"
#include "put_char.hpp"

namespace bsl::details
{
    /// <!-- description -->
    ///   @brief Outputs a line number to stdout.
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_line the line to output to stdout
    ///
    constexpr void
    // NOLINTNEXTLINE(bsl-non-safe-integral-types-are-forbidden)
    put_line(line_type mut_line) noexcept
    {
        // NOLINTNEXTLINE(bsl-non-safe-integral-types-are-forbidden, bsl-implicit-conversions-forbidden)
        constexpr uintmx base{static_cast<line_type>(10)};
        // NOLINTNEXTLINE(bsl-non-safe-integral-types-are-forbidden)
        constexpr uintmx max_digits{static_cast<bsl::uintmx>(70)};

        // NOLINTNEXTLINE(bsl-non-safe-integral-types-are-forbidden)
        bsl::uintmx mut_digits{};
        carray<char_type, max_digits> mut_buf{};

        if (static_cast<line_type>(0) == mut_line) {
            put_char('0');
            return;
        }

        // NOLINTNEXTLINE(bsl-types-fixed-width-ints-arithmetic-check)
        for (mut_digits = {}; mut_line > static_cast<line_type>(0); ++mut_digits) {
            // NOLINTNEXTLINE(bsl-types-fixed-width-ints-arithmetic-check, bsl-implicit-conversions-forbidden)
            *mut_buf.at_if(mut_digits) = (static_cast<char_type>(mut_line % base) + '0');
            // NOLINTNEXTLINE(bsl-types-fixed-width-ints-arithmetic-check)
            mut_line /= base;
        }

        // NOLINTNEXTLINE(bsl-types-fixed-width-ints-arithmetic-check, bsl-non-safe-integral-types-are-forbidden)
        for (bsl::uintmx mut_i{mut_digits}; mut_i > static_cast<bsl::uintmx>(0); --mut_i) {
            // NOLINTNEXTLINE(bsl-types-fixed-width-ints-arithmetic-check)
            put_char(*mut_buf.at_if(mut_i - static_cast<bsl::uintmx>(1)));
        }
    }
}

#endif
