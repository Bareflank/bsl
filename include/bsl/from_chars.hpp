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
/// @file from_chars.hpp
///

#ifndef BSL_FROM_CHARS_HPP
#define BSL_FROM_CHARS_HPP

#include "char_type.hpp"
#include "convert.hpp"
#include "string_view.hpp"
#include "safe_integral.hpp"

namespace bsl
{
    namespace details
    {
        /// <!-- description -->
        ///   @brief Returns the index of the first character in the
        ///     string that is not whitespace.
        ///
        /// <!-- inputs/outputs -->
        ///   @param str the string to parse
        ///   @return Returns the index of the first character in the
        ///     string that is not whitespace.
        ///
        [[nodiscard]] constexpr auto
        from_chars_ignore_whitespace(string_view const &str) noexcept -> safe_uintmax
        {
            for (safe_uintmax i{}; i < str.length(); ++i) {
                auto c{*str.at_if(i)};

                if (' ' == c) {
                    continue;
                }

                if ('\t' == c) {
                    continue;
                }

                if ('\n' == c) {
                    continue;
                }

                if ('\v' == c) {
                    continue;
                }

                if ('\f' == c) {
                    continue;
                }

                if ('\r' == c) {
                    continue;
                }

                return i;
            }

            return str.length();
        }

        /// <!-- description -->
        ///   @brief Implements bsl::from_chars for base 10 numbers.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T The type of integral being parsed
        ///   @param str the string to parse
        ///   @param idx the starting position in the string of the base 10
        ///     number to parse (i.e., the string with whitespace removed)
        ///   @return Returns the resulting base 10 number.
        ///
        template<typename T>
        [[nodiscard]] constexpr auto
        from_chars_parse_dec(string_view const &str, safe_uintmax &idx) noexcept -> safe_integral<T>
        {
            constexpr T base10{static_cast<T>(10)};

            bool negate{};
            bool found_digits{};
            safe_integral<T> val{};

            for (; idx < str.length(); ++idx) {
                char_type const digit{*str.at_if(idx)};

                if constexpr (val.is_signed_type()) {
                    if (digit == '-') {
                        negate = true;
                        continue;
                    }

                    bsl::touch();
                }

                if (digit > '/') {
                    if (digit < ':') {
                        found_digits = true;
                        if (negate) {
                            val *= bsl::convert<T>(base10);
                            val -= (bsl::convert<T>(digit) - bsl::convert<T>('0'));
                        }
                        else {
                            val *= bsl::convert<T>(base10);
                            val += (bsl::convert<T>(digit) - bsl::convert<T>('0'));
                        }

                        continue;
                    }

                    bsl::touch();
                }
                else {
                    bsl::touch();
                }

                break;
            }

            if (!found_digits) {
                val.set_failure();
            }
            else {
                bsl::touch();
            }

            return val;
        }

        /// <!-- description -->
        ///   @brief Implements bsl::from_chars for base 16 numbers.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T The type of integral being parsed
        ///   @param str the string to parse
        ///   @param idx the starting position in the string of the base 16
        ///     number to parse (i.e., the string with whitespace removed)
        ///   @return Returns the resulting base 16 number.
        ///
        template<typename T>
        [[nodiscard]] constexpr auto
        from_chars_parse_hex(string_view const &str, safe_uintmax &idx) noexcept -> safe_integral<T>
        {
            constexpr T base10{static_cast<T>(10)};
            constexpr T base16{static_cast<T>(16)};

            bool found_digits{};
            safe_integral<T> val{};

            if constexpr (val.is_signed_type()) {
                return safe_integral<T>::zero(true);
            }

            for (; idx < str.length(); ++idx) {
                char_type const digit{*str.at_if(idx)};

                if (digit > '/') {
                    if (digit < ':') {
                        found_digits = true;
                        val *= bsl::convert<T>(base16);
                        val += bsl::convert<T>(digit) - bsl::convert<T>('0');
                        continue;
                    }

                    bsl::touch();
                }
                else {
                    bsl::touch();
                }

                if (digit > '@') {
                    if (digit < 'G') {
                        found_digits = true;
                        val *= bsl::convert<T>(base16);
                        val += bsl::convert<T>(base10);
                        val += bsl::convert<T>(digit) - bsl::convert<T>('A');
                        continue;
                    }

                    bsl::touch();
                }
                else {
                    bsl::touch();
                }

                if (digit > '`') {
                    if (digit < 'g') {
                        found_digits = true;
                        val *= bsl::convert<T>(base16);
                        val += bsl::convert<T>(base10);
                        val += bsl::convert<T>(digit) - bsl::convert<T>('a');
                        continue;
                    }

                    bsl::touch();
                }
                else {
                    bsl::touch();
                }

                break;
            }

            if (!found_digits) {
                val.set_failure();
            }
            else {
                bsl::touch();
            }

            return val;
        }
    }

    /// <!-- description -->
    ///   @brief Converts a string into a bsl::safe_integral<T>. This is
    ///     similar to std::from_chars with some key differences:
    ///     - The parameters and return type are different. The API that was
    ///       approved for C++17 relies on pointer arithmetic which is not
    ///       compliant with AUTOSAR, or C++'s own Core Guidelines. Instead
    ///       of providing pointers, you provide this function with a
    ///       bsl::string_view to convert, and a bsl::save_integral<T>, with
    ///       T defining the type of integral to return. Since the a
    ///       bsl::safe_integral already returns an error code, there is no
    ///       need for the result structure that std::from_chars has, and
    ///       instead, this function returns the index at which parsing
    ///       stopped (or 0 on failure).
    ///     - We only support base 10 and base 16. Any other base will return
    ///       an invalid bsl::save_integral, and an index of 0.
    ///     - Base 16 can only be an unsigned type.
    ///     - If the bsl::safe_integral that is provided has already seen an
    ///       error, this function will return a bsl::safe_integral that
    ///       has its error flag set and an index of 0.
    ///     - If the provided string is empty, this function will return a
    ///       bsl::safe_integral that has its error flag set and an index of 0.
    ///     - If the function is unable to form a valid number (i.e., it is
    ///       unable to find any digits to parse), this function will return a
    ///       bsl::safe_integral that has its error flag set and an index of 0.
    ///     - If the parser experiences an overflow, underflow or wrap, this
    ///       function will return a bsl::safe_integral that has its error flag
    ///       set and an index of 0.
    ///     - Floating point is currently not supported.
    ///
    ///     There are some similarities as well:
    ///     - This function will remove whitespace before attempting to
    ///       parse the number.
    ///     - This function will ignore the 0x or 0X prefix. If these are
    ///       seen, it will return 0 with an index of 1, thinking that the
    ///       "x" or "X" is the position in the string to stop parsing.
    ///     - Only signed types can be negative.
    ///
    ///   @include example_from_chars_overview.hpp
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T The type of integral to parse
    ///   @param str the string to convert into an integral
    ///   @param val the place to store the result of parsing.
    ///   @param base either 10 or 16
    ///   @return Returns the index that the parser stopped parsing after
    ///     at when converting the number, or 0 in the event of an error.
    ///
    template<typename T>
    [[maybe_unused]] constexpr auto
    from_chars(
        string_view const &str,
        safe_integral<T> &val,
        safe_int32 const base = safe_int32{10}) noexcept -> safe_uintmax
    {
        constexpr safe_int32 base10{10};
        constexpr safe_int32 base16{16};

        if (!val) {
            val = safe_integral<T>::zero(true);
            return safe_uintmax::zero();
        }

        if (str.empty()) {
            val = safe_integral<T>::zero(true);
            return safe_uintmax::zero();
        }

        switch (base.get()) {
            case base10.get(): {
                safe_uintmax idx{details::from_chars_ignore_whitespace(str)};
                val = details::from_chars_parse_dec<T>(str, idx);
                if (!val) {
                    return safe_uintmax::zero();
                }
                return idx;
            }

            case base16.get(): {
                safe_uintmax idx{details::from_chars_ignore_whitespace(str)};
                val = details::from_chars_parse_hex<T>(str, idx);
                if (!val) {
                    return safe_uintmax::zero();
                }
                return idx;
            }

            default: {
                break;
            }
        }

        val = safe_integral<T>::zero(true);
        return safe_uintmax::zero();
    }
}

#endif
