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

#include "bsl/ensures.hpp"
#include "bsl/expects.hpp"
#include "bsl/is_signed.hpp"
#include "bsl/safe_idx.hpp"
#include "bsl/safe_integral.hpp"
#include "bsl/string_view.hpp"
#include "bsl/touch.hpp"
#include "bsl/unlikely.hpp"

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
        from_chars_ignore_whitespace(string_view const &str) noexcept -> safe_idx
        {
            safe_idx mut_i{};
            for (; mut_i < str.length(); ++mut_i) {
                char_type const digit{*str.at_if(mut_i)};

                if (' ' == digit) {
                    continue;
                }

                if ('\t' == digit) {
                    continue;
                }

                if ('\n' == digit) {
                    continue;
                }

                if ('\v' == digit) {
                    continue;
                }

                if ('\f' == digit) {
                    continue;
                }

                if ('\r' == digit) {
                    continue;
                }

                break;
            }

            if (unlikely(str.length() == mut_i)) {
                return npos;
            }

            return mut_i;
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
        from_chars_parse_dec(string_view const &str, safe_idx const &idx) noexcept
            -> safe_integral<T>
        {
            constexpr safe_integral<T> base10{static_cast<T>(10)};

            bool mut_negate{};
            safe_integral<T> mut_val{};

            auto mut_idx{idx};
            if constexpr (is_signed<T>::value) {
                if ('-' == *str.front_if()) {
                    mut_negate = true;
                    ++mut_idx;
                }
                else {
                    bsl::touch();
                }
            }

            for (safe_idx mut_i{mut_idx}; mut_i < str.length(); ++mut_i) {
                safe_integral<T> const digit{static_cast<T>(*str.at_if(mut_i))};

                constexpr safe_integral<T> lower_num{static_cast<T>('/')};
                constexpr safe_integral<T> upper_num{static_cast<T>(':')};

                if (digit > lower_num) {
                    if (digit < upper_num) {
                        constexpr safe_integral<T> offset{static_cast<T>('0')};
                        if constexpr (is_signed<T>::value) {
                            if (mut_negate) {
                                mut_val *= base10;
                                mut_val -= (digit - offset);
                            }
                            else {
                                mut_val *= base10;
                                mut_val += (digit - offset);
                            }
                        }
                        else {
                            mut_val *= base10;
                            mut_val += (digit - offset);
                        }

                        continue;
                    }

                    bsl::touch();
                }
                else {
                    bsl::touch();
                }

                return safe_integral<T>::failure();
            }

            if (unlikely(mut_val.is_poisoned())) {
                return safe_integral<T>::failure();
            }

            return mut_val;
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
        from_chars_parse_hex(string_view const &str, safe_idx const &idx) noexcept
            -> safe_integral<T>
        {
            if constexpr (is_signed<T>::value) {
                return safe_integral<T>::failure();
            }

            constexpr safe_integral<T> base10{static_cast<T>(10)};
            constexpr safe_integral<T> base16{static_cast<T>(16)};

            safe_integral<T> mut_val{};

            for (safe_idx mut_i{idx}; mut_i < str.length(); ++mut_i) {
                safe_integral<T> const digit{static_cast<T>(*str.at_if(mut_i))};

                constexpr safe_integral<T> lower_num{static_cast<T>('/')};
                constexpr safe_integral<T> upper_num{static_cast<T>(':')};

                if (digit > lower_num) {
                    if (digit < upper_num) {
                        constexpr safe_integral<T> offset{static_cast<T>('0')};
                        mut_val *= base16;
                        mut_val += (digit - offset);
                        continue;
                    }

                    bsl::touch();
                }
                else {
                    bsl::touch();
                }

                constexpr safe_integral<T> lower_alpha1{static_cast<T>('@')};
                constexpr safe_integral<T> upper_alpha1{static_cast<T>('G')};

                if (digit > lower_alpha1) {
                    if (digit < upper_alpha1) {
                        constexpr safe_integral<T> offset{static_cast<T>('A')};
                        mut_val *= base16;
                        mut_val += base10;
                        mut_val += (digit - offset);
                        continue;
                    }

                    bsl::touch();
                }
                else {
                    bsl::touch();
                }

                constexpr safe_integral<T> lower_alpha2{static_cast<T>('`')};
                constexpr safe_integral<T> upper_alpha2{static_cast<T>('g')};

                if (digit > lower_alpha2) {
                    if (digit < upper_alpha2) {
                        constexpr safe_integral<T> offset{static_cast<T>('a')};
                        mut_val *= base16;
                        mut_val += base10;
                        mut_val += (digit - offset);
                        continue;
                    }

                    bsl::touch();
                }
                else {
                    bsl::touch();
                }

                return safe_integral<T>::failure();
            }

            if (unlikely(mut_val.is_poisoned())) {
                return safe_integral<T>::failure();
            }

            return mut_val;
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
    ///   @param base either 10 or 16
    ///   @return Returns the index that the parser stopped parsing after
    ///     at when converting the number, or 0 in the event of an error.
    ///
    template<typename T>
    [[maybe_unused]] constexpr auto
    from_chars(string_view const &str, safe_i32 const &base) noexcept -> safe_integral<T>
    {
        constexpr safe_i32 base10{10};
        constexpr safe_i32 base16{16};

        expects(base.is_valid_and_checked());

        if (unlikely(str.empty())) {
            return safe_integral<T>::failure();
        }

        auto const idx{details::from_chars_ignore_whitespace(str)};
        if (unlikely(npos == idx)) {
            return safe_integral<T>::failure();
        }

        safe_integral<T> mut_val{};
        switch (base.get()) {
            case base10.get(): {
                mut_val = details::from_chars_parse_dec<T>(str, idx);
                break;
            }

            case base16.get(): {
                mut_val = details::from_chars_parse_hex<T>(str, idx);
                break;
            }

            default: {
                mut_val = safe_integral<T>::failure();
                break;
            }
        }

        /// NOTE:
        /// - If the result is invalid because a conversion encountered an
        ///   error, we simply return an error. If however no error has
        ///   occurred, we ensure that the result is both valid and checked.
        ///

        if (unlikely(mut_val.is_invalid())) {
            return safe_integral<T>::failure();
        }

        ensures(mut_val.is_valid_and_checked());
        return mut_val;
    }
}

#endif
