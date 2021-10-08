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

#ifndef BSL_DETAILS_FMT_IMPL_INTEGRAL_HELPERS_HPP
#define BSL_DETAILS_FMT_IMPL_INTEGRAL_HELPERS_HPP

#include "../carray.hpp"
#include "../char_type.hpp"
#include "../fmt_options.hpp"
#include "../fmt_sign.hpp"
#include "../fmt_type.hpp"
#include "../is_signed.hpp"
#include "../safe_idx.hpp"
#include "../safe_integral.hpp"
#include "../touch.hpp"
#include "fmt_impl_align.hpp"
#include "fmt_impl_integral_info.hpp"
#include "out.hpp"

#pragma clang diagnostic ignored "-Wswitch-enum"

namespace bsl::details
{
    /// <!-- description -->
    ///   @brief Returns the base to format the integral with
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of integral to output
    ///   @param ops ops the fmt options used to format the output
    ///   @param mut_info the info to return
    ///   @return Returns the base to format the integral with
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    get_integral_info_base(fmt_options const &ops, fmt_impl_integral_info &mut_info) noexcept
        -> safe_integral<T>
    {
        constexpr safe_integral<T> base2{static_cast<T>(2)};
        constexpr safe_integral<T> base10{static_cast<T>(10)};
        constexpr safe_integral<T> base16{static_cast<T>(16)};

        switch (ops.type()) {
            case fmt_type::fmt_type_b: {
                if (ops.alternate_form()) {
                    mut_info.extras += safe_idx::magic_2();
                }
                else {
                    bsl::touch();
                }

                return base2;
            }

            case fmt_type::fmt_type_x: {
                if (ops.alternate_form()) {
                    mut_info.extras += safe_idx::magic_2();
                }
                else {
                    bsl::touch();
                }

                return base16;
            }

            default: {
                break;
            }
        }

        return base10;
    }

    /// <!-- description -->
    ///   @brief This function gathers information about an integral
    ///     number which is used by fmt_impl_integral. Specifically:
    ///     - The base is determined by parsing the fmt_options for
    ///       what type the user requested. For example, hex is base
    ///       16, dec is base 10 and bin is base 2.
    ///     - This function also calculates the number of "extra"
    ///       characters fmt_impl_integral will have to output. This
    ///       includes things like "0x" and +/-. All of these
    ///       extra characters consume characters from any "width" the
    ///       user might have provided and need to be accounted for.
    ///     - The fmt_impl_integral function use a common divide by base
    ///       approach to convert a number to a string. This approach
    ///       converts the number in reverse order, so the characters
    ///       must be stored in a buffer and then outputted in reverse
    ///       order.
    ///     - The buffer that we store the digits in (which is in reverse
    ///       order as stated above) is a simple C-style array and not a
    ///       bsl::array as the bsl::array depends on this functionality
    ///       which would create a circular reference.
    ///     - The total number of digits that the number will consume
    ///       must also be recorded. This prevents the need to add a 0
    ///       at the end of the buffer.
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of integral to output
    ///   @param ops ops the fmt options used to format the output
    ///   @param val the integral value to output
    ///   @return Returns fmt_impl_integral_info<T>
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    get_integral_info(fmt_options const &ops, safe_integral<T> const &val) noexcept
        -> fmt_impl_integral_info
    {
        constexpr safe_integral<T> base10{static_cast<T>(10)};
        constexpr safe_integral<T> last_numerical_digit{static_cast<T>(9)};

        fmt_impl_integral_info mut_info{};
        auto const base{get_integral_info_base<T>(ops, mut_info)};

        /// NOTE:
        /// - The provided val must be valid before this function is called,
        ///   otherwise the results are undefined. We also convert val from
        ///   a potential index type to a non-index type (if it is one). This
        ///   way we can work on it without breaking the safe_integral rules
        ///   and it simplifies how this works.
        ///

        safe_integral<T> mut_val{val.get()};
        switch (ops.sign()) {
            case fmt_sign::fmt_sign_pos_neg:
                [[fallthrough]];
            case fmt_sign::fmt_sign_space_for_pos: {
                ++mut_info.extras;
                break;
            }

            case fmt_sign::fmt_sign_neg_only:
                [[fallthrough]];
            default: {
                if constexpr (is_signed<T>::value) {
                    if (mut_val.is_neg()) {
                        ++mut_info.extras;
                    }
                    else {
                        bsl::touch();
                    }
                }

                break;
            }
        }

        if (mut_val.is_zero()) {
            ++mut_info.digits;
            return mut_info;
        }

        /// NOTE:
        /// - The buffer is large enough that it will never overflow, so we
        ///   check for 0 in the for loop instead. This can be seen in the
        ///   unit tests as the case where the buffer would overflow is
        ///   impossible to hit with any tests given to it.
        ///

        for (mut_info.digits = {}; !mut_val.checked().is_zero(); ++mut_info.digits) {
            /// NOTE:
            /// - Base cannot be 0. As stated above, we assume that the
            ///   provided val is valid, so the results of this math must
            ///   also be valid which is why it is marked as checked.
            ///

            safe_integral<T> mut_digit{(mut_val % base).checked()};
            mut_val = (mut_val / base).checked();

            /// NOTE:
            /// - If the provided val is negative, we cannot simply swap
            ///   it's whole val because if it is min(), such a swap would
            ///   result in overflow. So we need to negate each digit.
            ///   Since each digit is the result of division, it will
            ///   always be smaller than the provided type's max(), and
            ///   there fore doing the negation is safe which is why it
            ///   is marked as checked.
            ///

            if constexpr (is_signed<T>::value) {
                if (mut_digit.is_neg()) {
                    mut_digit = (-mut_digit).checked();
                }
                else {
                    bsl::touch();
                }
            }

            if (mut_digit > last_numerical_digit) {
                mut_digit -= base10;
                mut_digit += static_cast<T>('A');
            }
            else {
                mut_digit += static_cast<T>('0');
            }

            /// NOTE:
            /// - Since the highest value that we support is a 16bit
            ///   integral, even if the provided val is 8bits, we are
            ///   only using the bottom half of the ASCII table, so
            ///   the math above cannot overflow which is why we mark
            ///   it as checked.
            ///

            *mut_info.buf.at_if(mut_info.digits.get()) =
                static_cast<char_type>(mut_digit.checked().get());
        }

        return mut_info;
    }

    /// <!-- description -->
    ///   @brief This function is responsible for implementing the guts
    ///     for integral types. For integrals, all of the fmt options
    ///     must be accounted for.
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam OUT_T the type of out (i.e., debug, alert, etc)
    ///   @tparam T the type of integral to output
    ///   @param o the instance of out<T> to output to
    ///   @param ops ops the fmt options used to format the output
    ///   @param val the integral being outputted
    ///
    template<typename OUT_T, typename T>
    constexpr void
    fmt_impl_integral(
        out<OUT_T> const o, fmt_options const &ops, safe_integral<T> const &val) noexcept
    {
        auto const info{get_integral_info(ops, val)};
        safe_umx const len{(info.digits + info.extras).get()};
        auto const padding{fmt_impl_align_pre(o, ops, len, false)};

        /// NOTE:
        /// - We assume that val is not invalid. If it is, the execution of
        ///   this function is undefined.
        ///

        switch (ops.sign()) {
            case fmt_sign::fmt_sign_pos_neg: {
                if constexpr (is_signed<T>::value) {
                    if (val.is_neg()) {
                        o.write_to_console('-');
                    }
                    else {
                        o.write_to_console('+');
                    }
                }
                else {
                    o.write_to_console('+');
                }

                break;
            }

            case fmt_sign::fmt_sign_space_for_pos: {
                if constexpr (is_signed<T>::value) {
                    if (val.is_neg()) {
                        o.write_to_console('-');
                    }
                    else {
                        o.write_to_console(' ');
                    }
                }
                else {
                    o.write_to_console(' ');
                }

                break;
            }

            case fmt_sign::fmt_sign_neg_only:
                [[fallthrough]];
            default: {
                if constexpr (is_signed<T>::value) {
                    if (val.is_neg()) {
                        o.write_to_console('-');
                    }
                    else {
                        bsl::touch();
                    }
                }

                break;
            }
        }

        if (ops.alternate_form()) {
            switch (ops.type()) {
                case fmt_type::fmt_type_b: {
                    o.write_to_console("0b", safe_umx::magic_2().get());
                    break;
                }

                case fmt_type::fmt_type_x: {
                    o.write_to_console("0x", safe_umx::magic_2().get());
                    break;
                }

                default: {
                    break;
                }
            }
        }
        else {
            bsl::touch();
        }

        if (ops.sign_aware()) {
            for (safe_idx mut_pi{}; mut_pi < padding; ++mut_pi) {
                o.write_to_console('0');
            }
        }
        else {
            bsl::touch();
        }

        if (val.is_zero()) {
            o.write_to_console('0');
        }
        else {
            for (safe_idx mut_i{info.digits}; mut_i.is_pos(); --mut_i) {
                o.write_to_console(*info.buf.at_if((mut_i - safe_idx::magic_1()).get()));
            }
        }

        fmt_impl_align_suf(o, ops, len, false);
    }
}

#endif
