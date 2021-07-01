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

#include "../char_type.hpp"
#include "../fmt_options.hpp"
#include "../is_signed.hpp"
#include "../safe_integral.hpp"
#include "../touch.hpp"
#include "fmt_impl_align.hpp"
#include "fmt_impl_integral_info.hpp"
#include "out.hpp"

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
    get_integral_info_base(fmt_options const &ops, fmt_impl_integral_info<T> &mut_info) noexcept
        -> safe_integral<T>
    {
        constexpr safe_integral<T> base2{static_cast<T>(2)};
        constexpr safe_integral<T> base10{static_cast<T>(10)};
        constexpr safe_integral<T> base16{static_cast<T>(16)};
        constexpr safe_uintmax extra_chars{static_cast<bsl::uintmax>(2)};

        switch (ops.type()) {
            case fmt_type::fmt_type_b: {
                if (ops.alternate_form()) {
                    mut_info.extras += extra_chars;
                }
                else {
                    bsl::touch();
                }

                return base2;
            }

            case fmt_type::fmt_type_x: {
                if (ops.alternate_form()) {
                    mut_info.extras += extra_chars;
                }
                else {
                    bsl::touch();
                }

                return base16;
            }

            case fmt_type::fmt_type_c:
            case fmt_type::fmt_type_d:
            case fmt_type::fmt_type_s:
            case fmt_type::fmt_type_default: {
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
        -> fmt_impl_integral_info<T>
    {
        constexpr safe_integral<T> base10{static_cast<T>(10)};
        constexpr safe_integral<T> last_numerical_digit{static_cast<T>(9)};

        fmt_impl_integral_info<T> mut_info{};
        auto const base{get_integral_info_base(ops, mut_info)};

        switch (ops.sign()) {
            case fmt_sign::fmt_sign_pos_neg:
            case fmt_sign::fmt_sign_space_for_pos: {
                ++mut_info.extras;
                break;
            }

            case fmt_sign::fmt_sign_neg_only: {
                if constexpr (is_signed<T>::value) {
                    if (val.is_neg()) {
                        ++mut_info.extras;
                    }
                    else {
                        bsl::touch();
                    }
                }

                break;
            }
        }

        if (val.is_zero()) {
            ++mut_info.digits;
        }
        else {
            auto mut_val{val};
            for (mut_info.digits = {}; mut_info.digits < MAX_NUM_DIGITS; ++mut_info.digits) {
                if (mut_val.is_zero()) {
                    break;
                }

                safe_integral<T> mut_digit{mut_val % base};
                mut_val /= base;

                if constexpr (is_signed<T>::value) {
                    if (mut_digit.is_neg()) {
                        mut_digit = -mut_digit;
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

                *mut_info.buf.at_if(mut_info.digits) = static_cast<char_type>(mut_digit.get());
            }
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
        fmt_impl_integral_info<T> const info{get_integral_info(ops, val)};
        safe_uintmax const padding{fmt_impl_align_pre(o, ops, info.digits + info.extras, false)};

        if (is_signed<T>::value) {
            switch (ops.sign()) {
                case fmt_sign::fmt_sign_pos_neg: {
                    if (val.is_neg()) {
                        o.write_to_console('-');
                    }
                    else {
                        o.write_to_console('+');
                    }

                    break;
                }

                case fmt_sign::fmt_sign_space_for_pos: {
                    if (val.is_neg()) {
                        o.write_to_console('-');
                    }
                    else {
                        o.write_to_console(' ');
                    }

                    break;
                }

                case fmt_sign::fmt_sign_neg_only: {
                    if (val.is_neg()) {
                        o.write_to_console('-');
                    }
                    else {
                        bsl::touch();
                    }

                    break;
                }
            }
        }
        else {
            bsl::touch();
        }

        if (ops.alternate_form()) {
            switch (ops.type()) {
                case fmt_type::fmt_type_b: {
                    o.write_to_console("0b");
                    break;
                }

                case fmt_type::fmt_type_x: {
                    o.write_to_console("0x");
                    break;
                }

                case fmt_type::fmt_type_c:
                case fmt_type::fmt_type_d:
                case fmt_type::fmt_type_s:
                case fmt_type::fmt_type_default: {
                    break;
                }
            }
        }
        else {
            bsl::touch();
        }

        if (ops.sign_aware()) {
            for (safe_uintmax mut_pi{}; mut_pi < padding; ++mut_pi) {
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
            constexpr safe_uintmax one{static_cast<bsl::uintmax>(1)};
            for (safe_uintmax mut_i{info.digits}; mut_i.is_pos(); --mut_i) {
                o.write_to_console(*info.buf.at_if(mut_i - one));
            }
        }

        fmt_impl_align_suf(o, ops, info.digits + info.extras, false);
    }
}

#endif
