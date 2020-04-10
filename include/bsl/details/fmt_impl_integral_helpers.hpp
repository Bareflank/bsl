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

#include "fmt_impl_align.hpp"
#include "out.hpp"

#include "../cstdint.hpp"
#include "../enable_if.hpp"
#include "../fmt_options.hpp"
#include "../is_integral.hpp"
#include "../is_signed.hpp"

namespace bsl
{
    namespace details
    {
        /// @class bsl::details::fmt_impl_integral_info
        ///
        /// <!-- description -->
        ///   @brief Used to store information about an integral. This is used
        ///     by the fmt logic to output a number.
        ///
        /// <!-- template parameters -->
        ///   @tparam V the type of integral to get info from
        ///
        template<typename V>
        struct fmt_impl_integral_info final
        {
            /// @brief stores the base of the number (2, 10 or 16)
            V base;
            /// @brief stores the number in reverse
            V reversed;
            /// @brief stores the total number of digits in the number
            bsl::uintmax digits;
            /// @brief stores the total number of extra characters needed
            bsl::uintmax extras;
        };

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
        ///       approach to convert a number to a string. The problem
        ///       with this approach is the number is outputted in reverse
        ///       order. Normally a character buffer is allocated, filled
        ///       with the characters, reversed and then outputted.
        ///       Since we don't want to use temp storage, we reverse the
        ///       number in its integral format first. This way, when
        ///       the fmt_impl_integral function attempts to output the
        ///       number it will be reversing an already reversed number
        ///       which will output correctly.
        ///     - The total number of digits that the number will consume
        ///       must also be recorded. This is used to ensure trailing
        ///       zeros are still outputted (e.g., the number 400 in reverse
        ///       is 4, which would only output 4 when reversed again, but
        ///       knowing how many digits must be outputted ensures that
        ///       the 0 case is accounted for, which ensures 400 is outputted
        ///       by the fmt_impl_integral function).
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam V the type of integral value being outputted
        ///   @param ops ops the fmt options used to format the output
        ///   @param val the integral value being outputted
        ///   @return Returns fmt_impl_integral_info<V>
        ///
        template<typename V>
        constexpr fmt_impl_integral_info<V>
        get_integral_info(fmt_options const &ops, V val) noexcept
        {
            fmt_impl_integral_info<V> info{static_cast<V>(10), static_cast<V>(0), 0U, 0U};

            switch (ops.type()) {
                case fmt_type::fmt_type_b: {
                    if (ops.alternate_form()) {
                        ++info.extras;
                        ++info.extras;
                    }

                    info.base = static_cast<V>(2);
                    break;
                }

                case fmt_type::fmt_type_x: {
                    if (ops.alternate_form()) {
                        ++info.extras;
                        ++info.extras;
                    }

                    info.base = static_cast<V>(16);
                    break;
                }

                case fmt_type::fmt_type_c:
                case fmt_type::fmt_type_d:
                case fmt_type::fmt_type_s:
                case fmt_type::fmt_type_default: {
                    info.base = static_cast<V>(10);
                    break;
                }
            }

            switch (ops.sign()) {
                case fmt_sign::fmt_sign_pos_neg: {
                    if (is_signed<V>::value && (val < static_cast<V>(0))) {
                        val = -val;
                    }
                    ++info.extras;
                    break;
                }

                case fmt_sign::fmt_sign_space_for_pos: {
                    if (is_signed<V>::value && (val < static_cast<V>(0))) {
                        val = -val;
                    }
                    ++info.extras;
                    break;
                }

                case fmt_sign::fmt_sign_neg_only: {
                    if (is_signed<V>::value && (val < static_cast<V>(0))) {
                        val = -val;
                        ++info.extras;
                    }
                    break;
                }
            }

            if (static_cast<V>(0) == val) {
                ++info.digits;
            }
            else {
                while (val > static_cast<V>(0)) {
                    ++info.digits;
                    info.reversed = (info.reversed * info.base) + (val % info.base);
                    val /= info.base;
                }
            }

            return info;
        }

        /// <!-- description -->
        ///   @brief This function is responsible for implementing the guts
        ///     for integral types. For integrals, all of the fmt options
        ///     must be accounted for.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam OUT the type of out (i.e., debug, alert, etc)
        ///   @param o the instance of out<T> to output to
        ///   @param ops ops the fmt options used to format the output
        ///   @param val the integral being outputted
        ///
        template<typename OUT, typename V>
        constexpr void
        fmt_impl_integral(OUT &&o, fmt_options const &ops, V const val) noexcept
        {
            fmt_impl_integral_info<V> info{get_integral_info(ops, val)};

            bsl::uintmax const padding{
                fmt_impl_align_pre(o, ops, info.digits + info.extras, false)};

            if (is_signed<V>::value) {
                switch (ops.sign()) {
                    case fmt_sign::fmt_sign_pos_neg: {
                        o.write((val < static_cast<V>(0)) ? '-' : '+');
                        break;
                    }

                    case fmt_sign::fmt_sign_space_for_pos: {
                        o.write((val < static_cast<V>(0)) ? '-' : ' ');
                        break;
                    }

                    case fmt_sign::fmt_sign_neg_only: {
                        if (val < static_cast<V>(0)) {
                            o.write('-');
                        }

                        break;
                    }
                }
            }

            if (ops.alternate_form()) {
                switch (ops.type()) {
                    case fmt_type::fmt_type_b: {
                        o.write("0b");
                        break;
                    }

                    case fmt_type::fmt_type_x: {
                        o.write("0x");
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

            if (ops.sign_aware()) {
                for (bsl::uintmax i{}; i < padding; ++i) {
                    o.write('0');
                }
            }

            for (bsl::uintmax i{info.digits}; i > 0U; --i) {
                V digit{static_cast<V>(info.reversed % info.base)};
                if (digit > static_cast<V>(9)) {
                    digit += static_cast<V>(static_cast<V>('A') - static_cast<V>(10));
                }
                else {
                    digit += static_cast<V>('0');
                }

                o.write(static_cast<char_type>(digit));
                info.reversed /= info.base;
            }

            fmt_impl_align_suf(o, ops, info.digits + info.extras, false);
        }
    }
}

#endif
