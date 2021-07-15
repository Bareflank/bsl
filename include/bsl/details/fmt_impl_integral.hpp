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

#ifndef BSL_DETAILS_FMT_IMPL_INTEGRAL_HPP
#define BSL_DETAILS_FMT_IMPL_INTEGRAL_HPP

#include "../char_type.hpp"
#include "../enable_if.hpp"
#include "../fmt_options.hpp"
#include "../forward.hpp"
#include "../is_constant_evaluated.hpp"
#include "../is_integral.hpp"
#include "../is_signed.hpp"
#include "../safe_integral.hpp"
#include "../touch.hpp"
#include "../unlikely.hpp"
#include "fmt_impl_align.hpp"
#include "fmt_impl_integral_helpers.hpp"
#include "out.hpp"

namespace bsl
{
    /// <!-- description -->
    ///   @brief This function is responsible for implementing bsl::fmt
    ///     for integral types. For integral types with b, d, x and default,
    ///     this will call fmt_impl_integral_out which does the bulk of
    ///     the work. For c, this will output the integral as a character
    ///     type.
    ///
    /// <!-- notes -->
    ///   @note This function exists in the details folder because it is
    ///     private to the BSL, but it does not exist in the details namespace
    ///     as it can be overridden by the user to provide their own
    ///     fmt support for their own types.
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
    fmt_impl(out<OUT_T> const o, fmt_options const &ops, safe_integral<T> const &val) noexcept
    {
        constexpr safe_uintmax one{static_cast<bsl::uintmax>(1)};
        constexpr safe_uintmax size_of_error{static_cast<bsl::uintmax>(7)};

        if (is_constant_evaluated()) {
            return;
        }

        if (unlikely(!val)) {
            details::fmt_impl_align_pre(o, ops, size_of_error, true);
            o.write_to_console("[error]");
            details::fmt_impl_align_suf(o, ops, size_of_error, true);
            return;
        }

        switch (ops.type()) {
            case fmt_type::fmt_type_b:
            case fmt_type::fmt_type_d:
            case fmt_type::fmt_type_x:
            case fmt_type::fmt_type_default: {
                fmt_impl_integral(o, ops, val);
                break;
            }

            case fmt_type::fmt_type_c:
            case fmt_type::fmt_type_s: {
                details::fmt_impl_align_pre(o, ops, one, true);
                o.write_to_console(static_cast<char_type>(val.get()));
                details::fmt_impl_align_suf(o, ops, one, true);
                break;
            }
        }
    }

    /// <!-- description -->
    ///   @brief This function is responsible for implementing bsl::fmt
    ///     for integral types. For integral types with b, d, x and default,
    ///     this will call fmt_impl_integral_out which does the bulk of
    ///     the work. For c, this will output the integral as a character
    ///     type.
    ///
    /// <!-- notes -->
    ///   @note This function exists in the details folder because it is
    ///     private to the BSL, but it does not exist in the details namespace
    ///     as it can be overridden by the user to provide their own
    ///     fmt support for their own types.
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam OUT_T the type of out (i.e., debug, alert, etc)
    ///   @tparam T the type of integral to output
    ///   @param o the instance of out<T> to output to
    ///   @param ops ops the fmt options used to format the output
    ///   @param val the integral being outputted
    ///
    template<typename OUT_T, typename T, enable_if_t<is_integral<T>::value, bool> = true>
    constexpr void
    fmt_impl(out<OUT_T> const o, fmt_options const &ops, T const val) noexcept
    {
        fmt_impl(o, ops, safe_integral<T>{val});
    }

    /// <!-- description -->
    ///   @brief Outputs the provided integral to the provided
    ///     output type.
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T1 the type of outputter provided
    ///   @tparam T2 the type of integral to output
    ///   @param o the instance of the outputter used to output the value.
    ///   @param val the integral to output
    ///   @return return o
    ///
    template<typename T1, typename T2>
    [[maybe_unused]] constexpr auto
    operator<<(out<T1> const o, safe_integral<T2> const &val) noexcept -> out<T1>
    {
        if (is_constant_evaluated()) {
            if (unlikely(!val)) {
                return o;
            }

            return o;
        }

        if constexpr (!o) {
            return o;
        }

        if (unlikely(!val)) {
            o.write_to_console("[error]");
            return o;
        }

        details::fmt_impl_integral_info<T2> const info{
            details::get_integral_info<T2>(nullops, val)};

        if (val.is_zero()) {
            o.write_to_console('0');
        }
        else {
            if constexpr (is_signed<T2>::value) {
                if (val.is_neg()) {
                    o.write_to_console('-');
                }
                else {
                    bsl::touch();
                }
            }

            constexpr safe_uintmax one{static_cast<bsl::uintmax>(1)};
            for (safe_uintmax mut_i{info.digits}; mut_i.is_pos(); --mut_i) {
                o.write_to_console(*info.buf.at_if(mut_i - one));
            }
        }

        return o;
    }

    /// <!-- description -->
    ///   @brief Outputs the provided integral to the provided
    ///     output type.
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T1 the type of outputter provided
    ///   @tparam T2 the type of integral to output
    ///   @param o the instance of the outputter used to output the value.
    ///   @param val the integral to output
    ///   @return return o
    ///
    template<typename T1, typename T2, enable_if_t<is_integral<T2>::value, bool> = true>
    [[maybe_unused]] constexpr auto
    operator<<(out<T1> const o, T2 const val) noexcept -> out<T1>
    {
        return o << safe_integral<T2>(val);
    }
}

#endif
