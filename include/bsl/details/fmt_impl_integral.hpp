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
#include "../fmt_type.hpp"
#include "../is_constant_evaluated.hpp"
#include "../is_integral.hpp"
#include "../is_signed.hpp"
#include "../safe_idx.hpp"
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
        constexpr safe_umx size_of_error{static_cast<bsl::uintmx>(7)};

        if (is_constant_evaluated()) {
            return;
        }

        auto mut_val{val};
        if (unlikely(mut_val.is_poisoned())) {
            details::fmt_impl_align_pre(o, ops, size_of_error, true);
            o.write_to_console("[error]");
            details::fmt_impl_align_suf(o, ops, size_of_error, true);
            return;
        }

        switch (ops.type()) {
            case fmt_type::fmt_type_b:
                [[fallthrough]];
            case fmt_type::fmt_type_d:
                [[fallthrough]];
            case fmt_type::fmt_type_x:
                [[fallthrough]];
            case fmt_type::fmt_type_default: {
                fmt_impl_integral(o, ops, mut_val);
                break;
            }

            case fmt_type::fmt_type_c:
                [[fallthrough]];
            case fmt_type::fmt_type_s:
                [[fallthrough]];
            default: {
                details::fmt_impl_align_pre(o, ops, safe_umx::magic_1(), true);
                o.write_to_console(static_cast<char_type>(mut_val.get()));
                details::fmt_impl_align_suf(o, ops, safe_umx::magic_1(), true);
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
    ///   @param o the instance of out<T> to output to
    ///   @param ops ops the fmt options used to format the output
    ///   @param val the integral being outputted
    ///
    template<typename OUT_T>
    constexpr void
    fmt_impl(out<OUT_T> const o, fmt_options const &ops, safe_idx const &val) noexcept
    {
        fmt_impl(o, ops, safe_integral<bsl::uintmx>{val.get()});
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
    ///   @tparam OUT_T the type of outputter provided
    ///   @tparam T the type of integral to output
    ///   @param o the instance of the outputter used to output the value.
    ///   @param val the integral to output
    ///   @return return o
    ///
    template<typename OUT_T, typename T>
    [[maybe_unused]] constexpr auto
    operator<<(out<OUT_T> const o, safe_integral<T> const &val) noexcept -> out<OUT_T>
    {
        if (is_constant_evaluated()) {
            return o;
        }

        if constexpr (o.empty()) {
            return o;
        }

        auto mut_val{val};
        if (unlikely(mut_val.is_poisoned())) {
            o.write_to_console("[error]");
            return o;
        }

        if (mut_val.is_zero()) {
            o.write_to_console('0');
            return o;
        }

        auto const info{details::get_integral_info(nullops, mut_val)};
        if constexpr (is_signed<T>::value) {
            if (mut_val.is_neg()) {
                o.write_to_console('-');
            }
            else {
                bsl::touch();
            }
        }

        for (safe_idx mut_i{info.digits}; mut_i.is_pos(); --mut_i) {
            o.write_to_console(*info.buf.at_if((mut_i - safe_idx::magic_1()).get()));
        }

        return o;
    }

    /// <!-- description -->
    ///   @brief Outputs the provided integral to the provided
    ///     output type.
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam OUT_T the type of outputter provided
    ///   @param o the instance of the outputter used to output the value.
    ///   @param val the integral to output
    ///   @return return o
    ///
    template<typename OUT_T>
    [[maybe_unused]] constexpr auto
    operator<<(out<OUT_T> const o, safe_idx const &val) noexcept -> out<OUT_T>
    {
        return o << safe_integral<bsl::uintmx>{val.get()};
    }

    /// <!-- description -->
    ///   @brief Outputs the provided integral to the provided
    ///     output type.
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam OUT_T the type of outputter provided
    ///   @tparam T the type of integral to output
    ///   @param o the instance of the outputter used to output the value.
    ///   @param val the integral to output
    ///   @return return o
    ///
    template<typename OUT_T, typename T, enable_if_t<is_integral<T>::value, bool> = true>
    [[maybe_unused]] constexpr auto
    operator<<(out<OUT_T> const o, T const val) noexcept -> out<OUT_T>
    {
        return o << safe_integral<T>(val);
    }
}

#endif
