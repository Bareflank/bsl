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

#include "fmt_impl_align.hpp"
#include "fmt_impl_integral_helpers.hpp"
#include "out.hpp"

#include "../char_type.hpp"
#include "../cstdint.hpp"
#include "../enable_if.hpp"
#include "../fmt_options.hpp"
#include "../is_integral.hpp"

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
    ///   @tparam OUT the type of out (i.e., debug, alert, etc)
    ///   @param o the instance of out<T> to output to
    ///   @param ops ops the fmt options used to format the output
    ///   @param val the integral being outputted
    ///
    template<typename OUT, typename V, enable_if_t<is_integral<V>::value, bool> = true>
    constexpr void
    fmt_impl(OUT &&o, fmt_options const &ops, V const val) noexcept
    {
        switch (ops.type()) {
            case fmt_type::fmt_type_b:
            case fmt_type::fmt_type_d:
            case fmt_type::fmt_type_x:
            case fmt_type::fmt_type_default: {
                fmt_impl_integral(bsl::forward<OUT>(o), ops, val);
                break;
            }

            case fmt_type::fmt_type_c:
            case fmt_type::fmt_type_s: {
                details::fmt_impl_align_pre(o, ops, 1U, true);
                o.write(static_cast<char_type>(val));
                details::fmt_impl_align_suf(o, ops, 1U, true);
                break;
            }
        }
    }

    /// <!-- description -->
    ///   @brief Outputs the provided integral to the provided
    ///     output type.
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of outputter provided
    ///   @param o the instance of the outputter used to output the value.
    ///   @param val the integral to output
    ///   @return return o
    ///
    template<typename T, typename V, enable_if_t<is_integral<V>::value, bool> = true>
    [[maybe_unused]] constexpr out<T>
    operator<<(out<T> const o, V val) noexcept
    {
        if constexpr (o.empty()) {
            return o;
        }

        if (is_signed<V>::value && (val < static_cast<V>(0))) {
            o.write('-');
            val = -val;
        }

        if (static_cast<V>(0) == val) {
            o.write('0');
        }
        else {
            V reversed{};
            bsl::uintmax digits{};

            while (val > static_cast<V>(0)) {
                ++digits;
                reversed = (reversed * static_cast<V>(10)) + (val % static_cast<V>(10));
                val /= static_cast<V>(10);
            }

            for (bsl::uintmax i{digits}; i > 0U; --i) {
                V const digit{static_cast<V>(reversed % static_cast<V>(10))};
                o.write(static_cast<char_type>(digit + static_cast<V>('0')));
                reversed /= static_cast<V>(10);
            }
        }

        return o;
    }
}

#endif
