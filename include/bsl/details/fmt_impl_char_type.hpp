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

#ifndef BSL_DETAILS_FMT_IMPL_CHAR_TYPE_HPP
#define BSL_DETAILS_FMT_IMPL_CHAR_TYPE_HPP

#include "fmt_impl_align.hpp"
#include "fmt_impl_integral_helpers.hpp"
#include "out.hpp"

#include "../convert.hpp"
#include "../char_type.hpp"
#include "../forward.hpp"
#include "../fmt_options.hpp"

namespace bsl
{
    /// <!-- description -->
    ///   @brief This function is responsible for implementing bsl::fmt
    ///     for character types. For chars, the only fmt options
    ///     that are available are alignment, fill and width, all of which
    ///     are handled by the fmt_impl_align_xxx functions.
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
    ///   @param c the character being outputted
    ///
    template<typename OUT>
    constexpr void
    fmt_impl(OUT &&o, fmt_options const &ops, char_type const c) noexcept
    {
        switch (ops.type()) {
            case fmt_type::fmt_type_b:
            case fmt_type::fmt_type_d:
            case fmt_type::fmt_type_x: {
                details::fmt_impl_integral(bsl::forward<OUT>(o), ops, to_u8(c));
                break;
            }

            case fmt_type::fmt_type_c:
            case fmt_type::fmt_type_s:
            case fmt_type::fmt_type_default: {
                details::fmt_impl_align_pre(o, ops, to_umax(1), true);
                o.write(c);
                details::fmt_impl_align_suf(o, ops, to_umax(1), true);
                break;
            }
        }
    }

    /// <!-- description -->
    ///   @brief Outputs the provided char_type to the provided
    ///     output type.
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of outputter provided
    ///   @param o the instance of the outputter used to output the value.
    ///   @param c the char_type to output
    ///   @return return o
    ///
    template<typename T>
    [[maybe_unused]] constexpr out<T>
    operator<<(out<T> const o, char_type const c) noexcept
    {
        if constexpr (!o) {
            return o;
        }

        o.write(c);
        return o;
    }
}

#endif
