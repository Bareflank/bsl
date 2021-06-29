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

#ifndef BSL_DETAILS_FMT_IMPL_STRING_VIEW_HPP
#define BSL_DETAILS_FMT_IMPL_STRING_VIEW_HPP

#include "../basic_string_view.hpp"
#include "../fmt_options.hpp"
#include "fmt_impl_align.hpp"
#include "out.hpp"

namespace bsl
{
    /// <!-- description -->
    ///   @brief This function is responsible for implementing bsl::fmt
    ///     for string_view types. For strings, the only fmt options
    ///     that are available are alignment, fill and width, all of which
    ///     are handled by the fmt_impl_align_xxx functions.
    ///   @related bsl::basic_string_view
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam OUT_T the type of out (i.e., debug, alert, etc)
    ///   @tparam CHAR_T the type of characters in the string
    ///   @param o the instance of out<T> to output to
    ///   @param ops ops the fmt options used to format the output
    ///   @param str the string_view being outputted
    ///
    template<typename OUT_T, typename CHAR_T>
    constexpr void
    fmt_impl(OUT_T &&o, fmt_options const &ops, basic_string_view<CHAR_T> const &str) noexcept
    {
        details::fmt_impl_align_pre(o, ops, str.length(), true);
        o.write(str.data());
        details::fmt_impl_align_suf(o, ops, str.length(), true);
    }

    /// <!-- description -->
    ///   @brief Outputs the provided bsl::basic_string_view to the provided
    ///     output type.
    ///   @related bsl::basic_string_view
    ///   @include basic_string_view/example_basic_string_view_ostream.hpp
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of outputter provided
    ///   @tparam CHAR_T the type of characters in the string
    ///   @param o the instance of the outputter used to output the value.
    ///   @param str the basic_string_view to output
    ///   @return return o
    ///
    template<typename T, typename CHAR_T>
    [[maybe_unused]] constexpr auto
    operator<<(out<T> const o, basic_string_view<CHAR_T> const &str) noexcept -> out<T>
    {
        if (is_constant_evaluated()) {
            if (unlikely(!str)) {
                return o;
            }

            return o;
        }

        if constexpr (!o) {
            return o;
        }

        if (unlikely(!str)) {
            o.write("[empty bsl::string_view]");
            return o;
        }

        o.write(str.data());
        return o;
    }
}

#endif
