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

#ifndef BSL_DETAILS_FMT_IMPL_ALIGN_HPP
#define BSL_DETAILS_FMT_IMPL_ALIGN_HPP

#include "../fmt_align.hpp"
#include "../fmt_options.hpp"
#include "../safe_idx.hpp"
#include "../safe_integral.hpp"
#include "../touch.hpp"
#include "out.hpp"

namespace bsl::details
{
    /// <!-- description -->
    ///   @brief Returns the padding needed for alignment
    ///
    /// <!-- inputs/outputs -->
    ///   @param ops ops the fmt options used to format the output
    ///   @param len the length of the output the fmt_impl function will
    ///      use up. The align functions will use the rest.
    ///   @return Returns the padding needed for alignment
    ///
    [[nodiscard]] constexpr auto
    fmt_impl_align_padding(fmt_options const &ops, safe_umx const &len) noexcept -> safe_umx
    {
        /// NOTE:
        /// - We specifically look for overflow here to see if we need to
        ///   return 0 as this can happen and it is not an error, so we
        ///   mark the result as checked.
        ///

        if (len < ops.width()) {
            return (ops.width() - len).checked();
        }

        return {};
    }

    /// <!-- description -->
    ///   @brief This implements alignment for all of the fmt_impl
    ///     functions. Once the impl functions know what the total length
    ///     of their output will be, this function will output padding
    ///     as needed given whatever width, alignment and fill type the
    ///     user provided. This specific version will output the padding
    ///     on the left side.
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of out (i.e., debug, alert, etc)
    ///   @param o the instance of out<T> to output to
    ///   @param ops ops the fmt options used to format the output
    ///   @param len the length of the output the fmt_impl function will
    ///      use up. The align functions will use the rest.
    ///   @param left true if the default behavior is to left align, false
    ///     otherwise
    ///   @return Returns the size of the padding
    ///
    template<typename T>
    [[maybe_unused]] constexpr auto
    fmt_impl_align_pre(
        out<T> const o, fmt_options const &ops, safe_umx const &len, bool const left) noexcept
        -> safe_umx
    {
        auto const padding{fmt_impl_align_padding(ops, len)};

        /// NOTE:
        /// - The provided len cannot be invalid, otherwise this function
        ///   is undefined. Since len is valid, padding must also be valid,
        ///   and therefore the math below is all valid which is why it is
        ///   all marked as checked.
        ///

        if (!ops.sign_aware()) {
            if (padding != safe_umx::magic_0()) {
                switch (ops.align()) {
                    case fmt_align::fmt_align_left: {
                        break;
                    }

                    case fmt_align::fmt_align_center: {
                        auto const half{(padding >> safe_umx::magic_1()).checked()};
                        for (safe_idx mut_cpi{}; mut_cpi < half; ++mut_cpi) {
                            o.write_to_console(ops.fill());
                        }
                        break;
                    }

                    case fmt_align::fmt_align_right: {
                        for (safe_idx mut_rpi{}; mut_rpi < padding; ++mut_rpi) {
                            o.write_to_console(ops.fill());
                        }
                        break;
                    }

                    case fmt_align::fmt_align_default:
                        [[fallthrough]];
                    default: {
                        if (!left) {
                            for (safe_idx mut_dpi{}; mut_dpi < padding; ++mut_dpi) {
                                o.write_to_console(ops.fill());
                            }
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
        }
        else {
            bsl::touch();
        }

        return padding;
    }

    /// <!-- description -->
    ///   @brief This implements alignment for all of the fmt_impl
    ///     functions. Once the impl functions know what the total length
    ///     of their output will be, this function will output padding
    ///     as needed given whatever width, alignment and fill type the
    ///     user provided. This specific version will output the padding
    ///     on the right side.
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of out (i.e., debug, alert, etc)
    ///   @param o the instance of out<T> to output to
    ///   @param ops ops the fmt options used to format the output
    ///   @param len the length of the output the fmt_impl function will
    ///      use up. The align functions will use the rest.
    ///   @param left true if the default behavior is to left align, false
    ///     otherwise
    ///
    template<typename T>
    constexpr void
    fmt_impl_align_suf(
        out<T> const o, fmt_options const &ops, safe_umx const &len, bool const left) noexcept
    {
        auto const padding{fmt_impl_align_padding(ops, len)};

        /// NOTE:
        /// - The provided len cannot be invalid, otherwise this function
        ///   is undefined. Since len is valid, padding must also be valid,
        ///   and therefore the math below is all valid which is why it is
        ///   all marked as checked.
        ///

        if (!ops.sign_aware()) {
            if (padding != safe_umx::magic_0()) {
                switch (ops.align()) {
                    case fmt_align::fmt_align_left: {
                        for (safe_idx mut_lpi{}; mut_lpi < padding; ++mut_lpi) {
                            o.write_to_console(ops.fill());
                        }
                        break;
                    }

                    case fmt_align::fmt_align_center: {
                        auto const half{(padding - (padding >> safe_umx::magic_1())).checked()};
                        for (safe_idx mut_cpi{}; mut_cpi < half; ++mut_cpi) {
                            o.write_to_console(ops.fill());
                        }
                        break;
                    }

                    case fmt_align::fmt_align_right: {
                        break;
                    }

                    case fmt_align::fmt_align_default:
                        [[fallthrough]];
                    default: {
                        if (left) {
                            for (safe_idx mut_dpi{}; mut_dpi < padding; ++mut_dpi) {
                                o.write_to_console(ops.fill());
                            }
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
        }
        else {
            bsl::touch();
        }
    }
}

#endif
