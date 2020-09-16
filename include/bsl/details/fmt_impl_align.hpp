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

#include "../convert.hpp"
#include "../fmt_options.hpp"
#include "../safe_integral.hpp"
#include "../touch.hpp"

namespace bsl::details
{
    /// <!-- description -->
    ///   @brief This implements alignment for all of the fmt_impl
    ///     functions. Once the impl functions know what the total length
    ///     of their output will be, this function will output padding
    ///     as needed given whatever width, alignment and fill type the
    ///     user provided. This specific version will output the padding
    ///     on the left side.
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam OUT_T the type of out (i.e., debug, alert, etc)
    ///   @param o the instance of out<T> to output to
    ///   @param ops ops the fmt options used to format the output
    ///   @param len the length of the output the fmt_impl function will
    ///      use up. The align functions will use the rest.
    ///   @param left true if the default behavior is to left align, false
    ///     otherwise
    ///   @return Returns the size of the padding
    ///
    template<typename OUT_T>
    [[maybe_unused]] constexpr auto
    fmt_impl_align_pre(
        OUT_T const &o, fmt_options const &ops, safe_uintmax const &len, bool const left) noexcept
        -> safe_uintmax
    {
        safe_uintmax padding{};

        if (len < ops.width()) {
            padding = ops.width() - len;
        }
        else {
            padding = to_umax(0);
        }

        if (!ops.sign_aware()) {
            if (padding != to_umax(0)) {
                switch (ops.align()) {
                    case fmt_align::fmt_align_left: {
                        break;
                    }

                    case fmt_align::fmt_align_center: {
                        safe_uintmax half{padding >> safe_uintmax::one()};
                        for (safe_uintmax cpi{}; cpi < half; ++cpi) {
                            o.write(ops.fill());
                        }
                        break;
                    }

                    case fmt_align::fmt_align_right: {
                        for (safe_uintmax rpi{}; rpi < padding; ++rpi) {
                            o.write(ops.fill());
                        }
                        break;
                    }

                    case fmt_align::fmt_align_default: {
                        if (!left) {
                            for (safe_uintmax dpi{}; dpi < padding; ++dpi) {
                                o.write(ops.fill());
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
    ///   @tparam OUT_T the type of out (i.e., debug, alert, etc)
    ///   @param o the instance of out<T> to output to
    ///   @param ops ops the fmt options used to format the output
    ///   @param len the length of the output the fmt_impl function will
    ///      use up. The align functions will use the rest.
    ///   @param left true if the default behavior is to left align, false
    ///     otherwise
    ///
    template<typename OUT_T>
    constexpr auto
    fmt_impl_align_suf(
        OUT_T const &o, fmt_options const &ops, safe_uintmax const &len, bool const left) noexcept
        -> void
    {
        safe_uintmax padding{};

        if (len < ops.width()) {
            padding = ops.width() - len;
        }
        else {
            padding = to_umax(0);
        }

        if (!ops.sign_aware()) {
            if (padding != to_umax(0)) {
                switch (ops.align()) {
                    case fmt_align::fmt_align_left: {
                        for (safe_uintmax lpi{}; lpi < padding; ++lpi) {
                            o.write(ops.fill());
                        }
                        break;
                    }

                    case fmt_align::fmt_align_center: {
                        safe_uintmax half{padding - (padding >> safe_uintmax::one())};
                        for (safe_uintmax cpi{}; cpi < half; ++cpi) {
                            o.write(ops.fill());
                        }
                        break;
                    }

                    case fmt_align::fmt_align_right: {
                        break;
                    }

                    case fmt_align::fmt_align_default: {
                        if (left) {
                            for (safe_uintmax dpi{}; dpi < padding; ++dpi) {
                                o.write(ops.fill());
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
