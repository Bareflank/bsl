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

#ifndef BSL_DETAILS_FMT_IMPL_VOID_POINTER_HPP
#define BSL_DETAILS_FMT_IMPL_VOID_POINTER_HPP

#include "../fmt_options.hpp"
#include "../is_constant_evaluated.hpp"
#include "fmt_impl_integral_helpers.hpp"
#include "out.hpp"

namespace bsl
{
    /// <!-- description -->
    ///   @brief Outputs the provided pointer to the provided
    ///     output type.
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of outputter provided
    ///   @param o the instance of the outputter used to output the value.
    ///   @param ptr the pointer to output
    ///   @return return o
    ///
    template<typename T>
    [[maybe_unused]] constexpr auto
    operator<<(out<T> const o, void const *const ptr) noexcept -> out<T>
    {
        if (is_constant_evaluated()) {
            return o;
        }

        if constexpr (o.empty()) {
            return o;
        }

        if (nullptr == ptr) {
            o.write_to_console("nullptr");
        }
        else {
            // We must convert the pointer to an integer before we can use
            // output it. There is no math being performed to this number.
            details::fmt_impl_integral(    // --
                o,                         // --
                ptrops,                    // --
                // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
                safe_umx{reinterpret_cast<bsl::uintmx>(ptr)});
        }

        return o;
    }
}

#endif
