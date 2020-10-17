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
///
/// @file fmt_type.hpp
///

#ifndef BSL_FMT_TYPE_HPP
#define BSL_FMT_TYPE_HPP

#include "cstdint.hpp"

namespace bsl
{
    /// <!-- description -->
    ///   @brief Used to determine how to output an unsigned integer
    ///     type (either as hex or dec). All ofther {fmt} types are
    ///     currently not supported and this has no effect on signed
    ///     integer types.
    ///
    enum class fmt_type : bsl::uint32
    {
        fmt_type_default = 0U,
        fmt_type_b = 1U,
        fmt_type_c = 2U,
        fmt_type_d = 3U,
        fmt_type_s = 4U,
        fmt_type_x = 5U,
    };
}

#endif
