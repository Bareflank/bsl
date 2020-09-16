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

#ifndef BSL_OUT_TYPE_HPP
#define BSL_OUT_TYPE_HPP

#include "out_type_empty.hpp"
#include "out.hpp"

#include "../bool_constant.hpp"
#include "../conditional.hpp"
#include "../cstdint.hpp"
#include "../disjunction.hpp"

namespace bsl::details
{
    // clang-format off

    /// @brief used to disable debugging for debug() and alert()
    ///
    /// <!-- template parameters -->
    ///   @tparam DL the debug level this out statement uses
    ///   @tparam T the type of out statement being used
    ///
    template<bsl::uintmax DL, typename T>
    using out_type =
        conditional_t <
        disjunction<
            bool_constant<DL < BSL_DEBUG_LEVEL>, bool_constant<DL == BSL_DEBUG_LEVEL>>::value,
            out<T>,
            out<out_type_empty>>;
}

#endif
