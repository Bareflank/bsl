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

#ifndef BSL_DETAILS_FMT_FSM_HPP
#define BSL_DETAILS_FMT_FSM_HPP

#include "../cstdint.hpp"

namespace bsl::details
{
    /// @enum bsl::details::fmt_fsm
    ///
    /// <!-- description -->
    ///   @brief Used to define a finite state machine that is used to
    ///     parse the {fmt} style syntax for formatting. Although there
    ///     are many ways to implement a parser, the FSM proved to be
    ///     a really simple approach, even though the FSM in this case
    ///     is overly simplified. What makes this approach so simple is
    ///     each field is accounted for in the FSM, yet each parser is
    ///     optional based on what the user provides, so everything is
    ///     accounted for.
    ///
    enum class fmt_fsm : bsl::uint32
    {
        fmt_fsm_align = 0U,
        fmt_fsm_sign = 1U,
        fmt_fsm_alternate_form = 2U,
        fmt_fsm_sign_aware = 3U,
        fmt_fsm_width = 4U,
        fmt_fsm_type = 5U,
    };
}

#endif
