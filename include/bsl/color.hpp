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
/// @file color.hpp
///

#ifndef BSL_COLOR_HPP
#define BSL_COLOR_HPP

#include "string_view.hpp"

namespace bsl
{
    namespace details
    {
        /// <!-- description -->
        ///   @brief Returns val if color is enabled, "" otherwise
        ///
        /// <!-- inputs/outputs -->
        ///   @param val the color to return if color is enabled
        ///   @return Returns val if color is enabled, "" otherwise
        ///
        [[nodiscard]] constexpr auto
        if_color_enabled(cstr_type const val) noexcept -> cstr_type
        {
            if constexpr (ENABLE_COLOR) {
                return val;
            }

            return "";
        }
    }

    /// @brief resets the color output of debug statements
    constexpr string_view rst{details::if_color_enabled("\033[0m")};

    /// @brief changes the foreground color to normal black
    constexpr string_view blk{details::if_color_enabled("\033[0;90m")};
    /// @brief changes the foreground color to normal red
    constexpr string_view red{details::if_color_enabled("\033[0;91m")};
    /// @brief changes the foreground color to normal green
    constexpr string_view grn{details::if_color_enabled("\033[0;92m")};
    /// @brief changes the foreground color to normal yellow
    constexpr string_view ylw{details::if_color_enabled("\033[0;93m")};
    /// @brief changes the foreground color to normal blue
    constexpr string_view blu{details::if_color_enabled("\033[0;94m")};
    /// @brief changes the foreground color to normal magenta
    constexpr string_view mag{details::if_color_enabled("\033[0;95m")};
    /// @brief changes the foreground color to normal cyan
    constexpr string_view cyn{details::if_color_enabled("\033[0;96m")};
    /// @brief changes the foreground color to normal white
    constexpr string_view wht{details::if_color_enabled("\033[0;97m")};

    /// @brief changes the foreground color to bold black
    constexpr string_view bold_blk{details::if_color_enabled("\033[1;90m")};
    /// @brief changes the foreground color to bold red
    constexpr string_view bold_red{details::if_color_enabled("\033[1;91m")};
    /// @brief changes the foreground color to bold green
    constexpr string_view bold_grn{details::if_color_enabled("\033[1;92m")};
    /// @brief changes the foreground color to bold yellow
    constexpr string_view bold_ylw{details::if_color_enabled("\033[1;93m")};
    /// @brief changes the foreground color to bold blue
    constexpr string_view bold_blu{details::if_color_enabled("\033[1;94m")};
    /// @brief changes the foreground color to bold magenta
    constexpr string_view bold_mag{details::if_color_enabled("\033[1;95m")};
    /// @brief changes the foreground color to bold cyan
    constexpr string_view bold_cyn{details::if_color_enabled("\033[1;96m")};
    /// @brief changes the foreground color to bold white
    constexpr string_view bold_wht{details::if_color_enabled("\033[1;97m")};
}

#endif
