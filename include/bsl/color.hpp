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

#include "cstr_type.hpp"

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
    // Defining colors using octals is the standard way of doing this. WRT to
    // the use of a lower case name, we want these to mimic C++
    // NOLINTNEXTLINE(bsl-literals-no-octal, bsl-name-case)
    constexpr cstr_type reset_color{details::if_color_enabled("\033[0m")};
    /// @brief resets the color output of debug statements
    // Defining colors using octals is the standard way of doing this. WRT to
    // the use of a lower case name, we want these to mimic C++
    // NOLINTNEXTLINE(bsl-literals-no-octal, bsl-name-case)
    constexpr cstr_type rst{details::if_color_enabled("\033[0m")};

    /// @brief changes the foreground color to normal black
    // Defining colors using octals is the standard way of doing this. WRT to
    // the use of a lower case name, we want these to mimic C++
    // NOLINTNEXTLINE(bsl-literals-no-octal, bsl-name-case)
    constexpr cstr_type black{details::if_color_enabled("\033[0;90m")};
    /// @brief changes the foreground color to normal black
    // Defining colors using octals is the standard way of doing this. WRT to
    // the use of a lower case name, we want these to mimic C++
    // NOLINTNEXTLINE(bsl-literals-no-octal, bsl-name-case)
    constexpr cstr_type blk{details::if_color_enabled("\033[0;90m")};
    /// @brief changes the foreground color to normal red
    // Defining colors using octals is the standard way of doing this. WRT to
    // the use of a lower case name, we want these to mimic C++
    // NOLINTNEXTLINE(bsl-literals-no-octal, bsl-name-case)
    constexpr cstr_type red{details::if_color_enabled("\033[0;91m")};
    /// @brief changes the foreground color to normal green
    // Defining colors using octals is the standard way of doing this. WRT to
    // the use of a lower case name, we want these to mimic C++
    // NOLINTNEXTLINE(bsl-literals-no-octal, bsl-name-case)
    constexpr cstr_type green{details::if_color_enabled("\033[0;92m")};
    /// @brief changes the foreground color to normal green
    // Defining colors using octals is the standard way of doing this. WRT to
    // the use of a lower case name, we want these to mimic C++
    // NOLINTNEXTLINE(bsl-literals-no-octal, bsl-name-case)
    constexpr cstr_type grn{details::if_color_enabled("\033[0;92m")};
    /// @brief changes the foreground color to normal yellow
    // Defining colors using octals is the standard way of doing this. WRT to
    // the use of a lower case name, we want these to mimic C++
    // NOLINTNEXTLINE(bsl-literals-no-octal, bsl-name-case)
    constexpr cstr_type yellow{details::if_color_enabled("\033[0;93m")};
    /// @brief changes the foreground color to normal yellow
    // Defining colors using octals is the standard way of doing this. WRT to
    // the use of a lower case name, we want these to mimic C++
    // NOLINTNEXTLINE(bsl-literals-no-octal, bsl-name-case)
    constexpr cstr_type ylw{details::if_color_enabled("\033[0;93m")};
    /// @brief changes the foreground color to normal blue
    // Defining colors using octals is the standard way of doing this. WRT to
    // the use of a lower case name, we want these to mimic C++
    // NOLINTNEXTLINE(bsl-literals-no-octal, bsl-name-case)
    constexpr cstr_type blue{details::if_color_enabled("\033[0;94m")};
    /// @brief changes the foreground color to normal blue
    // Defining colors using octals is the standard way of doing this. WRT to
    // the use of a lower case name, we want these to mimic C++
    // NOLINTNEXTLINE(bsl-literals-no-octal, bsl-name-case)
    constexpr cstr_type blu{details::if_color_enabled("\033[0;94m")};
    /// @brief changes the foreground color to normal magenta
    // Defining colors using octals is the standard way of doing this. WRT to
    // the use of a lower case name, we want these to mimic C++
    // NOLINTNEXTLINE(bsl-literals-no-octal, bsl-name-case)
    constexpr cstr_type magenta{details::if_color_enabled("\033[0;95m")};
    /// @brief changes the foreground color to normal magenta
    // Defining colors using octals is the standard way of doing this. WRT to
    // the use of a lower case name, we want these to mimic C++
    // NOLINTNEXTLINE(bsl-literals-no-octal, bsl-name-case)
    constexpr cstr_type mag{details::if_color_enabled("\033[0;95m")};
    /// @brief changes the foreground color to normal cyan
    // Defining colors using octals is the standard way of doing this. WRT to
    // the use of a lower case name, we want these to mimic C++
    // NOLINTNEXTLINE(bsl-literals-no-octal, bsl-name-case)
    constexpr cstr_type cyan{details::if_color_enabled("\033[0;96m")};
    /// @brief changes the foreground color to normal cyan
    // Defining colors using octals is the standard way of doing this. WRT to
    // the use of a lower case name, we want these to mimic C++
    // NOLINTNEXTLINE(bsl-literals-no-octal, bsl-name-case)
    constexpr cstr_type cyn{details::if_color_enabled("\033[0;96m")};
    /// @brief changes the foreground color to normal white
    // Defining colors using octals is the standard way of doing this. WRT to
    // the use of a lower case name, we want these to mimic C++
    // NOLINTNEXTLINE(bsl-literals-no-octal, bsl-name-case)
    constexpr cstr_type white{details::if_color_enabled("\033[0;97m")};
    /// @brief changes the foreground color to normal white
    // Defining colors using octals is the standard way of doing this. WRT to
    // the use of a lower case name, we want these to mimic C++
    // NOLINTNEXTLINE(bsl-literals-no-octal, bsl-name-case)
    constexpr cstr_type wht{details::if_color_enabled("\033[0;97m")};

    /// @brief changes the foreground color to bold black
    // Defining colors using octals is the standard way of doing this. WRT to
    // the use of a lower case name, we want these to mimic C++
    // NOLINTNEXTLINE(bsl-literals-no-octal, bsl-name-case)
    constexpr cstr_type bold_black{details::if_color_enabled("\033[1;90m")};
    /// @brief changes the foreground color to bold black
    // Defining colors using octals is the standard way of doing this. WRT to
    // the use of a lower case name, we want these to mimic C++
    // NOLINTNEXTLINE(bsl-literals-no-octal, bsl-name-case)
    constexpr cstr_type bold_blk{details::if_color_enabled("\033[1;90m")};
    /// @brief changes the foreground color to bold red
    // Defining colors using octals is the standard way of doing this. WRT to
    // the use of a lower case name, we want these to mimic C++
    // NOLINTNEXTLINE(bsl-literals-no-octal, bsl-name-case)
    constexpr cstr_type bold_red{details::if_color_enabled("\033[1;91m")};
    /// @brief changes the foreground color to bold green
    // Defining colors using octals is the standard way of doing this. WRT to
    // the use of a lower case name, we want these to mimic C++
    // NOLINTNEXTLINE(bsl-literals-no-octal, bsl-name-case)
    constexpr cstr_type bold_green{details::if_color_enabled("\033[1;92m")};
    /// @brief changes the foreground color to bold green
    // Defining colors using octals is the standard way of doing this. WRT to
    // the use of a lower case name, we want these to mimic C++
    // NOLINTNEXTLINE(bsl-literals-no-octal, bsl-name-case)
    constexpr cstr_type bold_grn{details::if_color_enabled("\033[1;92m")};
    /// @brief changes the foreground color to bold yellow
    // Defining colors using octals is the standard way of doing this. WRT to
    // the use of a lower case name, we want these to mimic C++
    // NOLINTNEXTLINE(bsl-literals-no-octal, bsl-name-case)
    constexpr cstr_type bold_yellow{details::if_color_enabled("\033[1;93m")};
    /// @brief changes the foreground color to bold yellow
    // Defining colors using octals is the standard way of doing this. WRT to
    // the use of a lower case name, we want these to mimic C++
    // NOLINTNEXTLINE(bsl-literals-no-octal, bsl-name-case)
    constexpr cstr_type bold_ylw{details::if_color_enabled("\033[1;93m")};
    /// @brief changes the foreground color to bold blue
    // Defining colors using octals is the standard way of doing this. WRT to
    // the use of a lower case name, we want these to mimic C++
    // NOLINTNEXTLINE(bsl-literals-no-octal, bsl-name-case)
    constexpr cstr_type bold_blue{details::if_color_enabled("\033[1;94m")};
    /// @brief changes the foreground color to bold blue
    // Defining colors using octals is the standard way of doing this. WRT to
    // the use of a lower case name, we want these to mimic C++
    // NOLINTNEXTLINE(bsl-literals-no-octal, bsl-name-case)
    constexpr cstr_type bold_blu{details::if_color_enabled("\033[1;94m")};
    /// @brief changes the foreground color to bold magenta
    // Defining colors using octals is the standard way of doing this. WRT to
    // the use of a lower case name, we want these to mimic C++
    // NOLINTNEXTLINE(bsl-literals-no-octal, bsl-name-case)
    constexpr cstr_type bold_magenta{details::if_color_enabled("\033[1;95m")};
    /// @brief changes the foreground color to bold magenta
    // Defining colors using octals is the standard way of doing this. WRT to
    // the use of a lower case name, we want these to mimic C++
    // NOLINTNEXTLINE(bsl-literals-no-octal, bsl-name-case)
    constexpr cstr_type bold_mag{details::if_color_enabled("\033[1;95m")};
    /// @brief changes the foreground color to bold cyan
    // Defining colors using octals is the standard way of doing this. WRT to
    // the use of a lower case name, we want these to mimic C++
    // NOLINTNEXTLINE(bsl-literals-no-octal, bsl-name-case)
    constexpr cstr_type bold_cyan{details::if_color_enabled("\033[1;96m")};
    /// @brief changes the foreground color to bold cyan
    // Defining colors using octals is the standard way of doing this. WRT to
    // the use of a lower case name, we want these to mimic C++
    // NOLINTNEXTLINE(bsl-literals-no-octal, bsl-name-case)
    constexpr cstr_type bold_cyn{details::if_color_enabled("\033[1;96m")};
    /// @brief changes the foreground color to bold white
    // Defining colors using octals is the standard way of doing this. WRT to
    // the use of a lower case name, we want these to mimic C++
    // NOLINTNEXTLINE(bsl-literals-no-octal, bsl-name-case)
    constexpr cstr_type bold_white{details::if_color_enabled("\033[1;97m")};
    /// @brief changes the foreground color to bold white
    // Defining colors using octals is the standard way of doing this. WRT to
    // the use of a lower case name, we want these to mimic C++
    // NOLINTNEXTLINE(bsl-literals-no-octal, bsl-name-case)
    constexpr cstr_type bold_wht{details::if_color_enabled("\033[1;97m")};
}

#endif
