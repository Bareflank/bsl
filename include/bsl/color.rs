// @copyright
// Copyright (C) 2020 Assured Information Security, Inc.
//
// @copyright
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// @copyright
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// @copyright
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

/// <!-- description -->
///   @brief Returns val if color is enabled, "" otherwise
///
/// <!-- inputs/outputs -->
///   @param val the color to return if color is enabled
///   @return Returns val if color is enabled, "" otherwise
///
#[cfg(not(feature = "disable_color"))]
const fn if_color_enabled(val: &str) -> &str {
    return val;
}

/// <!-- description -->
///   @brief Returns val if color is enabled, "" otherwise
///
/// <!-- inputs/outputs -->
///   @param val the color to return if color is enabled
///   @return Returns val if color is enabled, "" otherwise
///
#[cfg(feature = "disable_color")]
const fn if_color_enabled(val: &str) -> &str {
    return "";
}

/// @brief resets the color output of debug statements
#[allow(non_upper_case_globals)]
pub const rst: &str = if_color_enabled("\x1B[0m");

/// @brief changes the foreground color to normal black
#[allow(non_upper_case_globals)]
pub const blk: &str = if_color_enabled("\x1B[0;90m");
/// @brief changes the foreground color to normal red
#[allow(non_upper_case_globals)]
pub const red: &str = if_color_enabled("\x1B[0;91m");
/// @brief changes the foreground color to normal green
#[allow(non_upper_case_globals)]
pub const grn: &str = if_color_enabled("\x1B[0;92m");
/// @brief changes the foreground color to normal yellow
#[allow(non_upper_case_globals)]
pub const ylw: &str = if_color_enabled("\x1B[0;93m");
/// @brief changes the foreground color to normal blue
#[allow(non_upper_case_globals)]
pub const blu: &str = if_color_enabled("\x1B[0;94m");
/// @brief changes the foreground color to normal magenta
#[allow(non_upper_case_globals)]
pub const mag: &str = if_color_enabled("\x1B[0;95m");
/// @brief changes the foreground color to normal cyan
#[allow(non_upper_case_globals)]
pub const cyn: &str = if_color_enabled("\x1B[0;96m");
/// @brief changes the foreground color to normal white
#[allow(non_upper_case_globals)]
pub const wht: &str = if_color_enabled("\x1B[0;97m");

/// @brief changes the foreground color to bold black
#[allow(non_upper_case_globals)]
pub const bold_blk: &str = if_color_enabled("\x1B[1;90m");
/// @brief changes the foreground color to bold red
#[allow(non_upper_case_globals)]
pub const bold_red: &str = if_color_enabled("\x1B[1;91m");
/// @brief changes the foreground color to bold green
#[allow(non_upper_case_globals)]
pub const bold_grn: &str = if_color_enabled("\x1B[1;92m");
/// @brief changes the foreground color to bold yellow
#[allow(non_upper_case_globals)]
pub const bold_ylw: &str = if_color_enabled("\x1B[1;93m");
/// @brief changes the foreground color to bold blue
#[allow(non_upper_case_globals)]
pub const bold_blu: &str = if_color_enabled("\x1B[1;94m");
/// @brief changes the foreground color to bold magenta
#[allow(non_upper_case_globals)]
pub const bold_mag: &str = if_color_enabled("\x1B[1;95m");
/// @brief changes the foreground color to bold cyan
#[allow(non_upper_case_globals)]
pub const bold_cyn: &str = if_color_enabled("\x1B[1;96m");
/// @brief changes the foreground color to bold white
#[allow(non_upper_case_globals)]
pub const bold_wht: &str = if_color_enabled("\x1B[1;97m");

// -----------------------------------------------------------------------------
// Unit Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod test_color {
    use super::*;

    #[test]
    fn color_general() {
        assert!(bold_wht == if_color_enabled(bold_wht));

        println!("{}blk{}", blk, rst);
        println!("{}red{}", red, rst);
        println!("{}grn{}", grn, rst);
        println!("{}ylw{}", ylw, rst);
        println!("{}blu{}", blu, rst);
        println!("{}mag{}", mag, rst);
        println!("{}cyn{}", cyn, rst);
        println!("{}wht{}", wht, rst);

        println!("{}bold_blk{}", bold_blk, rst);
        println!("{}bold_red{}", bold_red, rst);
        println!("{}bold_grn{}", bold_grn, rst);
        println!("{}bold_ylw{}", bold_ylw, rst);
        println!("{}bold_blu{}", bold_blu, rst);
        println!("{}bold_mag{}", bold_mag, rst);
        println!("{}bold_cyn{}", bold_cyn, rst);
        println!("{}bold_wht{}", bold_wht, rst);
    }
}
