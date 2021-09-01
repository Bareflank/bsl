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

#include "../fmt_test.hpp"

#include <bsl/debug.hpp>
#include <bsl/ut.hpp>

/// <!-- description -->
///   @brief Main function for this unit test. If a call to bsl::ut_check() fails
///     the application will fast fail. If all calls to bsl::ut_check() pass, this
///     function will successfully return with bsl::exit_success.
///
/// <!-- inputs/outputs -->
///   @return Always returns bsl::exit_success.
///
[[nodiscard]] auto
main() noexcept -> bsl::exit_code
{
    bsl::ut_scenario{"bool with formatting type b"} = []() noexcept {
        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"b", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("1"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"b", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("0"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"10b", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("         1"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"10b", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("         0"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"<b", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("1"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"<b", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("0"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{">b", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("1"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{">b", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("0"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"^b", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("1"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"^b", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("0"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"<10b", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("1         "));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"<10b", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("0         "));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{">10b", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("         1"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{">10b", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("         0"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"^10b", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("    1     "));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"^10b", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("    0     "));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#<10b", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("1#########"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#<10b", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("0#########"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#>10b", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("#########1"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#>10b", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("#########0"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#^10b", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("####1#####"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#^10b", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("####0#####"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"<#10b", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("0b1       "));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"<#10b", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("0b0       "));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{">#10b", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("       0b1"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{">#10b", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("       0b0"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"^#10b", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("   0b1    "));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"^#10b", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("   0b0    "));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#<#10b", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("0b1#######"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#<#10b", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("0b0#######"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#>#10b", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("#######0b1"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#>#10b", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("#######0b0"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#^#10b", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("###0b1####"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#^#10b", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("###0b0####"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#b", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("0b1"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#b", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("0b0"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#10b", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("       0b1"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#10b", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("       0b0"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"0b", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("1"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"0b", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("0"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"010b", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("0000000001"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"010b", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("0000000000"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#010b", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("0b00000001"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#010b", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("0b00000000"));
            };
        };
    };

    bsl::ut_scenario{"bool with formatting type c"} = []() noexcept {
        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"c", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("1"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"c", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("0"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"10c", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("         1"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"10c", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("         0"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"<c", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("1"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"<c", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("0"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{">c", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("1"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{">c", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("0"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"^c", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("1"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"^c", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("0"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"<10c", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("1         "));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"<10c", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("0         "));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{">10c", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("         1"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{">10c", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("         0"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"^10c", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("    1     "));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"^10c", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("    0     "));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#<10c", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("1#########"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#<10c", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("0#########"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#>10c", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("#########1"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#>10c", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("#########0"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#^10c", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("####1#####"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#^10c", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("####0#####"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"<#10c", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("1         "));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"<#10c", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("0         "));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{">#10c", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("         1"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{">#10c", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("         0"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"^#10c", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("    1     "));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"^#10c", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("    0     "));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#<#10c", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("1#########"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#<#10c", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("0#########"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#>#10c", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("#########1"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#>#10c", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("#########0"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#^#10c", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("####1#####"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#^#10c", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("####0#####"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#c", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("1"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#c", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("0"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#10c", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("         1"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#10c", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("         0"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"0c", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("1"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"0c", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("0"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"010c", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("0000000001"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"010c", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("0000000000"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#010c", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("0000000001"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#010c", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("0000000000"));
            };
        };
    };

    bsl::ut_scenario{"bool with formatting type d"} = []() noexcept {
        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"d", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("1"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"d", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("0"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"10d", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("         1"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"10d", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("         0"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"<d", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("1"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"<d", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("0"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{">d", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("1"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{">d", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("0"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"^d", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("1"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"^d", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("0"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"<10d", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("1         "));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"<10d", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("0         "));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{">10d", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("         1"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{">10d", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("         0"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"^10d", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("    1     "));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"^10d", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("    0     "));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#<10d", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("1#########"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#<10d", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("0#########"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#>10d", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("#########1"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#>10d", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("#########0"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#^10d", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("####1#####"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#^10d", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("####0#####"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"<#10d", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("1         "));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"<#10d", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("0         "));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{">#10d", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("         1"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{">#10d", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("         0"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"^#10d", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("    1     "));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"^#10d", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("    0     "));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#<#10d", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("1#########"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#<#10d", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("0#########"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#>#10d", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("#########1"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#>#10d", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("#########0"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#^#10d", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("####1#####"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#^#10d", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("####0#####"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#d", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("1"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#d", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("0"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#10d", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("         1"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#10d", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("         0"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"0d", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("1"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"0d", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("0"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"010d", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("0000000001"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"010d", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("0000000000"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#010d", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("0000000001"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#010d", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("0000000000"));
            };
        };
    };

    bsl::ut_scenario{"bool with formatting type x"} = []() noexcept {
        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"x", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("1"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"x", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("0"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"10x", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("         1"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"10x", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("         0"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"<x", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("1"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"<x", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("0"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{">x", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("1"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{">x", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("0"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"^x", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("1"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"^x", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("0"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"<10x", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("1         "));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"<10x", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("0         "));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{">10x", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("         1"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{">10x", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("         0"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"^10x", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("    1     "));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"^10x", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("    0     "));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#<10x", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("1#########"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#<10x", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("0#########"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#>10x", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("#########1"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#>10x", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("#########0"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#^10x", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("####1#####"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#^10x", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("####0#####"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"<#10x", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("0x1       "));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"<#10x", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("0x0       "));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{">#10x", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("       0x1"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{">#10x", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("       0x0"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"^#10x", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("   0x1    "));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"^#10x", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("   0x0    "));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#<#10x", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("0x1#######"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#<#10x", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("0x0#######"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#>#10x", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("#######0x1"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#>#10x", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("#######0x0"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#^#10x", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("###0x1####"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#^#10x", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("###0x0####"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#x", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("0x1"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#x", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("0x0"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#10x", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("       0x1"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#10x", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("       0x0"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"0x", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("1"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"0x", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("0"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"010x", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("0000000001"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"010x", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("0000000000"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#010x", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("0x00000001"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#010x", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("0x00000000"));
            };
        };
    };

    bsl::ut_scenario{"bool with formatting type s"} = []() noexcept {
        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"s", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("true"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"s", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("false"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"10s", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("true      "));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"10s", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("false     "));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"<s", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("true"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"<s", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("false"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{">s", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("true"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{">s", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("false"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"^s", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("true"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"^s", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("false"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"<10s", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("true      "));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"<10s", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("false     "));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{">10s", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("      true"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{">10s", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("     false"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"^10s", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("   true   "));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"^10s", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("  false   "));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#<10s", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("true######"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#<10s", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("false#####"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#>10s", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("######true"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#>10s", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("#####false"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#^10s", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("###true###"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#^10s", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("##false###"));
            };
        };
    };

    bsl::ut_scenario{"bool with default formatting type"} = []() noexcept {
        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("true"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("false"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"10", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("true      "));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"10", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("false     "));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"<", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("true"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"<", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("false"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{">", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("true"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{">", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("false"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"^", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("true"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"^", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("false"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"<10", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("true      "));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"<10", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("false     "));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{">10", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("      true"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{">10", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("     false"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"^10", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("   true   "));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"^10", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("  false   "));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#<10", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("true######"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#<10", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("false#####"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#>10", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("######true"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#>10", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("#####false"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#^10", true};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("###true###"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#^10", false};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("##false###"));
            };
        };
    };

    return bsl::ut_success();
}
