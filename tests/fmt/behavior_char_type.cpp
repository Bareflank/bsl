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
    bsl::ut_scenario{"char_type with formatting type b"} = []() noexcept {
        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"b", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("101010"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"10b", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("    101010"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"<b", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("101010"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{">b", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("101010"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"^b", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("101010"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"<10b", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("101010    "));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{">10b", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("    101010"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"^10b", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("  101010  "));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#<10b", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("101010####"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#>10b", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("####101010"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#^10b", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("##101010##"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"<#10b", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("0b101010  "));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{">#10b", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("  0b101010"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"^#10b", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted(" 0b101010 "));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#<#10b", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("0b101010##"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#>#10b", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("##0b101010"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#^#10b", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("#0b101010#"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#b", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("0b101010"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#10b", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("  0b101010"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"0b", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("101010"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"010b", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("0000101010"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#010b", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("0b00101010"));
            };
        };
    };

    bsl::ut_scenario{"char_type with formatting type d"} = []() noexcept {
        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"d", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("42"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"10d", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("        42"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"<d", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("42"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{">d", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("42"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"^d", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("42"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"<10d", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("42        "));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{">10d", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("        42"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"^10d", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("    42    "));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#<10d", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("42########"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#>10d", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("########42"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#^10d", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("####42####"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"<#10d", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("42        "));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{">#10d", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("        42"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"^#10d", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("    42    "));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#<#10d", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("42########"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#>#10d", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("########42"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#^#10d", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("####42####"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#d", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("42"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#10d", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("        42"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"0d", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("42"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"010d", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("0000000042"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#010d", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("0000000042"));
            };
        };
    };

    bsl::ut_scenario{"char_type with formatting type x"} = []() noexcept {
        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"x", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("2A"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"10x", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("        2A"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"<x", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("2A"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{">x", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("2A"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"^x", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("2A"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"<10x", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("2A        "));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{">10x", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("        2A"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"^10x", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("    2A    "));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#<10x", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("2A########"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#>10x", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("########2A"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#^10x", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("####2A####"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"<#10x", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("0x2A      "));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{">#10x", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("      0x2A"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"^#10x", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("   0x2A   "));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#<#10x", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("0x2A######"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#>#10x", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("######0x2A"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#^#10x", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("###0x2A###"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#x", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("0x2A"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#10x", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("      0x2A"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"0x", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("2A"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"010x", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("000000002A"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#010x", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("0x0000002A"));
            };
        };
    };

    bsl::ut_scenario{"char_type with formatting type c"} = []() noexcept {
        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"c", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("*"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"10c", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("*         "));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"<c", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("*"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{">c", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("*"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"^c", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("*"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"<10c", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("*         "));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{">10c", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("         *"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"^10c", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("    *     "));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#<10c", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("*#########"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#>10c", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("#########*"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#^10c", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("####*#####"));
            };
        };
    };

    bsl::ut_scenario{"char_type with default formatting type"} = []() noexcept {
        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("*"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"10", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("*         "));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"<", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("*"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{">", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("*"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"^", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("*"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"<10", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("*         "));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{">10", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("         *"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"^10", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("    *     "));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#<10", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("*#########"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#>10", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("#########*"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#^10", '*'};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("####*#####"));
            };
        };
    };

    return bsl::ut_success();
}
