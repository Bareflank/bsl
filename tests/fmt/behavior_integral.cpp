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

#include <bsl/convert.hpp>
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
    bsl::ut_scenario{"integral with no formatting"} = []() {
        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << 0;
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("0"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << 42;
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("42"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << -42;
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("-42"));
            };
        };
    };

    bsl::ut_scenario{"safe_integral with no formatting"} = []() {
        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::to_i32(0);
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("0"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::to_i32(42);
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("42"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::to_i32(-42);
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("-42"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::safe_uintmax::failure();
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("[error]"));
            };
        };
    };

    bsl::ut_scenario{"integral with no formatting using fmt"} = []() {
        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{bsl::nullops, 0};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("0"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{bsl::nullops, 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("42"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{bsl::nullops, -42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("-42"));
            };
        };
    };

    bsl::ut_scenario{"integral with no formatting using fmt"} = []() {
        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{bsl::nullops, bsl::to_i32(0)};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("0"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{bsl::nullops, bsl::to_i32(42)};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("42"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{bsl::nullops, bsl::to_i32(-42)};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("-42"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{bsl::nullops, bsl::safe_uintmax::failure()};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("[error]"));
            };
        };
    };

    bsl::ut_scenario{"integral with minimal formatting"} = []() {
        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"b", 0};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("0"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"d", 0};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("0"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"x", 0};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("0"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"c", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("*"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"s", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("*"));
            };
        };
    };

    bsl::ut_scenario{"integral with minimal formatting using fmt"} = []() {
        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"b", bsl::to_i32(0)};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("0"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"d", bsl::to_i32(0)};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("0"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"x", bsl::to_i32(0)};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("0"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"c", bsl::to_i32(42)};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("*"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"s", bsl::to_i32(42)};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("*"));
            };
        };
    };

    bsl::ut_scenario{"integral with formatting type b"} = []() {
        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"b", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("101010"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"10b", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("    101010"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"<b", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("101010"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{">b", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("101010"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"^b", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("101010"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"<10b", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("101010    "));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{">10b", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("    101010"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"^10b", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("  101010  "));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#<10b", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("101010####"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#>10b", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("####101010"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#^10b", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("##101010##"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"<#10b", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("0b101010  "));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{">#10b", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("  0b101010"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"^#10b", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted(" 0b101010 "));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#<#10b", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("0b101010##"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#>#10b", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("##0b101010"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#^#10b", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("#0b101010#"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#b", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("0b101010"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#10b", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("  0b101010"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"0b", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("101010"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"010b", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("0000101010"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#010b", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("0b00101010"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"+b", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("+101010"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"+b", -42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("-101010"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"-b", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("101010"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"-b", -42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("-101010"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{" b", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted(" 101010"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{" b", -42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("-101010"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"<+10b", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("+101010   "));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"<+10b", -42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("-101010   "));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{">+10b", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("   +101010"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{">+10b", -42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("   -101010"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"^+10b", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted(" +101010  "));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"^+10b", -42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted(" -101010  "));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"+#010b", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("+0b0101010"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"+#010b", -42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("-0b0101010"));
            };
        };
    };

    bsl::ut_scenario{"integral with formatting type d"} = []() {
        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"d", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("42"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"10d", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("        42"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"<d", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("42"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{">d", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("42"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"^d", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("42"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"<10d", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("42        "));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{">10d", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("        42"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"^10d", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("    42    "));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#<10d", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("42########"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#>10d", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("########42"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#^10d", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("####42####"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"<#10d", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("42        "));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{">#10d", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("        42"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"^#10d", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("    42    "));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#<#10d", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("42########"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#>#10d", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("########42"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#^#10d", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("####42####"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#d", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("42"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#10d", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("        42"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"0d", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("42"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"010d", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("0000000042"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#010d", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("0000000042"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"+d", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("+42"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"+d", -42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("-42"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"-d", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("42"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"-d", -42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("-42"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{" d", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted(" 42"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{" d", -42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("-42"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"<+10d", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("+42       "));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"<+10d", -42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("-42       "));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{">+10d", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("       +42"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{">+10d", -42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("       -42"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"^+10d", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("   +42    "));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"^+10d", -42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("   -42    "));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"+#010d", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("+000000042"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"+#010d", -42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("-000000042"));
            };
        };
    };

    bsl::ut_scenario{"integral with formatting type x"} = []() {
        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"x", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("2A"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"10x", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("        2A"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"<x", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("2A"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{">x", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("2A"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"^x", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("2A"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"<10x", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("2A        "));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{">10x", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("        2A"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"^10x", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("    2A    "));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#<10x", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("2A########"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#>10x", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("########2A"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#^10x", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("####2A####"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"<#10x", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("0x2A      "));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{">#10x", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("      0x2A"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"^#10x", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("   0x2A   "));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#<#10x", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("0x2A######"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#>#10x", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("######0x2A"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#^#10x", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("###0x2A###"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#x", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("0x2A"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#10x", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("      0x2A"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"0x", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("2A"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"010x", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("000000002A"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#010x", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("0x0000002A"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"+x", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("+2A"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"+x", -42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("-2A"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"-x", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("2A"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"-x", -42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("-2A"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{" x", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted(" 2A"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{" x", -42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("-2A"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"<+10x", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("+2A       "));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"<+10x", -42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("-2A       "));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{">+10x", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("       +2A"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{">+10x", -42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("       -2A"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"^+10x", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("   +2A    "));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"^+10x", -42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("   -2A    "));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"+#010x", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("+0x000002A"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"+#010x", -42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("-0x000002A"));
            };
        };
    };

    bsl::ut_scenario{"integral with formatting type c"} = []() {
        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"c", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("*"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"10c", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("*         "));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"<c", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("*"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{">c", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("*"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"^c", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("*"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"<10c", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("*         "));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{">10c", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("         *"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"^10c", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("    *     "));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#<10c", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("*#########"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#>10c", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("#########*"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#^10c", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("####*#####"));
            };
        };
    };

    bsl::ut_scenario{"integral with default formatting type"} = []() {
        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("42"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"10", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("        42"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"<", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("42"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{">", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("42"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"^", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("42"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"<10", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("42        "));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{">10", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("        42"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"^10", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("    42    "));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#<10", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("42########"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#>10", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("########42"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#^10", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("####42####"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"<#10", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("42        "));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{">#10", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("        42"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"^#10", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("    42    "));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#<#10", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("42########"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#>#10", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("########42"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#^#10", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("####42####"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("42"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#10", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("        42"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"0", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("42"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"010", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("0000000042"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#010", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("0000000042"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"+", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("+42"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"+", -42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("-42"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"-", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("42"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"-", -42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("-42"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{" ", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted(" 42"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{" ", -42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("-42"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"<+10", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("+42       "));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"<+10", -42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("-42       "));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{">+10", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("       +42"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{">+10", -42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("       -42"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"^+10", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("   +42    "));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"^+10", -42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("   -42    "));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"+#010", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("+000000042"));
            };
        };

        bsl::ut_when{} = []() {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"+#010", -42};
            bsl::ut_then{} = []() {
                bsl::ut_check(fmt_test::was_this_outputted("-000000042"));
            };
        };
    };

    return bsl::ut_success();
}
