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
    bsl::ut_scenario{"cstr_type with no formatting"} = []() noexcept {
        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::cstr_type{};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("[empty bsl::cstr_type]"));
            };
        };
    };

    bsl::ut_scenario{"cstr_type with no formatting"} = []() noexcept {
        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << "Hello";
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("Hello"));
            };
        };
    };

    bsl::ut_scenario{"cstr_type with no formatting using fmt"} = []() noexcept {
        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{bsl::nullops, "Hello"};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("Hello"));
            };
        };
    };

    bsl::ut_scenario{"dynamic width tests"} = []() noexcept {
        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{bsl::nullops, "Hello", bsl::to_umax(0)};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("Hello"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{bsl::nullops, "Hello", bsl::to_umax(9)};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("Hello    "));
            };
        };
    };

    bsl::ut_scenario{"cstr_type with formatting type s"} = []() noexcept {
        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"s", "Hello"};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("Hello"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"10s", "Hello"};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("Hello     "));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"<s", "Hello"};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("Hello"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{">s", "Hello"};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("Hello"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"^s", "Hello"};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("Hello"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"<10s", "Hello"};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("Hello     "));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{">10s", "Hello"};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("     Hello"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"^10s", "Hello"};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("  Hello   "));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#<10s", "Hello"};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("Hello#####"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#>10s", "Hello"};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("#####Hello"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#^10s", "Hello"};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("##Hello###"));
            };
        };
    };

    bsl::ut_scenario{"cstr_type with default formatting type"} = []() noexcept {
        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"", "Hello"};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("Hello"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"10", "Hello"};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("Hello     "));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"<", "Hello"};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("Hello"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{">", "Hello"};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("Hello"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"^", "Hello"};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("Hello"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"<10", "Hello"};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("Hello     "));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{">10", "Hello"};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("     Hello"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"^10", "Hello"};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("  Hello   "));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#<10", "Hello"};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("Hello#####"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#>10", "Hello"};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("#####Hello"));
            };
        };

        bsl::ut_when{} = []() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::fmt{"#^10", "Hello"};
            bsl::ut_then{} = []() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("##Hello###"));
            };
        };
    };

    return bsl::ut_success();
}
