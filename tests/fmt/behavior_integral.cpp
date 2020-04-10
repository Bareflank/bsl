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

#include <bsl/char_type.hpp>
#include <bsl/cstr_type.hpp>
#include <bsl/cstdint.hpp>
#include <bsl/cstring.hpp>

#include <bsl/details/putc_stdout.hpp>
#include <bsl/details/puts_stdout.hpp>

namespace
{
    template<bsl::uintmax N>
    struct test_string_view final
    {
        bsl::char_type data[N]{};
        bsl::uintmax size{};
    };

    constexpr bsl::uintmax res_size{256};
    test_string_view<res_size> res{};

    template<bsl::uintmax N>
    bool
    operator==(test_string_view<N> const &lhs, bsl::cstr_type const str) noexcept
    {
        if (bsl::builtin_strlen(str) != lhs.size) {
            return false;
        }

        return bsl::builtin_strncmp(lhs.data, str, lhs.size) == 0;
    }

    void
    reset() noexcept
    {
        for (auto &e : res.data) {
            e = 0;
        }
        res.size = 0;
    }
}

namespace bsl
{
    namespace details
    {
        template<>
        void
        putc_stdout<void>(char_type const c) noexcept
        {
            res.data[res.size++] = c;
        }

        template<>
        void
        puts_stdout<void>(cstr_type const str) noexcept
        {
            for (bsl::uintmax i{}; i < bsl::builtin_strlen(str); ++i) {
                res.data[res.size++] = str[i];
            }
        }
    }
}

#include <bsl/debug.hpp>
#include <bsl/ut.hpp>

/// <!-- description -->
///   @brief Main function for this unit test. If a call to ut_check() fails
///     the application will fast fail. If all calls to ut_check() pass, this
///     function will successfully return with bsl::exit_success.
///
/// <!-- inputs/outputs -->
///   @return Always returns bsl::exit_success.
///
bsl::exit_code
main() noexcept
{
    bsl::ut_scenario{"integral with no formatting"} = []() {
        bsl::ut_when{} = []() {
            reset();
            bsl::print() << 0;
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "0");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << 42;
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "42");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << -42;
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "-42");
            };
        };
    };

    bsl::ut_scenario{"integral with no formatting using fmt"} = []() {
        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{bsl::nullops, 0};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "0");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{bsl::nullops, 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "42");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{bsl::nullops, -42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "-42");
            };
        };
    };

    bsl::ut_scenario{"integral with formatting type b"} = []() {
        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"b", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "101010");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"10b", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "    101010");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"<b", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "101010");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{">b", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "101010");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"^b", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "101010");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"<10b", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "101010    ");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{">10b", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "    101010");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"^10b", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "  101010  ");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"#<10b", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "101010####");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"#>10b", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "####101010");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"#^10b", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "##101010##");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"<#10b", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "0b101010  ");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{">#10b", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "  0b101010");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"^#10b", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == " 0b101010 ");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"#<#10b", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "0b101010##");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"#>#10b", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "##0b101010");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"#^#10b", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "#0b101010#");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"#b", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "0b101010");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"#10b", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "  0b101010");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"0b", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "101010");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"010b", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "0000101010");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"#010b", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "0b00101010");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"+b", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "+101010");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"+b", -42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "-101010");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"-b", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "101010");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"-b", -42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "-101010");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{" b", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == " 101010");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{" b", -42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "-101010");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"<+10b", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "+101010   ");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"<+10b", -42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "-101010   ");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{">+10b", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "   +101010");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{">+10b", -42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "   -101010");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"^+10b", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == " +101010  ");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"^+10b", -42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == " -101010  ");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"+#010b", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "+0b0101010");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"+#010b", -42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "-0b0101010");
            };
        };
    };

    bsl::ut_scenario{"integral with formatting type d"} = []() {
        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"d", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "42");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"10d", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "        42");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"<d", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "42");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{">d", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "42");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"^d", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "42");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"<10d", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "42        ");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{">10d", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "        42");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"^10d", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "    42    ");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"#<10d", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "42########");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"#>10d", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "########42");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"#^10d", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "####42####");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"<#10d", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "42        ");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{">#10d", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "        42");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"^#10d", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "    42    ");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"#<#10d", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "42########");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"#>#10d", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "########42");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"#^#10d", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "####42####");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"#d", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "42");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"#10d", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "        42");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"0d", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "42");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"010d", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "0000000042");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"#010d", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "0000000042");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"+d", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "+42");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"+d", -42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "-42");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"-d", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "42");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"-d", -42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "-42");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{" d", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == " 42");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{" d", -42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "-42");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"<+10d", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "+42       ");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"<+10d", -42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "-42       ");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{">+10d", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "       +42");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{">+10d", -42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "       -42");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"^+10d", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "   +42    ");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"^+10d", -42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "   -42    ");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"+#010d", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "+000000042");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"+#010d", -42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "-000000042");
            };
        };
    };

    bsl::ut_scenario{"integral with formatting type x"} = []() {
        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"x", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "2A");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"10x", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "        2A");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"<x", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "2A");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{">x", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "2A");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"^x", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "2A");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"<10x", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "2A        ");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{">10x", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "        2A");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"^10x", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "    2A    ");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"#<10x", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "2A########");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"#>10x", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "########2A");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"#^10x", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "####2A####");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"<#10x", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "0x2A      ");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{">#10x", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "      0x2A");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"^#10x", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "   0x2A   ");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"#<#10x", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "0x2A######");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"#>#10x", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "######0x2A");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"#^#10x", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "###0x2A###");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"#x", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "0x2A");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"#10x", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "      0x2A");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"0x", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "2A");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"010x", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "000000002A");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"#010x", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "0x0000002A");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"+x", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "+2A");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"+x", -42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "-2A");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"-x", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "2A");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"-x", -42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "-2A");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{" x", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == " 2A");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{" x", -42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "-2A");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"<+10x", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "+2A       ");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"<+10x", -42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "-2A       ");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{">+10x", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "       +2A");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{">+10x", -42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "       -2A");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"^+10x", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "   +2A    ");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"^+10x", -42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "   -2A    ");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"+#010x", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "+0x000002A");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"+#010x", -42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "-0x000002A");
            };
        };
    };

    bsl::ut_scenario{"integral with formatting type c"} = []() {
        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"c", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "*");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"10c", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "*         ");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"<c", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "*");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{">c", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "*");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"^c", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "*");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"<10c", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "*         ");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{">10c", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "         *");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"^10c", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "    *     ");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"#<10c", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "*#########");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"#>10c", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "#########*");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"#^10c", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "####*#####");
            };
        };
    };

    bsl::ut_scenario{"integral with default formatting type"} = []() {
        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "42");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"10", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "        42");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"<", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "42");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{">", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "42");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"^", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "42");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"<10", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "42        ");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{">10", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "        42");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"^10", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "    42    ");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"#<10", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "42########");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"#>10", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "########42");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"#^10", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "####42####");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"<#10", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "42        ");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{">#10", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "        42");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"^#10", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "    42    ");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"#<#10", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "42########");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"#>#10", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "########42");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"#^#10", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "####42####");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"#", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "42");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"#10", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "        42");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"0", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "42");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"010", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "0000000042");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"#010", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "0000000042");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"+", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "+42");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"+", -42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "-42");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"-", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "42");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"-", -42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "-42");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{" ", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == " 42");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{" ", -42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "-42");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"<+10", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "+42       ");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"<+10", -42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "-42       ");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{">+10", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "       +42");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{">+10", -42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "       -42");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"^+10", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "   +42    ");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"^+10", -42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "   -42    ");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"+#010", 42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "+000000042");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"+#010", -42};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "-000000042");
            };
        };
    };

    return bsl::ut_success();
}
