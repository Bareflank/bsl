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

#define BSL_DETAILS_PUTC_STDOUT_HPP
#define BSL_DETAILS_PUTS_STDOUT_HPP

#include <bsl/details/carray.hpp>

#include <bsl/char_type.hpp>
#include <bsl/convert.hpp>
#include <bsl/cstdint.hpp>
#include <bsl/cstdio.hpp>
#include <bsl/cstdlib.hpp>
#include <bsl/cstring.hpp>
#include <bsl/cstr_type.hpp>
#include <bsl/discard.hpp>
#include <bsl/safe_integral.hpp>

namespace
{
    template<bsl::uintmax N>
    struct test_string_view final
    {
        bsl::details::carray<bsl::char_type, N> data{};
        bsl::safe_uintmax size{};
    };

    constexpr bsl::safe_uintmax res_size{bsl::to_umax(10000)};
    test_string_view<res_size.get()> res{};

    template<bsl::uintmax N>
    [[nodiscard]] auto
    operator==(test_string_view<N> const &lhs, bsl::cstr_type const str) noexcept -> bool
    {
        if (bsl::builtin_strlen(str) != lhs.size) {
            return false;
        }

        return __builtin_memcmp(lhs.data.data(), str, lhs.size.get()) == 0;
    }

    void
    reset() noexcept
    {
        for (bsl::safe_uintmax i{}; i < res.data.size(); ++i) {
            *res.data.at_if(i) = 0;
        }

        res.size = bsl::to_umax(0);
    }
}

namespace bsl::details
{
    static void
    putc_stdout(bsl::char_type const c) noexcept
    {
        if (auto *const ptr{res.data.at_if(res.size)}) {
            *ptr = c;
        }
        else {
            bsl::discard(fputs("res.data too small\n", stderr));
            exit(1);
        }
        ++res.size;
    }

    static void
    puts_stdout(bsl::cstr_type const str) noexcept
    {
        for (bsl::safe_uintmax i{}; i < bsl::builtin_strlen(str); ++i) {
            putc_stdout(str[i.get()]);
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
[[nodiscard]] auto
main() noexcept -> bsl::exit_code
{
    bsl::ut_scenario{"char_type with no formatting"} = []() {
        bsl::ut_when{} = []() {
            reset();
            bsl::print() << '*';
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "*");
            };
        };
    };

    bsl::ut_scenario{"char_type with no formatting using fmt"} = []() {
        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{bsl::nullops, '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "*");
            };
        };
    };

    bsl::ut_scenario{"char_type with formatting type b"} = []() {
        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"b", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "101010");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"10b", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "    101010");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"<b", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "101010");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{">b", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "101010");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"^b", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "101010");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"<10b", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "101010    ");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{">10b", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "    101010");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"^10b", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "  101010  ");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"#<10b", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "101010####");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"#>10b", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "####101010");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"#^10b", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "##101010##");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"<#10b", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "0b101010  ");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{">#10b", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "  0b101010");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"^#10b", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == " 0b101010 ");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"#<#10b", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "0b101010##");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"#>#10b", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "##0b101010");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"#^#10b", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "#0b101010#");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"#b", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "0b101010");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"#10b", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "  0b101010");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"0b", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "101010");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"010b", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "0000101010");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"#010b", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "0b00101010");
            };
        };
    };

    bsl::ut_scenario{"char_type with formatting type d"} = []() {
        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"d", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "42");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"10d", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "        42");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"<d", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "42");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{">d", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "42");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"^d", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "42");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"<10d", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "42        ");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{">10d", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "        42");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"^10d", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "    42    ");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"#<10d", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "42########");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"#>10d", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "########42");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"#^10d", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "####42####");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"<#10d", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "42        ");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{">#10d", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "        42");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"^#10d", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "    42    ");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"#<#10d", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "42########");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"#>#10d", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "########42");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"#^#10d", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "####42####");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"#d", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "42");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"#10d", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "        42");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"0d", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "42");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"010d", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "0000000042");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"#010d", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "0000000042");
            };
        };
    };

    bsl::ut_scenario{"char_type with formatting type x"} = []() {
        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"x", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "2A");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"10x", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "        2A");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"<x", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "2A");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{">x", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "2A");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"^x", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "2A");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"<10x", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "2A        ");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{">10x", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "        2A");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"^10x", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "    2A    ");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"#<10x", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "2A########");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"#>10x", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "########2A");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"#^10x", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "####2A####");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"<#10x", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "0x2A      ");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{">#10x", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "      0x2A");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"^#10x", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "   0x2A   ");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"#<#10x", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "0x2A######");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"#>#10x", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "######0x2A");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"#^#10x", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "###0x2A###");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"#x", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "0x2A");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"#10x", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "      0x2A");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"0x", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "2A");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"010x", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "000000002A");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"#010x", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "0x0000002A");
            };
        };
    };

    bsl::ut_scenario{"char_type with formatting type c"} = []() {
        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"c", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "*");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"10c", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "*         ");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"<c", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "*");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{">c", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "*");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"^c", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "*");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"<10c", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "*         ");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{">10c", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "         *");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"^10c", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "    *     ");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"#<10c", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "*#########");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"#>10c", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "#########*");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"#^10c", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "####*#####");
            };
        };
    };

    bsl::ut_scenario{"char_type with default formatting type"} = []() {
        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "*");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"10", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "*         ");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"<", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "*");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{">", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "*");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"^", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "*");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"<10", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "*         ");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{">10", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "         *");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"^10", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "    *     ");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"#<10", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "*#########");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"#>10", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "#########*");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            bsl::print() << bsl::fmt{"#^10", '*'};
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "####*#####");
            };
        };
    };

    return bsl::ut_success();
}
