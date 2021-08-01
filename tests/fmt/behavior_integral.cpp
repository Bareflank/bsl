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

namespace
{
    template<typename T>
    void
    tests() noexcept
    {
        bsl::ut_scenario{"integral with formatting type b"} = [&]() noexcept {
            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"b", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("101010"));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"10b", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("    101010"));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"<b", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("101010"));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{">b", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("101010"));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"^b", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("101010"));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"<10b", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("101010    "));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{">10b", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("    101010"));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"^10b", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("  101010  "));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"#<10b", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("101010####"));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"#>10b", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("####101010"));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"#^10b", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("##101010##"));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"<#10b", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("0b101010  "));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{">#10b", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("  0b101010"));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"^#10b", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted(" 0b101010 "));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"#<#10b", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("0b101010##"));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"#>#10b", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("##0b101010"));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"#^#10b", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("#0b101010#"));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"#b", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("0b101010"));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"#10b", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("  0b101010"));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"0b", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("101010"));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"010b", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("0000101010"));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"#010b", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("0b00101010"));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"+b", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("+101010"));
                };
            };

            if constexpr (bsl::is_signed<T>::value) {
                bsl::ut_when{} = [&]() noexcept {
                    fmt_test::reset();
                    bsl::print() << bsl::fmt{"+b", static_cast<T>(-42)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(fmt_test::was_this_outputted("-101010"));
                    };
                };
            }

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"-b", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("101010"));
                };
            };

            if constexpr (bsl::is_signed<T>::value) {
                bsl::ut_when{} = [&]() noexcept {
                    fmt_test::reset();
                    bsl::print() << bsl::fmt{"-b", static_cast<T>(-42)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(fmt_test::was_this_outputted("-101010"));
                    };
                };
            }

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{" b", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted(" 101010"));
                };
            };

            if constexpr (bsl::is_signed<T>::value) {
                bsl::ut_when{} = [&]() noexcept {
                    fmt_test::reset();
                    bsl::print() << bsl::fmt{" b", static_cast<T>(-42)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(fmt_test::was_this_outputted("-101010"));
                    };
                };
            }

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"<+10b", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("+101010   "));
                };
            };

            if constexpr (bsl::is_signed<T>::value) {
                bsl::ut_when{} = [&]() noexcept {
                    fmt_test::reset();
                    bsl::print() << bsl::fmt{"<+10b", static_cast<T>(-42)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(fmt_test::was_this_outputted("-101010   "));
                    };
                };
            }

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{">+10b", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("   +101010"));
                };
            };

            if constexpr (bsl::is_signed<T>::value) {
                bsl::ut_when{} = [&]() noexcept {
                    fmt_test::reset();
                    bsl::print() << bsl::fmt{">+10b", static_cast<T>(-42)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(fmt_test::was_this_outputted("   -101010"));
                    };
                };
            }

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"^+10b", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted(" +101010  "));
                };
            };

            if constexpr (bsl::is_signed<T>::value) {
                bsl::ut_when{} = [&]() noexcept {
                    fmt_test::reset();
                    bsl::print() << bsl::fmt{"^+10b", static_cast<T>(-42)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(fmt_test::was_this_outputted(" -101010  "));
                    };
                };
            }

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"+#010b", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("+0b0101010"));
                };
            };

            if constexpr (bsl::is_signed<T>::value) {
                bsl::ut_when{} = [&]() noexcept {
                    fmt_test::reset();
                    bsl::print() << bsl::fmt{"+#010b", static_cast<T>(-42)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(fmt_test::was_this_outputted("-0b0101010"));
                    };
                };
            }
        };

        bsl::ut_scenario{"integral with formatting type d"} = [&]() noexcept {
            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"d", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("42"));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"10d", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("        42"));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"<d", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("42"));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{">d", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("42"));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"^d", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("42"));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"<10d", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("42        "));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{">10d", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("        42"));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"^10d", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("    42    "));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"#<10d", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("42########"));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"#>10d", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("########42"));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"#^10d", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("####42####"));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"<#10d", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("42        "));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{">#10d", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("        42"));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"^#10d", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("    42    "));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"#<#10d", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("42########"));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"#>#10d", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("########42"));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"#^#10d", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("####42####"));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"#d", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("42"));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"#10d", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("        42"));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"0d", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("42"));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"010d", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("0000000042"));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"#010d", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("0000000042"));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"+d", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("+42"));
                };
            };

            if constexpr (bsl::is_signed<T>::value) {
                bsl::ut_when{} = [&]() noexcept {
                    fmt_test::reset();
                    bsl::print() << bsl::fmt{"+d", static_cast<T>(-42)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(fmt_test::was_this_outputted("-42"));
                    };
                };
            }

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"-d", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("42"));
                };
            };

            if constexpr (bsl::is_signed<T>::value) {
                bsl::ut_when{} = [&]() noexcept {
                    fmt_test::reset();
                    bsl::print() << bsl::fmt{"-d", static_cast<T>(-42)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(fmt_test::was_this_outputted("-42"));
                    };
                };
            }

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{" d", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted(" 42"));
                };
            };

            if constexpr (bsl::is_signed<T>::value) {
                bsl::ut_when{} = [&]() noexcept {
                    fmt_test::reset();
                    bsl::print() << bsl::fmt{" d", static_cast<T>(-42)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(fmt_test::was_this_outputted("-42"));
                    };
                };
            }

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"<+10d", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("+42       "));
                };
            };

            if constexpr (bsl::is_signed<T>::value) {
                bsl::ut_when{} = [&]() noexcept {
                    fmt_test::reset();
                    bsl::print() << bsl::fmt{"<+10d", static_cast<T>(-42)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(fmt_test::was_this_outputted("-42       "));
                    };
                };
            }

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{">+10d", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("       +42"));
                };
            };

            if constexpr (bsl::is_signed<T>::value) {
                bsl::ut_when{} = [&]() noexcept {
                    fmt_test::reset();
                    bsl::print() << bsl::fmt{">+10d", static_cast<T>(-42)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(fmt_test::was_this_outputted("       -42"));
                    };
                };
            }

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"^+10d", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("   +42    "));
                };
            };

            if constexpr (bsl::is_signed<T>::value) {
                bsl::ut_when{} = [&]() noexcept {
                    fmt_test::reset();
                    bsl::print() << bsl::fmt{"^+10d", static_cast<T>(-42)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(fmt_test::was_this_outputted("   -42    "));
                    };
                };
            }

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"+#010d", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("+000000042"));
                };
            };

            if constexpr (bsl::is_signed<T>::value) {
                bsl::ut_when{} = [&]() noexcept {
                    fmt_test::reset();
                    bsl::print() << bsl::fmt{"+#010d", static_cast<T>(-42)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(fmt_test::was_this_outputted("-000000042"));
                    };
                };
            }
        };

        bsl::ut_scenario{"integral with formatting type x"} = [&]() noexcept {
            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"x", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("2A"));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"10x", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("        2A"));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"<x", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("2A"));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{">x", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("2A"));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"^x", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("2A"));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"<10x", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("2A        "));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{">10x", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("        2A"));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"^10x", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("    2A    "));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"#<10x", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("2A########"));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"#>10x", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("########2A"));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"#^10x", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("####2A####"));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"<#10x", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("0x2A      "));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{">#10x", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("      0x2A"));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"^#10x", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("   0x2A   "));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"#<#10x", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("0x2A######"));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"#>#10x", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("######0x2A"));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"#^#10x", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("###0x2A###"));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"#x", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("0x2A"));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"#10x", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("      0x2A"));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"0x", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("2A"));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"010x", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("000000002A"));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"#010x", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("0x0000002A"));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"+x", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("+2A"));
                };
            };

            if constexpr (bsl::is_signed<T>::value) {
                bsl::ut_when{} = [&]() noexcept {
                    fmt_test::reset();
                    bsl::print() << bsl::fmt{"+x", static_cast<T>(-42)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(fmt_test::was_this_outputted("-2A"));
                    };
                };
            }

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"-x", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("2A"));
                };
            };

            if constexpr (bsl::is_signed<T>::value) {
                bsl::ut_when{} = [&]() noexcept {
                    fmt_test::reset();
                    bsl::print() << bsl::fmt{"-x", static_cast<T>(-42)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(fmt_test::was_this_outputted("-2A"));
                    };
                };
            }

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{" x", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted(" 2A"));
                };
            };

            if constexpr (bsl::is_signed<T>::value) {
                bsl::ut_when{} = [&]() noexcept {
                    fmt_test::reset();
                    bsl::print() << bsl::fmt{" x", static_cast<T>(-42)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(fmt_test::was_this_outputted("-2A"));
                    };
                };
            }

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"<+10x", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("+2A       "));
                };
            };

            if constexpr (bsl::is_signed<T>::value) {
                bsl::ut_when{} = [&]() noexcept {
                    fmt_test::reset();
                    bsl::print() << bsl::fmt{"<+10x", static_cast<T>(-42)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(fmt_test::was_this_outputted("-2A       "));
                    };
                };
            }

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{">+10x", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("       +2A"));
                };
            };

            if constexpr (bsl::is_signed<T>::value) {
                bsl::ut_when{} = [&]() noexcept {
                    fmt_test::reset();
                    bsl::print() << bsl::fmt{">+10x", static_cast<T>(-42)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(fmt_test::was_this_outputted("       -2A"));
                    };
                };
            }

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"^+10x", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("   +2A    "));
                };
            };

            if constexpr (bsl::is_signed<T>::value) {
                bsl::ut_when{} = [&]() noexcept {
                    fmt_test::reset();
                    bsl::print() << bsl::fmt{"^+10x", static_cast<T>(-42)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(fmt_test::was_this_outputted("   -2A    "));
                    };
                };
            }

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"+#010x", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("+0x000002A"));
                };
            };

            if constexpr (bsl::is_signed<T>::value) {
                bsl::ut_when{} = [&]() noexcept {
                    fmt_test::reset();
                    bsl::print() << bsl::fmt{"+#010x", static_cast<T>(-42)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(fmt_test::was_this_outputted("-0x000002A"));
                    };
                };
            }
        };

        bsl::ut_scenario{"integral with formatting type c"} = [&]() noexcept {
            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"c", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("*"));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"10c", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("*         "));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"<c", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("*"));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{">c", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("*"));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"^c", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("*"));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"<10c", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("*         "));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{">10c", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("         *"));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"^10c", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("    *     "));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"#<10c", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("*#########"));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"#>10c", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("#########*"));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"#^10c", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("####*#####"));
                };
            };
        };

        bsl::ut_scenario{"integral with default formatting type"} = [&]() noexcept {
            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("42"));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"10", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("        42"));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"<", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("42"));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{">", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("42"));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"^", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("42"));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"<10", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("42        "));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{">10", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("        42"));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"^10", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("    42    "));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"#<10", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("42########"));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"#>10", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("########42"));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"#^10", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("####42####"));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"<#10", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("42        "));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{">#10", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("        42"));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"^#10", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("    42    "));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"#<#10", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("42########"));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"#>#10", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("########42"));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"#^#10", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("####42####"));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"#", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("42"));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"#10", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("        42"));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"0", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("42"));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"010", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("0000000042"));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"#010", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("0000000042"));
                };
            };

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"+", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("+42"));
                };
            };

            if constexpr (bsl::is_signed<T>::value) {
                bsl::ut_when{} = [&]() noexcept {
                    fmt_test::reset();
                    bsl::print() << bsl::fmt{"+", static_cast<T>(-42)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(fmt_test::was_this_outputted("-42"));
                    };
                };
            }

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"-", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("42"));
                };
            };

            if constexpr (bsl::is_signed<T>::value) {
                bsl::ut_when{} = [&]() noexcept {
                    fmt_test::reset();
                    bsl::print() << bsl::fmt{"-", static_cast<T>(-42)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(fmt_test::was_this_outputted("-42"));
                    };
                };
            }

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{" ", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted(" 42"));
                };
            };

            if constexpr (bsl::is_signed<T>::value) {
                bsl::ut_when{} = [&]() noexcept {
                    fmt_test::reset();
                    bsl::print() << bsl::fmt{" ", static_cast<T>(-42)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(fmt_test::was_this_outputted("-42"));
                    };
                };
            }

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"<+10", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("+42       "));
                };
            };

            if constexpr (bsl::is_signed<T>::value) {
                bsl::ut_when{} = [&]() noexcept {
                    fmt_test::reset();
                    bsl::print() << bsl::fmt{"<+10", static_cast<T>(-42)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(fmt_test::was_this_outputted("-42       "));
                    };
                };
            }

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{">+10", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("       +42"));
                };
            };

            if constexpr (bsl::is_signed<T>::value) {
                bsl::ut_when{} = [&]() noexcept {
                    fmt_test::reset();
                    bsl::print() << bsl::fmt{">+10", static_cast<T>(-42)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(fmt_test::was_this_outputted("       -42"));
                    };
                };
            }

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"^+10", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("   +42    "));
                };
            };

            if constexpr (bsl::is_signed<T>::value) {
                bsl::ut_when{} = [&]() noexcept {
                    fmt_test::reset();
                    bsl::print() << bsl::fmt{"^+10", static_cast<T>(-42)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(fmt_test::was_this_outputted("   -42    "));
                    };
                };
            }

            bsl::ut_when{} = [&]() noexcept {
                fmt_test::reset();
                bsl::print() << bsl::fmt{"+#010", static_cast<T>(42)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(fmt_test::was_this_outputted("+000000042"));
                };
            };

            if constexpr (bsl::is_signed<T>::value) {
                bsl::ut_when{} = [&]() noexcept {
                    fmt_test::reset();
                    bsl::print() << bsl::fmt{"+#010", static_cast<T>(-42)};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(fmt_test::was_this_outputted("-000000042"));
                    };
                };
            }
        };
    }
}

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
    tests<bsl::int8>();
    tests<bsl::int16>();
    tests<bsl::int32>();
    tests<bsl::int64>();
    tests<bsl::uint8>();
    tests<bsl::uint16>();
    tests<bsl::uint32>();
    tests<bsl::uint64>();
    tests<bsl::uintmx>();

    bsl::ut_scenario{"safe_idx with no formatting"} = [&]() noexcept {
        bsl::ut_when{} = [&]() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::to_idx(0);
            bsl::ut_then{} = [&]() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("0"));
            };
        };

        bsl::ut_when{} = [&]() noexcept {
            fmt_test::reset();
            bsl::print() << bsl::to_idx(42);
            bsl::ut_then{} = [&]() noexcept {
                bsl::ut_check(fmt_test::was_this_outputted("42"));
            };
        };
    };

    return bsl::ut_success();
}
