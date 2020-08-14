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

#include <bsl/byte.hpp>
#include <bsl/ut.hpp>

namespace
{
    /// <!-- description -->
    ///   @brief Used to execute the actual checks. We put the checks in this
    ///     function so that we can validate the tests both at compile-time
    ///     and at run-time. If a bsl::ut_check fails, the tests will either
    ///     fail fast at run-time, or will produce a compile-time error.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Always returns bsl::exit_success.
    ///
    [[nodiscard]] constexpr auto
    tests() noexcept -> bsl::exit_code
    {
        constexpr bsl::uint8 byte23{23};
        constexpr bsl::uint8 byte42{42};
        constexpr bsl::uint8 byte00{0x00};
        constexpr bsl::uint8 byte01{0x01};
        constexpr bsl::uint8 byte10{0x10};
        constexpr bsl::uint8 byte11{0x11};
        constexpr bsl::uint8 byteFE{0xFE};

        bsl::ut_scenario{"default construction"} = []() {
            bsl::ut_given{} = []() {
                bsl::byte b{};
                bsl::ut_then{} = [&b]() {
                    bsl::ut_check(b.to_integer() == 0);
                };
            };
        };

        bsl::ut_scenario{"by value construction"} = []() {
            bsl::ut_given{} = []() {
                bsl::byte b{byte42};
                bsl::ut_then{} = [&b]() {
                    bsl::ut_check(b.to_integer() == byte42);
                };
            };
        };

        bsl::ut_scenario{"to integer"} = []() {
            bsl::ut_given{} = []() {
                bsl::byte b{};
                bsl::ut_then{} = [&b]() {
                    bsl::ut_check(b.to_integer() == 0);
                };
            };

            bsl::ut_given{} = []() {
                bsl::byte b{byte42};
                bsl::ut_then{} = [&b]() {
                    bsl::ut_check(b.to_integer() == byte42);
                };
            };

            bsl::ut_given{} = []() {
                bsl::byte b{byte42};
                bsl::ut_then{} = [&b]() {
                    bsl::ut_check(b.to_integer<bsl::int32>() == 42);
                };
            };
        };

        bsl::ut_scenario{"equals"} = []() {
            bsl::ut_given{} = []() {
                bsl::byte b1{};
                bsl::byte b2{};
                bsl::ut_then{} = [&b1, &b2]() {
                    bsl::ut_check(b1 == b2);
                };
            };

            bsl::ut_given{} = []() {
                bsl::byte b1{byte42};
                bsl::byte b2{byte42};
                bsl::ut_then{} = [&b1, &b2]() {
                    bsl::ut_check(b1 == b2);
                };
            };
        };

        bsl::ut_scenario{"not equals"} = []() {
            bsl::ut_given{} = []() {
                bsl::byte b1{};
                bsl::byte b2{byte42};
                bsl::ut_then{} = [&b1, &b2]() {
                    bsl::ut_check(b1 != b2);
                };
            };

            bsl::ut_given{} = []() {
                bsl::byte b1{byte42};
                bsl::byte b2{};
                bsl::ut_then{} = [&b1, &b2]() {
                    bsl::ut_check(b1 != b2);
                };
            };

            bsl::ut_given{} = []() {
                bsl::byte b1{byte23};
                bsl::byte b2{byte42};
                bsl::ut_then{} = [&b1, &b2]() {
                    bsl::ut_check(b1 != b2);
                };
            };

            bsl::ut_given{} = []() {
                bsl::byte b1{byte42};
                bsl::byte b2{byte23};
                bsl::ut_then{} = [&b1, &b2]() {
                    bsl::ut_check(b1 != b2);
                };
            };
        };

        bsl::ut_scenario{"left shift assign"} = []() {
            bsl::ut_given{} = []() {
                bsl::byte b{};
                bsl::ut_when{} = [&b]() {
                    b <<= 4;
                    bsl::ut_then{} = [&b]() {
                        bsl::ut_check(b == bsl::byte{byte00});
                    };
                };
            };

            bsl::ut_given{} = []() {
                bsl::byte b{byte01};
                bsl::ut_when{} = [&b]() {
                    b <<= 4;
                    bsl::ut_then{} = [&b]() {
                        bsl::ut_check(b == bsl::byte{byte10});
                    };
                };
            };
        };

        bsl::ut_scenario{"right shift assign"} = []() {
            bsl::ut_given{} = []() {
                bsl::byte b{};
                bsl::ut_when{} = [&b]() {
                    b >>= 4;
                    bsl::ut_then{} = [&b]() {
                        bsl::ut_check(b == bsl::byte{byte00});
                    };
                };
            };

            bsl::ut_given{} = []() {
                bsl::byte b{byte10};
                bsl::ut_when{} = [&b]() {
                    b >>= 4;
                    bsl::ut_then{} = [&b]() {
                        bsl::ut_check(b == bsl::byte{byte01});
                    };
                };
            };
        };

        bsl::ut_scenario{"left shift"} = []() {
            bsl::ut_given{} = []() {
                bsl::byte b{};
                bsl::ut_then{} = [&b]() {
                    bsl::ut_check((b << 4) == bsl::byte{byte00});
                };
            };

            bsl::ut_given{} = []() {
                bsl::byte b{byte01};
                bsl::ut_when{} = [&b]() {
                    bsl::ut_check((b << 4) == bsl::byte{byte10});
                };
            };
        };

        bsl::ut_scenario{"right shift"} = []() {
            bsl::ut_given{} = []() {
                bsl::byte b{};
                bsl::ut_then{} = [&b]() {
                    bsl::ut_check((b >> 4) == bsl::byte{byte00});
                };
            };

            bsl::ut_given{} = []() {
                bsl::byte b{byte10};
                bsl::ut_when{} = [&b]() {
                    bsl::ut_check((b >> 4) == bsl::byte{byte01});
                };
            };
        };

        bsl::ut_scenario{"or assign"} = []() {
            bsl::ut_given{} = []() {
                bsl::byte b{};
                bsl::ut_when{} = [&b]() {
                    b |= bsl::byte{byte10};
                    bsl::ut_then{} = [&b]() {
                        bsl::ut_check(b == bsl::byte{byte10});
                    };
                };
            };

            bsl::ut_given{} = []() {
                bsl::byte b{byte01};
                bsl::ut_when{} = [&b]() {
                    b |= bsl::byte{byte10};
                    bsl::ut_then{} = [&b]() {
                        bsl::ut_check(b == bsl::byte{byte11});
                    };
                };
            };
        };

        bsl::ut_scenario{"and assign"} = []() {
            bsl::ut_given{} = []() {
                bsl::byte b{};
                bsl::ut_when{} = [&b]() {
                    b &= bsl::byte{byte10};
                    bsl::ut_then{} = [&b]() {
                        bsl::ut_check(b == bsl::byte{byte00});
                    };
                };
            };

            bsl::ut_given{} = []() {
                bsl::byte b{byte01};
                bsl::ut_when{} = [&b]() {
                    b &= bsl::byte{byte10};
                    bsl::ut_then{} = [&b]() {
                        bsl::ut_check(b == bsl::byte{byte00});
                    };
                };
            };
        };

        bsl::ut_scenario{"xor assign"} = []() {
            bsl::ut_given{} = []() {
                bsl::byte b{};
                bsl::ut_when{} = [&b]() {
                    b ^= bsl::byte{byte10};
                    bsl::ut_then{} = [&b]() {
                        bsl::ut_check(b == bsl::byte{byte10});
                    };
                };
            };

            bsl::ut_given{} = []() {
                bsl::byte b{byte01};
                bsl::ut_when{} = [&b]() {
                    b ^= bsl::byte{byte10};
                    bsl::ut_then{} = [&b]() {
                        bsl::ut_check(b == bsl::byte{byte11});
                    };
                };
            };
        };

        bsl::ut_scenario{"or"} = []() {
            bsl::ut_given{} = []() {
                bsl::byte b{};
                bsl::ut_then{} = [&b]() {
                    bsl::ut_check((b | bsl::byte{byte10}) == bsl::byte{byte10});
                };
            };

            bsl::ut_given{} = []() {
                bsl::byte b{byte01};
                bsl::ut_then{} = [&b]() {
                    bsl::ut_check((b | bsl::byte{byte10}) == bsl::byte{byte11});
                };
            };
        };

        bsl::ut_scenario{"and"} = []() {
            bsl::ut_given{} = []() {
                bsl::byte b{};
                bsl::ut_then{} = [&b]() {
                    bsl::ut_check((b & bsl::byte{byte10}) == bsl::byte{byte00});
                };
            };

            bsl::ut_given{} = []() {
                bsl::byte b{byte01};
                bsl::ut_then{} = [&b]() {
                    bsl::ut_check((b & bsl::byte{byte10}) == bsl::byte{byte00});
                };
            };
        };

        bsl::ut_scenario{"and"} = []() {
            bsl::ut_given{} = []() {
                bsl::byte b{};
                bsl::ut_then{} = [&b]() {
                    bsl::ut_check((b ^ bsl::byte{byte10}) == bsl::byte{byte10});
                };
            };

            bsl::ut_given{} = []() {
                bsl::byte b{byte01};
                bsl::ut_then{} = [&b]() {
                    bsl::ut_check((b ^ bsl::byte{byte10}) == bsl::byte{byte11});
                };
            };
        };

        bsl::ut_scenario{"complement"} = []() {
            bsl::ut_given{} = []() {
                bsl::byte b{byte01};
                bsl::ut_then{} = [&b]() {
                    bsl::ut_check(~b == bsl::byte{byteFE});
                };
            };
        };

        bsl::ut_scenario{"output doesn't crash"} = []() {
            bsl::ut_given{} = []() {
                bsl::byte b{byte42};
                bsl::ut_then{} = [&b]() {
                    bsl::debug() << b << '\n';
                };
            };
        };

        return bsl::ut_success();
    }
}

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
    static_assert(tests() == bsl::ut_success());
    return tests();
}
