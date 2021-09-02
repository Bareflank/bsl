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

#include <bsl/convert.hpp>
#include <bsl/discard.hpp>
#include <bsl/from_chars.hpp>
#include <bsl/is_same.hpp>
#include <bsl/is_signed.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/string_view.hpp>
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
    template<typename T>
    [[nodiscard]] constexpr auto
    tests() noexcept -> bsl::exit_code
    {
        bsl::ut_scenario{"invalid arguments"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::string_view const str{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(bsl::from_chars<T>(str, 10_i32).is_invalid());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::string_view const str{" \t\n\v\f\r"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(bsl::from_chars<T>(str, 10_i32).is_invalid());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::string_view const str{"42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(bsl::from_chars<T>(str, 42_i32).is_invalid());
                };
            };
        };

        bsl::ut_scenario{"dec negative"} = []() noexcept {
            if constexpr (bsl::is_signed<T>::value) {
                bsl::ut_given{} = []() noexcept {
                    bsl::string_view const str{"-42"};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(bsl::from_chars<T>(str, 10_i32) == static_cast<T>(-42));
                    };
                };

                bsl::ut_given{} = []() noexcept {
                    bsl::string_view const str{"--42"};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(bsl::from_chars<T>(str, 10_i32).is_invalid());
                    };
                };

                bsl::ut_given{} = []() noexcept {
                    bsl::string_view const str{"-4-2"};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(bsl::from_chars<T>(str, 10_i32).is_invalid());
                    };
                };

                bsl::ut_given{} = []() noexcept {
                    bsl::string_view const str{"-/42"};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(bsl::from_chars<T>(str, 10_i32).is_invalid());
                    };
                };

                bsl::ut_given{} = []() noexcept {
                    bsl::string_view const str{"-:42"};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(bsl::from_chars<T>(str, 10_i32).is_invalid());
                    };
                };

                bsl::ut_given{} = []() noexcept {
                    bsl::string_view const str{"-/"};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(bsl::from_chars<T>(str, 10_i32).is_invalid());
                    };
                };

                bsl::ut_given{} = []() noexcept {
                    bsl::string_view const str{"-:"};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(bsl::from_chars<T>(str, 10_i32).is_invalid());
                    };
                };

                bsl::ut_given_at_runtime{} = []() noexcept {
                    bsl::string_view const str{"-42424242424242424242424242424242"};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(bsl::from_chars<T>(str, 10_i32).is_invalid());
                    };
                };

                if constexpr (bsl::is_same<T, bsl::int8>::value) {
                    bsl::ut_given{} = []() noexcept {
                        bsl::string_view const str{"-128"};
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check(
                                bsl::from_chars<T>(str, 10_i32) == bsl::safe_i8::min_value());
                        };
                    };
                }

                if constexpr (bsl::is_same<T, bsl::int16>::value) {
                    bsl::ut_given{} = []() noexcept {
                        bsl::string_view const str{"-32768"};
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check(
                                bsl::from_chars<T>(str, 10_i32) == bsl::safe_i16::min_value());
                        };
                    };
                }

                if constexpr (bsl::is_same<T, bsl::int32>::value) {
                    bsl::ut_given{} = []() noexcept {
                        bsl::string_view const str{"-2147483648"};
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check(
                                bsl::from_chars<T>(str, 10_i32) == bsl::safe_i32::min_value());
                        };
                    };
                }

                if constexpr (bsl::is_same<T, bsl::int64>::value) {
                    bsl::ut_given{} = []() noexcept {
                        bsl::string_view const str{"-9223372036854775808"};
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check(
                                bsl::from_chars<T>(str, 10_i32) == bsl::safe_i64::min_value());
                        };
                    };
                }
            }
            else {
                bsl::ut_given{} = []() noexcept {
                    bsl::string_view const str{"-42"};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(bsl::from_chars<bsl::uint8>(str, 10_i32).is_invalid());
                    };
                };
            }
        };

        bsl::ut_scenario{"dec positive"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::string_view const str{"42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(bsl::from_chars<T>(str, 10_i32) == static_cast<T>(42));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::string_view const str{"/42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(bsl::from_chars<T>(str, 10_i32).is_invalid());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::string_view const str{":42"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(bsl::from_chars<T>(str, 10_i32).is_invalid());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::string_view const str{"/"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(bsl::from_chars<T>(str, 10_i32).is_invalid());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::string_view const str{"4/2"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(bsl::from_chars<T>(str, 10_i32).is_invalid());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::string_view const str{":"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(bsl::from_chars<T>(str, 10_i32).is_invalid());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::string_view const str{"4:2"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(bsl::from_chars<T>(str, 10_i32).is_invalid());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::string_view const str{"42424242424242424242424242424242"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(bsl::from_chars<T>(str, 10_i32).is_invalid());
                };
            };

            if constexpr (bsl::is_same<T, bsl::int8>::value) {
                bsl::ut_given{} = []() noexcept {
                    bsl::string_view const str{"127"};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(bsl::from_chars<T>(str, 10_i32) == bsl::safe_i8::max_value());
                    };
                };
            }

            if constexpr (bsl::is_same<T, bsl::int16>::value) {
                bsl::ut_given{} = []() noexcept {
                    bsl::string_view const str{"32767"};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            bsl::from_chars<T>(str, 10_i32) == bsl::safe_i16::max_value());
                    };
                };
            }

            if constexpr (bsl::is_same<T, bsl::int32>::value) {
                bsl::ut_given{} = []() noexcept {
                    bsl::string_view const str{"2147483647"};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            bsl::from_chars<T>(str, 10_i32) == bsl::safe_i32::max_value());
                    };
                };
            }

            if constexpr (bsl::is_same<T, bsl::int64>::value) {
                bsl::ut_given{} = []() noexcept {
                    bsl::string_view const str{"9223372036854775807"};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            bsl::from_chars<T>(str, 10_i32) == bsl::safe_i64::max_value());
                    };
                };
            }

            if constexpr (bsl::is_same<T, bsl::uint8>::value) {
                bsl::ut_given{} = []() noexcept {
                    bsl::string_view const str{"255"};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(bsl::from_chars<T>(str, 10_i32) == bsl::safe_u8::max_value());
                    };
                };
            }

            if constexpr (bsl::is_same<T, bsl::uint16>::value) {
                bsl::ut_given{} = []() noexcept {
                    bsl::string_view const str{"65535"};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            bsl::from_chars<T>(str, 10_i32) == bsl::safe_u16::max_value());
                    };
                };
            }

            if constexpr (bsl::is_same<T, bsl::uint32>::value) {
                bsl::ut_given{} = []() noexcept {
                    bsl::string_view const str{"4294967295"};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            bsl::from_chars<T>(str, 10_i32) == bsl::safe_u32::max_value());
                    };
                };
            }

            if constexpr (bsl::is_same<T, bsl::uint64>::value) {
                bsl::ut_given{} = []() noexcept {
                    bsl::string_view const str{"18446744073709551615"};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            bsl::from_chars<T>(str, 10_i32) == bsl::safe_u64::max_value());
                    };
                };
            }
        };

        bsl::ut_scenario{"hex"} = []() noexcept {
            if constexpr (bsl::is_signed<T>::value) {
                bsl::ut_given{} = []() noexcept {
                    bsl::string_view const str{"42"};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(bsl::from_chars<T>(str, 16_i32).is_invalid());
                    };
                };
            }
            else {
                bsl::ut_given{} = []() noexcept {
                    bsl::string_view const str{"42"};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(bsl::from_chars<T>(str, 16_i32) == static_cast<T>(0x42));
                    };
                };

                bsl::ut_given{} = []() noexcept {
                    bsl::string_view const str{"90"};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(bsl::from_chars<T>(str, 16_i32) == static_cast<T>(0x90));
                    };
                };

                bsl::ut_given{} = []() noexcept {
                    bsl::string_view const str{"af"};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(bsl::from_chars<T>(str, 16_i32) == static_cast<T>(0xAF));
                    };
                };

                bsl::ut_given{} = []() noexcept {
                    bsl::string_view const str{"Af"};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(bsl::from_chars<T>(str, 16_i32) == static_cast<T>(0xAF));
                    };
                };

                bsl::ut_given{} = []() noexcept {
                    bsl::string_view const str{"aF"};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(bsl::from_chars<T>(str, 16_i32) == static_cast<T>(0xAF));
                    };
                };

                bsl::ut_given{} = []() noexcept {
                    bsl::string_view const str{"AF"};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(bsl::from_chars<T>(str, 16_i32) == static_cast<T>(0xAF));
                    };
                };

                bsl::ut_given{} = []() noexcept {
                    bsl::string_view const str{"/42"};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(bsl::from_chars<T>(str, 16_i32).is_invalid());
                    };
                };

                bsl::ut_given{} = []() noexcept {
                    bsl::string_view const str{":42"};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(bsl::from_chars<T>(str, 16_i32).is_invalid());
                    };
                };

                bsl::ut_given{} = []() noexcept {
                    bsl::string_view const str{"@42"};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(bsl::from_chars<T>(str, 16_i32).is_invalid());
                    };
                };

                bsl::ut_given{} = []() noexcept {
                    bsl::string_view const str{"G42"};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(bsl::from_chars<T>(str, 16_i32).is_invalid());
                    };
                };

                bsl::ut_given{} = []() noexcept {
                    bsl::string_view const str{"`42"};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(bsl::from_chars<T>(str, 16_i32).is_invalid());
                    };
                };

                bsl::ut_given{} = []() noexcept {
                    bsl::string_view const str{"g42"};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(bsl::from_chars<T>(str, 16_i32).is_invalid());
                    };
                };

                bsl::ut_given{} = []() noexcept {
                    bsl::string_view const str{"/"};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(bsl::from_chars<T>(str, 16_i32).is_invalid());
                    };
                };

                bsl::ut_given{} = []() noexcept {
                    bsl::string_view const str{":"};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(bsl::from_chars<T>(str, 16_i32).is_invalid());
                    };
                };

                bsl::ut_given{} = []() noexcept {
                    bsl::string_view const str{"@"};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(bsl::from_chars<T>(str, 16_i32).is_invalid());
                    };
                };

                bsl::ut_given{} = []() noexcept {
                    bsl::string_view const str{"G"};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(bsl::from_chars<T>(str, 16_i32).is_invalid());
                    };
                };

                bsl::ut_given{} = []() noexcept {
                    bsl::string_view const str{"`"};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(bsl::from_chars<T>(str, 16_i32).is_invalid());
                    };
                };

                bsl::ut_given{} = []() noexcept {
                    bsl::string_view const str{"g"};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(bsl::from_chars<T>(str, 16_i32).is_invalid());
                    };
                };

                bsl::ut_given_at_runtime{} = []() noexcept {
                    bsl::string_view const str{"42424242424242424242424242424242"};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(bsl::from_chars<T>(str, 16_i32).is_invalid());
                    };
                };

                bsl::ut_given{} = []() noexcept {
                    bsl::string_view const str{"0"};
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(
                            bsl::from_chars<T>(str, 16_i32) == bsl::safe_integral<T>::min_value());
                    };
                };

                if constexpr (bsl::is_same<T, bsl::uint8>::value) {
                    bsl::ut_given{} = []() noexcept {
                        bsl::string_view const str{"FF"};
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check(
                                bsl::from_chars<T>(str, 16_i32) == bsl::safe_u8::max_value());
                        };
                    };
                }

                if constexpr (bsl::is_same<T, bsl::uint16>::value) {
                    bsl::ut_given{} = []() noexcept {
                        bsl::string_view const str{"FFFF"};
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check(
                                bsl::from_chars<T>(str, 16_i32) == bsl::safe_u16::max_value());
                        };
                    };
                }

                if constexpr (bsl::is_same<T, bsl::uint32>::value) {
                    bsl::ut_given{} = []() noexcept {
                        bsl::string_view const str{"FFFFFFFF"};
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check(
                                bsl::from_chars<T>(str, 16_i32) == bsl::safe_u32::max_value());
                        };
                    };
                }

                if constexpr (bsl::is_same<T, bsl::uint64>::value) {
                    bsl::ut_given{} = []() noexcept {
                        bsl::string_view const str{"FFFFFFFFFFFFFFFF"};
                        bsl::ut_then{} = [&]() noexcept {
                            bsl::ut_check(
                                bsl::from_chars<T>(str, 16_i32) == bsl::safe_u64::max_value());
                        };
                    };
                }
            }
        };

        return bsl::ut_success();
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
    static_assert(tests<bsl::int8>() == bsl::ut_success());
    static_assert(tests<bsl::int16>() == bsl::ut_success());
    static_assert(tests<bsl::int32>() == bsl::ut_success());
    static_assert(tests<bsl::int64>() == bsl::ut_success());
    static_assert(tests<bsl::uint8>() == bsl::ut_success());
    static_assert(tests<bsl::uint16>() == bsl::ut_success());
    static_assert(tests<bsl::uint32>() == bsl::ut_success());
    static_assert(tests<bsl::uint64>() == bsl::ut_success());

    bsl::discard(tests<bsl::int8>());
    bsl::discard(tests<bsl::int16>());
    bsl::discard(tests<bsl::int32>());
    bsl::discard(tests<bsl::int64>());
    bsl::discard(tests<bsl::uint8>());
    bsl::discard(tests<bsl::uint16>());
    bsl::discard(tests<bsl::uint32>());
    bsl::discard(tests<bsl::uint64>());

    return bsl::ut_success();
}
