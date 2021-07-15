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

#include <bsl/basic_string_view.hpp>
#include <bsl/convert.hpp>
#include <bsl/cstr_type.hpp>
#include <bsl/npos.hpp>
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
        bsl::ut_scenario{"construction"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(msg.empty());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::cstr_type const null_msg{};
                bsl::basic_string_view<bsl::char_type> const msg{null_msg};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(msg.empty());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{""};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(msg.empty());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(msg == "Hello");
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::cstr_type const null_msg{};
                bsl::basic_string_view<bsl::char_type> const msg{null_msg, bsl::to_umax(0)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(msg.empty());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{"", bsl::to_umax(0)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(msg.empty());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{"Hello", bsl::to_umax(0)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(msg.empty());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{"Hello", bsl::safe_uintmax::failure()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(msg.empty());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{"Hello", bsl::to_umax(5)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(msg == "Hello");
                };
            };
        };

        bsl::ut_scenario{"assignment"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> mut_msg{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_msg = "";
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_msg.empty());
                    };
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> mut_msg{"Hello"};
                bsl::ut_when{} = [&]() noexcept {
                    mut_msg = "";
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_msg.empty());
                    };
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> mut_msg{""};
                bsl::ut_when{} = [&]() noexcept {
                    mut_msg = "Hello";
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_msg == "Hello");
                    };
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> mut_msg{"World"};
                bsl::ut_when{} = [&]() noexcept {
                    mut_msg = "Hello";
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_msg == "Hello");
                    };
                };
            };
        };

        bsl::ut_scenario{"at_if"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> mut_msg{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(nullptr == mut_msg.at_if(bsl::to_umax(0)));
                    bsl::ut_check(nullptr == mut_msg.at_if(bsl::npos));
                    bsl::ut_check(nullptr == mut_msg.at_if(bsl::safe_uintmax::failure()));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(nullptr == msg.at_if(bsl::to_umax(0)));
                    bsl::ut_check(nullptr == msg.at_if(bsl::npos));
                    bsl::ut_check(nullptr == msg.at_if(bsl::safe_uintmax::failure()));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> mut_msg{"Hello"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check('H' == *mut_msg.at_if(bsl::to_umax(0)));
                    bsl::ut_check('e' == *mut_msg.at_if(bsl::to_umax(1)));
                    bsl::ut_check('l' == *mut_msg.at_if(bsl::to_umax(2)));
                    bsl::ut_check('l' == *mut_msg.at_if(bsl::to_umax(3)));
                    bsl::ut_check('o' == *mut_msg.at_if(bsl::to_umax(4)));
                    bsl::ut_check(nullptr == mut_msg.at_if(bsl::to_umax(5)));
                    bsl::ut_check(nullptr == mut_msg.at_if(bsl::npos));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> mut_msg{"Hello"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(nullptr == mut_msg.at_if(bsl::safe_uintmax::failure()));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check('H' == *msg.at_if(bsl::to_umax(0)));
                    bsl::ut_check('e' == *msg.at_if(bsl::to_umax(1)));
                    bsl::ut_check('l' == *msg.at_if(bsl::to_umax(2)));
                    bsl::ut_check('l' == *msg.at_if(bsl::to_umax(3)));
                    bsl::ut_check('o' == *msg.at_if(bsl::to_umax(4)));
                    bsl::ut_check(nullptr == msg.at_if(bsl::to_umax(5)));
                    bsl::ut_check(nullptr == msg.at_if(bsl::npos));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(nullptr == msg.at_if(bsl::safe_uintmax::failure()));
                };
            };
        };

        bsl::ut_scenario{"front_if"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> mut_msg{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(nullptr == mut_msg.front_if());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(nullptr == msg.front_if());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> mut_msg{"Hello"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check('H' == *mut_msg.front_if());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check('H' == *msg.front_if());
                };
            };
        };

        bsl::ut_scenario{"back_if"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> mut_msg{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(nullptr == mut_msg.back_if());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(nullptr == msg.back_if());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> mut_msg{"Hello"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check('o' == *mut_msg.back_if());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check('o' == *msg.back_if());
                };
            };
        };

        bsl::ut_scenario{"data"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> mut_msg{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(nullptr == mut_msg.data());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(nullptr == msg.data());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> mut_msg{"Hello"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(nullptr != mut_msg.data());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(nullptr != msg.data());
                };
            };
        };

        bsl::ut_scenario{"begin"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> mut_msg{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(nullptr == mut_msg.begin().get_if());
                    bsl::ut_check(bsl::to_umax(0) == mut_msg.begin().index());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(nullptr == msg.begin().get_if());
                    bsl::ut_check(bsl::to_umax(0) == msg.begin().index());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(nullptr == msg.cbegin().get_if());
                    bsl::ut_check(bsl::to_umax(0) == msg.cbegin().index());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> mut_msg{"Hello"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check('H' == *(mut_msg.begin().get_if()));
                    bsl::ut_check(bsl::to_umax(0) == mut_msg.begin().index());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check('H' == *(msg.begin().get_if()));
                    bsl::ut_check(bsl::to_umax(0) == msg.begin().index());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check('H' == *(msg.cbegin().get_if()));
                    bsl::ut_check(bsl::to_umax(0) == msg.cbegin().index());
                };
            };
        };

        bsl::ut_scenario{"iter"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> mut_msg{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(nullptr == mut_msg.iter(bsl::to_umax(1)).get_if());
                    bsl::ut_check(mut_msg.size() == mut_msg.iter(bsl::to_umax(1)).index());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(nullptr == msg.iter(bsl::to_umax(1)).get_if());
                    bsl::ut_check(msg.size() == msg.iter(bsl::to_umax(1)).index());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(nullptr == msg.citer(bsl::to_umax(1)).get_if());
                    bsl::ut_check(msg.size() == msg.citer(bsl::to_umax(1)).index());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> mut_msg{"Hello"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check('e' == *(mut_msg.iter(bsl::to_umax(1)).get_if()));
                    bsl::ut_check(bsl::to_umax(1) == mut_msg.iter(bsl::to_umax(1)).index());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check('e' == *(msg.iter(bsl::to_umax(1)).get_if()));
                    bsl::ut_check(bsl::to_umax(1) == msg.iter(bsl::to_umax(1)).index());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check('e' == *(msg.citer(bsl::to_umax(1)).get_if()));
                    bsl::ut_check(bsl::to_umax(1) == msg.citer(bsl::to_umax(1)).index());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> mut_msg{"Hello"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(nullptr == mut_msg.iter(bsl::npos).get_if());
                    bsl::ut_check(mut_msg.size() == mut_msg.iter(bsl::npos).index());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(nullptr == msg.iter(bsl::npos).get_if());
                    bsl::ut_check(msg.size() == msg.iter(bsl::npos).index());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(nullptr == msg.citer(bsl::npos).get_if());
                    bsl::ut_check(msg.size() == msg.citer(bsl::npos).index());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> mut_msg{"Hello"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(nullptr == mut_msg.iter(bsl::safe_uintmax::failure()).get_if());
                    bsl::ut_check(mut_msg.size() == mut_msg.iter(bsl::safe_uintmax::failure()).index());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(nullptr == msg.iter(bsl::safe_uintmax::failure()).get_if());
                    bsl::ut_check(msg.size() == msg.iter(bsl::safe_uintmax::failure()).index());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(nullptr == msg.citer(bsl::safe_uintmax::failure()).get_if());
                    bsl::ut_check(msg.size() == msg.citer(bsl::safe_uintmax::failure()).index());
                };
            };
        };

        bsl::ut_scenario{"end"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> mut_msg{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(nullptr == mut_msg.end().get_if());
                    bsl::ut_check(mut_msg.size() == mut_msg.end().index());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(nullptr == msg.end().get_if());
                    bsl::ut_check(msg.size() == msg.end().index());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(nullptr == msg.cend().get_if());
                    bsl::ut_check(msg.size() == msg.cend().index());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> mut_msg{"Hello"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_msg.size() == mut_msg.end().index());
                    bsl::ut_check(nullptr == mut_msg.end().get_if());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(msg.size() == msg.end().index());
                    bsl::ut_check(nullptr == msg.end().get_if());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(msg.size() == msg.cend().index());
                    bsl::ut_check(nullptr == msg.cend().get_if());
                };
            };
        };

        bsl::ut_scenario{"rbegin"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> mut_msg{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(nullptr == mut_msg.rbegin().get_if());
                    bsl::ut_check(bsl::to_umax(0) == mut_msg.rbegin().index());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(nullptr == msg.rbegin().get_if());
                    bsl::ut_check(bsl::to_umax(0) == msg.rbegin().index());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(nullptr == msg.crbegin().get_if());
                    bsl::ut_check(bsl::to_umax(0) == msg.crbegin().index());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> mut_msg{"Hello"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check('o' == *(mut_msg.rbegin().get_if()));
                    bsl::ut_check(bsl::to_umax(4) == mut_msg.rbegin().index());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check('o' == *(msg.rbegin().get_if()));
                    bsl::ut_check(bsl::to_umax(4) == msg.rbegin().index());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check('o' == *(msg.crbegin().get_if()));
                    bsl::ut_check(bsl::to_umax(4) == msg.crbegin().index());
                };
            };
        };

        bsl::ut_scenario{"riter"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> mut_msg{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(nullptr == mut_msg.riter(bsl::to_umax(1)).get_if());
                    bsl::ut_check(mut_msg.size() == mut_msg.riter(bsl::to_umax(1)).index());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(nullptr == msg.riter(bsl::to_umax(1)).get_if());
                    bsl::ut_check(msg.size() == msg.riter(bsl::to_umax(1)).index());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(nullptr == msg.criter(bsl::to_umax(1)).get_if());
                    bsl::ut_check(msg.size() == msg.criter(bsl::to_umax(1)).index());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> mut_msg{"Hello"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check('e' == *(mut_msg.riter(bsl::to_umax(1)).get_if()));
                    bsl::ut_check(bsl::to_umax(1) == mut_msg.riter(bsl::to_umax(1)).index());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check('e' == *(msg.riter(bsl::to_umax(1)).get_if()));
                    bsl::ut_check(bsl::to_umax(1) == msg.riter(bsl::to_umax(1)).index());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check('e' == *(msg.criter(bsl::to_umax(1)).get_if()));
                    bsl::ut_check(bsl::to_umax(1) == msg.criter(bsl::to_umax(1)).index());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> mut_msg{"Hello"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(nullptr == mut_msg.riter(bsl::npos).get_if());
                    bsl::ut_check(mut_msg.size() == mut_msg.riter(bsl::npos).index());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(nullptr == msg.riter(bsl::npos).get_if());
                    bsl::ut_check(msg.size() == msg.riter(bsl::npos).index());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(nullptr == msg.criter(bsl::npos).get_if());
                    bsl::ut_check(msg.size() == msg.criter(bsl::npos).index());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> mut_msg{"Hello"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(nullptr == mut_msg.riter(bsl::safe_uintmax::failure()).get_if());
                    bsl::ut_check(mut_msg.size() == mut_msg.riter(bsl::safe_uintmax::failure()).index());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(nullptr == msg.riter(bsl::safe_uintmax::failure()).get_if());
                    bsl::ut_check(msg.size() == msg.riter(bsl::safe_uintmax::failure()).index());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(nullptr == msg.criter(bsl::safe_uintmax::failure()).get_if());
                    bsl::ut_check(msg.size() == msg.criter(bsl::safe_uintmax::failure()).index());
                };
            };
        };

        bsl::ut_scenario{"rend"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> mut_msg{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(nullptr == mut_msg.rend().get_if());
                    bsl::ut_check(mut_msg.size() == mut_msg.rend().index());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(nullptr == msg.rend().get_if());
                    bsl::ut_check(msg.size() == msg.rend().index());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(nullptr == msg.crend().get_if());
                    bsl::ut_check(msg.size() == msg.crend().index());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> mut_msg{"Hello"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_msg.size() == mut_msg.rend().index());
                    bsl::ut_check(nullptr == mut_msg.rend().get_if());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(msg.size() == msg.rend().index());
                    bsl::ut_check(nullptr == msg.rend().get_if());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(msg.size() == msg.crend().index());
                    bsl::ut_check(nullptr == msg.crend().get_if());
                };
            };
        };

        bsl::ut_scenario{"empty"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> mut_msg{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_msg.empty());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(msg.empty());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> mut_msg{"Hello"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!mut_msg.empty());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!msg.empty());
                };
            };
        };

        bsl::ut_scenario{"operator bool"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> mut_msg{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!mut_msg);
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!msg);
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> mut_msg{"Hello"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!!mut_msg);
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!!msg);
                };
            };
        };

        bsl::ut_scenario{"size"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> mut_msg{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_msg.size() == bsl::to_umax(0));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(msg.size() == bsl::to_umax(0));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> mut_msg{"Hello"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_msg.size() == bsl::to_umax(5));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(msg.size() == bsl::to_umax(5));
                };
            };
        };

        bsl::ut_scenario{"length"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> mut_msg{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(bsl::to_umax(0) == mut_msg.length());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(bsl::to_umax(0) == msg.length());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> mut_msg{"Hello"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_msg.length() == bsl::to_umax(5));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(msg.length() == bsl::to_umax(5));
                };
            };
        };

        bsl::ut_scenario{"max_size"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> mut_msg{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_msg.max_size() == bsl::safe_uintmax::max() / sizeof(bsl::char_type));
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(msg.max_size() == bsl::safe_uintmax::max() / sizeof(bsl::char_type));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> mut_msg{"Hello"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_msg.max_size() == bsl::safe_uintmax::max() / sizeof(bsl::char_type));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(msg.max_size() == bsl::safe_uintmax::max() / sizeof(bsl::char_type));
                };
            };
        };

        bsl::ut_scenario{"size_bytes"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> mut_msg{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(bsl::to_umax(0) == mut_msg.size_bytes());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(bsl::to_umax(0) == msg.size_bytes());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> mut_msg{"Hello"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_msg.size_bytes() == bsl::to_umax(5) * sizeof(bsl::char_type));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(msg.size_bytes() == bsl::to_umax(5) * sizeof(bsl::char_type));
                };
            };
        };

        bsl::ut_scenario{"remove_prefix"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> mut_msg{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_msg.remove_prefix(bsl::to_umax(0));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_msg.empty());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> mut_msg{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_msg.remove_prefix(bsl::npos);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_msg.empty());
                    };
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> mut_msg{"Hello World"};
                bsl::ut_when{} = [&]() noexcept {
                    mut_msg.remove_prefix(bsl::to_umax(0));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_msg == "Hello World");
                    };
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> mut_msg{"Hello World"};
                bsl::ut_when{} = [&]() noexcept {
                    mut_msg.remove_prefix(bsl::to_umax(6));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_msg == "World");
                    };
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> mut_msg{"Hello World"};
                bsl::ut_when{} = [&]() noexcept {
                    mut_msg.remove_prefix(bsl::npos);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_msg.empty());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> mut_msg{"Hello World"};
                bsl::ut_when{} = [&]() noexcept {
                    mut_msg.remove_prefix(bsl::safe_uintmax::failure());
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_msg.empty());
                    };
                };
            };
        };

        bsl::ut_scenario{"remove_suffix"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> mut_msg{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_msg.remove_suffix(bsl::to_umax(0));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_msg.empty());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> mut_msg{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_msg.remove_suffix(bsl::npos);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_msg.empty());
                    };
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> mut_msg{"Hello World"};
                bsl::ut_when{} = [&]() noexcept {
                    mut_msg.remove_suffix(bsl::to_umax(0));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_msg == "Hello World");
                    };
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> mut_msg{"Hello World"};
                bsl::ut_when{} = [&]() noexcept {
                    mut_msg.remove_suffix(bsl::to_umax(6));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_msg == "Hello");
                    };
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> mut_msg{"Hello World"};
                bsl::ut_when{} = [&]() noexcept {
                    mut_msg.remove_suffix(bsl::npos);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_msg.empty());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> mut_msg{"Hello World"};
                bsl::ut_when{} = [&]() noexcept {
                    mut_msg.remove_suffix(bsl::safe_uintmax::failure());
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_msg.empty());
                    };
                };
            };
        };

        bsl::ut_scenario{"substr"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(msg.substr(bsl::to_umax(0), bsl::to_umax(0)).empty());
                        bsl::ut_check(msg.substr(bsl::to_umax(0), bsl::to_umax(3)).empty());
                        bsl::ut_check(msg.substr(bsl::to_umax(0), bsl::npos).empty());
                        bsl::ut_check(msg.substr(bsl::to_umax(1), bsl::to_umax(0)).empty());
                        bsl::ut_check(msg.substr(bsl::to_umax(1), bsl::to_umax(3)).empty());
                        bsl::ut_check(msg.substr(bsl::to_umax(1), bsl::npos).empty());
                        bsl::ut_check(msg.substr(bsl::npos, bsl::to_umax(0)).empty());
                        bsl::ut_check(msg.substr(bsl::npos, bsl::to_umax(3)).empty());
                        bsl::ut_check(msg.substr(bsl::npos, bsl::npos).empty());
                        bsl::ut_check(msg.substr(bsl::safe_uintmax::failure(), bsl::safe_uintmax::failure()).empty());
                    };
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{"Hello World"};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(msg.substr(bsl::to_umax(0), bsl::to_umax(0)).empty());
                        bsl::ut_check(msg.substr(bsl::to_umax(0), bsl::to_umax(3)) == "Hel");
                        bsl::ut_check(msg.substr(bsl::to_umax(0), bsl::npos) == "Hello World");
                        bsl::ut_check(msg.substr(bsl::to_umax(1), bsl::to_umax(0)).empty());
                        bsl::ut_check(msg.substr(bsl::to_umax(1), bsl::to_umax(3)) == "ell");
                        bsl::ut_check(msg.substr(bsl::to_umax(1), bsl::npos) == "ello World");
                        bsl::ut_check(msg.substr(bsl::npos, bsl::to_umax(0)).empty());
                        bsl::ut_check(msg.substr(bsl::npos, bsl::to_umax(3)).empty());
                        bsl::ut_check(msg.substr(bsl::npos, bsl::npos).empty());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{"Hello World"};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(msg.substr(bsl::to_umax(0), bsl::safe_uintmax::failure()).empty());
                        bsl::ut_check(msg.substr(bsl::safe_uintmax::failure(), bsl::to_umax(0)).empty());
                    };
                };
            };
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
    static_assert(tests() == bsl::ut_success());
    return tests();
}
