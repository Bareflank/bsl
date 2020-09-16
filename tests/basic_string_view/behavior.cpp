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
        bsl::ut_scenario{"construction"} = []() {
            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> msg{};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(msg.empty());
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> msg{""};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(msg.empty());
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> msg{"Hello"};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(msg == "Hello");
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> msg{"Hello", bsl::to_umax(0)};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(msg.empty());
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> msg{"Hello", bsl::to_umax(5)};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(msg == "Hello");
                };
            };
        };

        bsl::ut_scenario{"assignment"} = []() {
            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> msg{};
                bsl::ut_when{} = [&msg]() {
                    msg = "";
                    bsl::ut_then{} = [&msg]() {
                        bsl::ut_check(msg.empty());
                    };
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> msg{"Hello"};
                bsl::ut_when{} = [&msg]() {
                    msg = "";
                    bsl::ut_then{} = [&msg]() {
                        bsl::ut_check(msg.empty());
                    };
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> msg{""};
                bsl::ut_when{} = [&msg]() {
                    msg = "Hello";
                    bsl::ut_then{} = [&msg]() {
                        bsl::ut_check(msg == "Hello");
                    };
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> msg{"World"};
                bsl::ut_when{} = [&msg]() {
                    msg = "Hello";
                    bsl::ut_then{} = [&msg]() {
                        bsl::ut_check(msg == "Hello");
                    };
                };
            };
        };

        bsl::ut_scenario{"at_if"} = []() {
            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> msg{};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(msg.at_if(bsl::to_umax(0)) == nullptr);
                    bsl::ut_check(msg.at_if(bsl::npos) == nullptr);
                    bsl::ut_check(msg.at_if(bsl::safe_uintmax::zero(true)) == nullptr);
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> const msg{};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(msg.at_if(bsl::to_umax(0)) == nullptr);
                    bsl::ut_check(msg.at_if(bsl::npos) == nullptr);
                    bsl::ut_check(msg.at_if(bsl::safe_uintmax::zero(true)) == nullptr);
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> msg{"Hello"};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(*msg.at_if(bsl::to_umax(0)) == 'H');
                    bsl::ut_check(*msg.at_if(bsl::to_umax(1)) == 'e');
                    bsl::ut_check(*msg.at_if(bsl::to_umax(2)) == 'l');
                    bsl::ut_check(*msg.at_if(bsl::to_umax(3)) == 'l');
                    bsl::ut_check(*msg.at_if(bsl::to_umax(4)) == 'o');
                    bsl::ut_check(msg.at_if(bsl::to_umax(5)) == nullptr);
                    bsl::ut_check(msg.at_if(bsl::npos) == nullptr);
                    bsl::ut_check(msg.at_if(bsl::safe_uintmax::zero(true)) == nullptr);
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(*msg.at_if(bsl::to_umax(0)) == 'H');
                    bsl::ut_check(*msg.at_if(bsl::to_umax(1)) == 'e');
                    bsl::ut_check(*msg.at_if(bsl::to_umax(2)) == 'l');
                    bsl::ut_check(*msg.at_if(bsl::to_umax(3)) == 'l');
                    bsl::ut_check(*msg.at_if(bsl::to_umax(4)) == 'o');
                    bsl::ut_check(msg.at_if(bsl::to_umax(5)) == nullptr);
                    bsl::ut_check(msg.at_if(bsl::npos) == nullptr);
                    bsl::ut_check(msg.at_if(bsl::safe_uintmax::zero(true)) == nullptr);
                };
            };
        };

        bsl::ut_scenario{"front_if"} = []() {
            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> msg{};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(msg.front_if() == nullptr);
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> const msg{};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(msg.front_if() == nullptr);
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> msg{"Hello"};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(*msg.front_if() == 'H');
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(*msg.front_if() == 'H');
                };
            };
        };

        bsl::ut_scenario{"back_if"} = []() {
            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> msg{};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(msg.back_if() == nullptr);
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> const msg{};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(msg.back_if() == nullptr);
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> msg{"Hello"};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(*msg.back_if() == 'o');
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(*msg.back_if() == 'o');
                };
            };
        };

        bsl::ut_scenario{"data"} = []() {
            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> msg{};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(msg.data() == nullptr);
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> const msg{};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(msg.data() == nullptr);
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> msg{"Hello"};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(msg.data() != nullptr);
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(msg.data() != nullptr);
                };
            };
        };

        bsl::ut_scenario{"begin"} = []() {
            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> msg{};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(msg.begin().get_if() == nullptr);
                    bsl::ut_check(msg.begin().index() == bsl::to_umax(0));
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> const msg{};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(msg.begin().get_if() == nullptr);
                    bsl::ut_check(msg.begin().index() == bsl::to_umax(0));
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> const msg{};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(msg.cbegin().get_if() == nullptr);
                    bsl::ut_check(msg.cbegin().index() == bsl::to_umax(0));
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> msg{"Hello"};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(*(msg.begin().get_if()) == 'H');
                    bsl::ut_check(msg.begin().index() == bsl::to_umax(0));
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(*(msg.begin().get_if()) == 'H');
                    bsl::ut_check(msg.begin().index() == bsl::to_umax(0));
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(*(msg.cbegin().get_if()) == 'H');
                    bsl::ut_check(msg.cbegin().index() == bsl::to_umax(0));
                };
            };
        };

        bsl::ut_scenario{"iter"} = []() {
            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> msg{};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(msg.iter(bsl::to_umax(1)).get_if() == nullptr);
                    bsl::ut_check(msg.iter(bsl::to_umax(1)).index() == msg.size());
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> const msg{};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(msg.iter(bsl::to_umax(1)).get_if() == nullptr);
                    bsl::ut_check(msg.iter(bsl::to_umax(1)).index() == msg.size());
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> const msg{};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(msg.citer(bsl::to_umax(1)).get_if() == nullptr);
                    bsl::ut_check(msg.citer(bsl::to_umax(1)).index() == msg.size());
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> msg{"Hello"};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(*(msg.iter(bsl::to_umax(1)).get_if()) == 'e');
                    bsl::ut_check(msg.iter(bsl::to_umax(1)).index() == bsl::to_umax(1));
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(*(msg.iter(bsl::to_umax(1)).get_if()) == 'e');
                    bsl::ut_check(msg.iter(bsl::to_umax(1)).index() == bsl::to_umax(1));
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(*(msg.citer(bsl::to_umax(1)).get_if()) == 'e');
                    bsl::ut_check(msg.citer(bsl::to_umax(1)).index() == bsl::to_umax(1));
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> msg{"Hello"};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(msg.iter(bsl::npos).get_if() == nullptr);
                    bsl::ut_check(msg.iter(bsl::npos).index() == msg.size());
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(msg.iter(bsl::npos).get_if() == nullptr);
                    bsl::ut_check(msg.iter(bsl::npos).index() == msg.size());
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(msg.citer(bsl::npos).get_if() == nullptr);
                    bsl::ut_check(msg.citer(bsl::npos).index() == msg.size());
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> msg{"Hello"};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(msg.iter(bsl::safe_uintmax::zero(true)).get_if() == nullptr);
                    bsl::ut_check(msg.iter(bsl::safe_uintmax::zero(true)).index() == msg.size());
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(msg.iter(bsl::safe_uintmax::zero(true)).get_if() == nullptr);
                    bsl::ut_check(msg.iter(bsl::safe_uintmax::zero(true)).index() == msg.size());
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(msg.citer(bsl::safe_uintmax::zero(true)).get_if() == nullptr);
                    bsl::ut_check(msg.citer(bsl::safe_uintmax::zero(true)).index() == msg.size());
                };
            };
        };

        bsl::ut_scenario{"end"} = []() {
            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> msg{};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(msg.end().get_if() == nullptr);
                    bsl::ut_check(msg.end().index() == msg.size());
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> const msg{};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(msg.end().get_if() == nullptr);
                    bsl::ut_check(msg.end().index() == msg.size());
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> const msg{};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(msg.cend().get_if() == nullptr);
                    bsl::ut_check(msg.cend().index() == msg.size());
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> msg{"Hello"};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(msg.end().get_if() == nullptr);
                    bsl::ut_check(msg.end().index() == msg.size());
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(msg.end().get_if() == nullptr);
                    bsl::ut_check(msg.end().index() == msg.size());
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(msg.cend().get_if() == nullptr);
                    bsl::ut_check(msg.cend().index() == msg.size());
                };
            };
        };

        bsl::ut_scenario{"rbegin"} = []() {
            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> msg{};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(msg.rbegin().get_if() == nullptr);
                    bsl::ut_check(msg.rbegin().index() == bsl::to_umax(0));
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> const msg{};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(msg.rbegin().get_if() == nullptr);
                    bsl::ut_check(msg.rbegin().index() == bsl::to_umax(0));
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> const msg{};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(msg.crbegin().get_if() == nullptr);
                    bsl::ut_check(msg.crbegin().index() == bsl::to_umax(0));
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> msg{"Hello"};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(*(msg.rbegin().get_if()) == 'o');
                    bsl::ut_check(msg.rbegin().index() == bsl::to_umax(4));
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(*(msg.rbegin().get_if()) == 'o');
                    bsl::ut_check(msg.rbegin().index() == bsl::to_umax(4));
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(*(msg.crbegin().get_if()) == 'o');
                    bsl::ut_check(msg.crbegin().index() == bsl::to_umax(4));
                };
            };
        };

        bsl::ut_scenario{"riter"} = []() {
            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> msg{};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(msg.riter(bsl::to_umax(1)).get_if() == nullptr);
                    bsl::ut_check(msg.riter(bsl::to_umax(1)).index() == msg.size());
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> const msg{};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(msg.riter(bsl::to_umax(1)).get_if() == nullptr);
                    bsl::ut_check(msg.riter(bsl::to_umax(1)).index() == msg.size());
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> const msg{};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(msg.criter(bsl::to_umax(1)).get_if() == nullptr);
                    bsl::ut_check(msg.criter(bsl::to_umax(1)).index() == msg.size());
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> msg{"Hello"};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(*(msg.riter(bsl::to_umax(1)).get_if()) == 'e');
                    bsl::ut_check(msg.riter(bsl::to_umax(1)).index() == bsl::to_umax(1));
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(*(msg.riter(bsl::to_umax(1)).get_if()) == 'e');
                    bsl::ut_check(msg.riter(bsl::to_umax(1)).index() == bsl::to_umax(1));
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(*(msg.criter(bsl::to_umax(1)).get_if()) == 'e');
                    bsl::ut_check(msg.criter(bsl::to_umax(1)).index() == bsl::to_umax(1));
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> msg{"Hello"};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(msg.riter(bsl::npos).get_if() == nullptr);
                    bsl::ut_check(msg.riter(bsl::npos).index() == msg.size());
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(msg.riter(bsl::npos).get_if() == nullptr);
                    bsl::ut_check(msg.riter(bsl::npos).index() == msg.size());
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(msg.criter(bsl::npos).get_if() == nullptr);
                    bsl::ut_check(msg.criter(bsl::npos).index() == msg.size());
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> msg{"Hello"};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(msg.riter(bsl::safe_uintmax::zero(true)).get_if() == nullptr);
                    bsl::ut_check(msg.riter(bsl::safe_uintmax::zero(true)).index() == msg.size());
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(msg.riter(bsl::safe_uintmax::zero(true)).get_if() == nullptr);
                    bsl::ut_check(msg.riter(bsl::safe_uintmax::zero(true)).index() == msg.size());
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(msg.criter(bsl::safe_uintmax::zero(true)).get_if() == nullptr);
                    bsl::ut_check(msg.criter(bsl::safe_uintmax::zero(true)).index() == msg.size());
                };
            };
        };

        bsl::ut_scenario{"rend"} = []() {
            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> msg{};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(msg.rend().get_if() == nullptr);
                    bsl::ut_check(msg.rend().index() == msg.size());
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> const msg{};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(msg.rend().get_if() == nullptr);
                    bsl::ut_check(msg.rend().index() == msg.size());
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> const msg{};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(msg.crend().get_if() == nullptr);
                    bsl::ut_check(msg.crend().index() == msg.size());
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> msg{"Hello"};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(msg.rend().get_if() == nullptr);
                    bsl::ut_check(msg.rend().index() == msg.size());
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(msg.rend().get_if() == nullptr);
                    bsl::ut_check(msg.rend().index() == msg.size());
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(msg.crend().get_if() == nullptr);
                    bsl::ut_check(msg.crend().index() == msg.size());
                };
            };
        };

        bsl::ut_scenario{"empty"} = []() {
            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> msg{};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(msg.empty());
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> const msg{};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(msg.empty());
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> msg{"Hello"};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(!msg.empty());
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(!msg.empty());
                };
            };
        };

        bsl::ut_scenario{"operator bool"} = []() {
            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> msg{};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(!msg);
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> const msg{};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(!msg);
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> msg{"Hello"};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(!!msg);
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(!!msg);
                };
            };
        };

        bsl::ut_scenario{"size"} = []() {
            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> msg{};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(msg.size() == bsl::to_umax(0));
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> const msg{};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(msg.size() == bsl::to_umax(0));
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> msg{"Hello"};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(msg.size() == bsl::to_umax(5));
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(msg.size() == bsl::to_umax(5));
                };
            };
        };

        bsl::ut_scenario{"length"} = []() {
            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> msg{};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(msg.length() == bsl::to_umax(0));
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> const msg{};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(msg.length() == bsl::to_umax(0));
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> msg{"Hello"};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(msg.length() == bsl::to_umax(5));
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(msg.length() == bsl::to_umax(5));
                };
            };
        };

        bsl::ut_scenario{"max_size"} = []() {
            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> msg{};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(
                        msg.max_size() == bsl::safe_uintmax::max() / sizeof(bsl::char_type));
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> const msg{};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(
                        msg.max_size() == bsl::safe_uintmax::max() / sizeof(bsl::char_type));
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> msg{"Hello"};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(
                        msg.max_size() == bsl::safe_uintmax::max() / sizeof(bsl::char_type));
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(
                        msg.max_size() == bsl::safe_uintmax::max() / sizeof(bsl::char_type));
                };
            };
        };

        bsl::ut_scenario{"size_bytes"} = []() {
            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> msg{};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(msg.size_bytes() == bsl::to_umax(0));
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> const msg{};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(msg.size_bytes() == bsl::to_umax(0));
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> msg{"Hello"};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(msg.size_bytes() == bsl::to_umax(5) * sizeof(bsl::char_type));
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(msg.size_bytes() == bsl::to_umax(5) * sizeof(bsl::char_type));
                };
            };
        };

        bsl::ut_scenario{"remove_prefix"} = []() {
            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> msg{};
                bsl::ut_when{} = [&msg]() {
                    msg.remove_prefix(bsl::to_umax(0));
                    bsl::ut_then{} = [&msg]() {
                        bsl::ut_check(msg.empty());
                    };
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> msg{};
                bsl::ut_when{} = [&msg]() {
                    msg.remove_prefix(bsl::npos);
                    bsl::ut_then{} = [&msg]() {
                        bsl::ut_check(msg.empty());
                    };
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> msg{"Hello World"};
                bsl::ut_when{} = [&msg]() {
                    msg.remove_prefix(bsl::to_umax(0));
                    bsl::ut_then{} = [&msg]() {
                        bsl::ut_check(msg == "Hello World");
                    };
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> msg{"Hello World"};
                bsl::ut_when{} = [&msg]() {
                    msg.remove_prefix(bsl::to_umax(6));
                    bsl::ut_then{} = [&msg]() {
                        bsl::ut_check(msg == "World");
                    };
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> msg{"Hello World"};
                bsl::ut_when{} = [&msg]() {
                    msg.remove_prefix(bsl::npos);
                    bsl::ut_then{} = [&msg]() {
                        bsl::ut_check(msg.empty());
                    };
                };
            };
        };

        bsl::ut_scenario{"remove_suffix"} = []() {
            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> msg{};
                bsl::ut_when{} = [&msg]() {
                    msg.remove_suffix(bsl::to_umax(0));
                    bsl::ut_then{} = [&msg]() {
                        bsl::ut_check(msg.empty());
                    };
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> msg{};
                bsl::ut_when{} = [&msg]() {
                    msg.remove_suffix(bsl::npos);
                    bsl::ut_then{} = [&msg]() {
                        bsl::ut_check(msg.empty());
                    };
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> msg{"Hello World"};
                bsl::ut_when{} = [&msg]() {
                    msg.remove_suffix(bsl::to_umax(0));
                    bsl::ut_then{} = [&msg]() {
                        bsl::ut_check(msg == "Hello World");
                    };
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> msg{"Hello World"};
                bsl::ut_when{} = [&msg]() {
                    msg.remove_suffix(bsl::to_umax(6));
                    bsl::ut_then{} = [&msg]() {
                        bsl::ut_check(msg == "Hello");
                    };
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> msg{"Hello World"};
                bsl::ut_when{} = [&msg]() {
                    msg.remove_suffix(bsl::npos);
                    bsl::ut_then{} = [&msg]() {
                        bsl::ut_check(msg.empty());
                    };
                };
            };
        };

        bsl::ut_scenario{"substr"} = []() {
            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> msg{};
                bsl::ut_when{} = [&msg]() {
                    bsl::ut_then{} = [&msg]() {
                        bsl::ut_check(msg.substr(bsl::to_umax(0), bsl::to_umax(0)).empty());
                        bsl::ut_check(msg.substr(bsl::to_umax(0), bsl::to_umax(3)).empty());
                        bsl::ut_check(msg.substr(bsl::to_umax(0), bsl::npos).empty());
                        bsl::ut_check(msg.substr(bsl::to_umax(1), bsl::to_umax(0)).empty());
                        bsl::ut_check(msg.substr(bsl::to_umax(1), bsl::to_umax(3)).empty());
                        bsl::ut_check(msg.substr(bsl::to_umax(1), bsl::npos).empty());
                        bsl::ut_check(msg.substr(bsl::npos, bsl::to_umax(0)).empty());
                        bsl::ut_check(msg.substr(bsl::npos, bsl::to_umax(3)).empty());
                        bsl::ut_check(msg.substr(bsl::npos, bsl::npos).empty());
                        bsl::ut_check(
                            msg.substr(bsl::safe_uintmax::zero(true), bsl::safe_uintmax::zero(true))
                                .empty());
                    };
                };
            };

            bsl::ut_given{} = []() {
                bsl::basic_string_view<bsl::char_type> msg{"Hello World"};
                bsl::ut_when{} = [&msg]() {
                    bsl::ut_then{} = [&msg]() {
                        bsl::ut_check(msg.substr(bsl::to_umax(0), bsl::to_umax(0)).empty());
                        bsl::ut_check(msg.substr(bsl::to_umax(0), bsl::to_umax(3)) == "Hel");
                        bsl::ut_check(msg.substr(bsl::to_umax(0), bsl::npos) == "Hello World");
                        bsl::ut_check(msg.substr(bsl::to_umax(1), bsl::to_umax(0)).empty());
                        bsl::ut_check(msg.substr(bsl::to_umax(1), bsl::to_umax(3)) == "ell");
                        bsl::ut_check(msg.substr(bsl::to_umax(1), bsl::npos) == "ello World");
                        bsl::ut_check(msg.substr(bsl::npos, bsl::to_umax(0)).empty());
                        bsl::ut_check(msg.substr(bsl::npos, bsl::to_umax(3)).empty());
                        bsl::ut_check(msg.substr(bsl::npos, bsl::npos).empty());
                        bsl::ut_check(
                            msg.substr(bsl::safe_uintmax::zero(true), bsl::safe_uintmax::zero(true))
                                .empty());
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
