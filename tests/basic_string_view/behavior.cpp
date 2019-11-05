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
#include <bsl/cstr_type.hpp>
#include <bsl/numeric_limits.hpp>
#include <bsl/ut.hpp>

/// <!-- description -->
///   @brief Used to execute the actual checks. We put the checks in this
///     function so that we can validate the tests both at compile-time
///     and at run-time. If a bsl::ut_check fails, the tests will either
///     fail fast at run-time, or will produce a compile-time error.
///
/// <!-- inputs/outputs -->
///   @return Always returns bsl::exit_success.
///
constexpr bsl::exit_code
tests() noexcept
{
    constexpr bsl::uintmax max_size{bsl::numeric_limits<bsl::uintmax>::max()};

    bsl::ut_scenario{"at_if"} = []() {
        bsl::ut_given{} = []() {
            bsl::basic_string_view<bsl::char_type> msg{};
            bsl::ut_then{} = [&msg]() {
                bsl::ut_check(msg.at_if(0) == nullptr);
                bsl::ut_check(msg.at_if(max_size) == nullptr);
            };
        };

        bsl::ut_given{} = []() {
            bsl::basic_string_view<bsl::char_type> const msg{};
            bsl::ut_then{} = [&msg]() {
                bsl::ut_check(msg.at_if(0) == nullptr);
                bsl::ut_check(msg.at_if(max_size) == nullptr);
            };
        };

        bsl::ut_given{} = []() {
            bsl::basic_string_view<bsl::char_type> msg{"Hello"};
            bsl::ut_then{} = [&msg]() {
                bsl::ut_check(*msg.at_if(0) == 'H');
                bsl::ut_check(*msg.at_if(1) == 'e');
                bsl::ut_check(*msg.at_if(2) == 'l');
                bsl::ut_check(*msg.at_if(3) == 'l');
                bsl::ut_check(*msg.at_if(4) == 'o');
                bsl::ut_check(msg.at_if(5) == nullptr);
                bsl::ut_check(msg.at_if(max_size) == nullptr);
            };
        };

        bsl::ut_given{} = []() {
            bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
            bsl::ut_then{} = [&msg]() {
                bsl::ut_check(*msg.at_if(0) == 'H');
                bsl::ut_check(*msg.at_if(1) == 'e');
                bsl::ut_check(*msg.at_if(2) == 'l');
                bsl::ut_check(*msg.at_if(3) == 'l');
                bsl::ut_check(*msg.at_if(4) == 'o');
                bsl::ut_check(msg.at_if(5) == nullptr);
                bsl::ut_check(msg.at_if(max_size) == nullptr);
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
                bsl::ut_check(msg.begin().index() == 0);
            };
        };

        bsl::ut_given{} = []() {
            bsl::basic_string_view<bsl::char_type> const msg{};
            bsl::ut_then{} = [&msg]() {
                bsl::ut_check(msg.begin().get_if() == nullptr);
                bsl::ut_check(msg.begin().index() == 0);
            };
        };

        bsl::ut_given{} = []() {
            bsl::basic_string_view<bsl::char_type> const msg{};
            bsl::ut_then{} = [&msg]() {
                bsl::ut_check(msg.cbegin().get_if() == nullptr);
                bsl::ut_check(msg.cbegin().index() == 0);
            };
        };

        bsl::ut_given{} = []() {
            bsl::basic_string_view<bsl::char_type> msg{"Hello"};
            bsl::ut_then{} = [&msg]() {
                bsl::ut_check(*(msg.begin().get_if()) == 'H');
                bsl::ut_check(msg.begin().index() == 0);
            };
        };

        bsl::ut_given{} = []() {
            bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
            bsl::ut_then{} = [&msg]() {
                bsl::ut_check(*(msg.begin().get_if()) == 'H');
                bsl::ut_check(msg.begin().index() == 0);
            };
        };

        bsl::ut_given{} = []() {
            bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
            bsl::ut_then{} = [&msg]() {
                bsl::ut_check(*(msg.cbegin().get_if()) == 'H');
                bsl::ut_check(msg.cbegin().index() == 0);
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

    bsl::ut_scenario{"iter"} = []() {
        bsl::ut_given{} = []() {
            bsl::basic_string_view<bsl::char_type> msg{};
            bsl::ut_then{} = [&msg]() {
                bsl::ut_check(msg.iter(1).get_if() == nullptr);
                bsl::ut_check(msg.iter(1).index() == msg.size());
            };
        };

        bsl::ut_given{} = []() {
            bsl::basic_string_view<bsl::char_type> const msg{};
            bsl::ut_then{} = [&msg]() {
                bsl::ut_check(msg.iter(1).get_if() == nullptr);
                bsl::ut_check(msg.iter(1).index() == msg.size());
            };
        };

        bsl::ut_given{} = []() {
            bsl::basic_string_view<bsl::char_type> const msg{};
            bsl::ut_then{} = [&msg]() {
                bsl::ut_check(msg.citer(1).get_if() == nullptr);
                bsl::ut_check(msg.citer(1).index() == msg.size());
            };
        };

        bsl::ut_given{} = []() {
            bsl::basic_string_view<bsl::char_type> msg{"Hello"};
            bsl::ut_then{} = [&msg]() {
                bsl::ut_check(*(msg.iter(1).get_if()) == 'e');
                bsl::ut_check(msg.iter(1).index() == 1);
            };
        };

        bsl::ut_given{} = []() {
            bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
            bsl::ut_then{} = [&msg]() {
                bsl::ut_check(*(msg.iter(1).get_if()) == 'e');
                bsl::ut_check(msg.iter(1).index() == 1);
            };
        };

        bsl::ut_given{} = []() {
            bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
            bsl::ut_then{} = [&msg]() {
                bsl::ut_check(*(msg.citer(1).get_if()) == 'e');
                bsl::ut_check(msg.citer(1).index() == 1);
            };
        };
    };

    bsl::ut_scenario{"rbegin"} = []() {
        bsl::ut_given{} = []() {
            bsl::basic_string_view<bsl::char_type> msg{};
            bsl::ut_then{} = [&msg]() {
                bsl::ut_check(msg.rbegin().get_if() == nullptr);
                bsl::ut_check(msg.rbegin().index() == 0);
            };
        };

        bsl::ut_given{} = []() {
            bsl::basic_string_view<bsl::char_type> const msg{};
            bsl::ut_then{} = [&msg]() {
                bsl::ut_check(msg.rbegin().get_if() == nullptr);
                bsl::ut_check(msg.rbegin().index() == 0);
            };
        };

        bsl::ut_given{} = []() {
            bsl::basic_string_view<bsl::char_type> const msg{};
            bsl::ut_then{} = [&msg]() {
                bsl::ut_check(msg.crbegin().get_if() == nullptr);
                bsl::ut_check(msg.crbegin().index() == 0);
            };
        };

        bsl::ut_given{} = []() {
            bsl::basic_string_view<bsl::char_type> msg{"Hello"};
            bsl::ut_then{} = [&msg]() {
                bsl::ut_check(*(msg.rbegin().get_if()) == 'o');
                bsl::ut_check(msg.rbegin().index() == 4);
            };
        };

        bsl::ut_given{} = []() {
            bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
            bsl::ut_then{} = [&msg]() {
                bsl::ut_check(*(msg.rbegin().get_if()) == 'o');
                bsl::ut_check(msg.rbegin().index() == 4);
            };
        };

        bsl::ut_given{} = []() {
            bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
            bsl::ut_then{} = [&msg]() {
                bsl::ut_check(*(msg.crbegin().get_if()) == 'o');
                bsl::ut_check(msg.crbegin().index() == 4);
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

    bsl::ut_scenario{"riter"} = []() {
        bsl::ut_given{} = []() {
            bsl::basic_string_view<bsl::char_type> msg{};
            bsl::ut_then{} = [&msg]() {
                bsl::ut_check(msg.riter(1).get_if() == nullptr);
                bsl::ut_check(msg.riter(1).index() == msg.size());
            };
        };

        bsl::ut_given{} = []() {
            bsl::basic_string_view<bsl::char_type> const msg{};
            bsl::ut_then{} = [&msg]() {
                bsl::ut_check(msg.riter(1).get_if() == nullptr);
                bsl::ut_check(msg.riter(1).index() == msg.size());
            };
        };

        bsl::ut_given{} = []() {
            bsl::basic_string_view<bsl::char_type> const msg{};
            bsl::ut_then{} = [&msg]() {
                bsl::ut_check(msg.criter(1).get_if() == nullptr);
                bsl::ut_check(msg.criter(1).index() == msg.size());
            };
        };

        bsl::ut_given{} = []() {
            bsl::basic_string_view<bsl::char_type> msg{"Hello"};
            bsl::ut_then{} = [&msg]() {
                bsl::ut_check(*(msg.riter(1).get_if()) == 'e');
                bsl::ut_check(msg.riter(1).index() == 1);
            };
        };

        bsl::ut_given{} = []() {
            bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
            bsl::ut_then{} = [&msg]() {
                bsl::ut_check(*(msg.riter(1).get_if()) == 'e');
                bsl::ut_check(msg.riter(1).index() == 1);
            };
        };

        bsl::ut_given{} = []() {
            bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
            bsl::ut_then{} = [&msg]() {
                bsl::ut_check(*(msg.criter(1).get_if()) == 'e');
                bsl::ut_check(msg.criter(1).index() == 1);
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

    bsl::ut_scenario{"size"} = []() {
        bsl::ut_given{} = []() {
            bsl::basic_string_view<bsl::char_type> msg{};
            bsl::ut_then{} = [&msg]() {
                bsl::ut_check(msg.size() == 0);    // NOLINT
            };
        };

        bsl::ut_given{} = []() {
            bsl::basic_string_view<bsl::char_type> const msg{};
            bsl::ut_then{} = [&msg]() {
                bsl::ut_check(msg.size() == 0);    // NOLINT
            };
        };

        bsl::ut_given{} = []() {
            bsl::basic_string_view<bsl::char_type> msg{"Hello"};
            bsl::ut_then{} = [&msg]() {
                bsl::ut_check(msg.size() == 5);
            };
        };

        bsl::ut_given{} = []() {
            bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
            bsl::ut_then{} = [&msg]() {
                bsl::ut_check(msg.size() == 5);
            };
        };
    };

    bsl::ut_scenario{"length"} = []() {
        bsl::ut_given{} = []() {
            bsl::basic_string_view<bsl::char_type> msg{};
            bsl::ut_then{} = [&msg]() {
                bsl::ut_check(msg.length() == 0);
            };
        };

        bsl::ut_given{} = []() {
            bsl::basic_string_view<bsl::char_type> const msg{};
            bsl::ut_then{} = [&msg]() {
                bsl::ut_check(msg.length() == 0);
            };
        };

        bsl::ut_given{} = []() {
            bsl::basic_string_view<bsl::char_type> msg{"Hello"};
            bsl::ut_then{} = [&msg]() {
                bsl::ut_check(msg.length() == 5);
            };
        };

        bsl::ut_given{} = []() {
            bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
            bsl::ut_then{} = [&msg]() {
                bsl::ut_check(msg.length() == 5);
            };
        };
    };

    bsl::ut_scenario{"max_size"} = []() {
        bsl::ut_given{} = []() {
            bsl::basic_string_view<bsl::char_type> msg{};
            bsl::ut_then{} = [&msg]() {
                bsl::ut_check(msg.max_size() == max_size / sizeof(bsl::char_type));
            };
        };

        bsl::ut_given{} = []() {
            bsl::basic_string_view<bsl::char_type> const msg{};
            bsl::ut_then{} = [&msg]() {
                bsl::ut_check(msg.max_size() == max_size / sizeof(bsl::char_type));
            };
        };

        bsl::ut_given{} = []() {
            bsl::basic_string_view<bsl::char_type> msg{"Hello"};
            bsl::ut_then{} = [&msg]() {
                bsl::ut_check(msg.max_size() == max_size / sizeof(bsl::char_type));
            };
        };

        bsl::ut_given{} = []() {
            bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
            bsl::ut_then{} = [&msg]() {
                bsl::ut_check(msg.max_size() == max_size / sizeof(bsl::char_type));
            };
        };
    };

    bsl::ut_scenario{"size_bytes"} = []() {
        bsl::ut_given{} = []() {
            bsl::basic_string_view<bsl::char_type> msg{};
            bsl::ut_then{} = [&msg]() {
                bsl::ut_check(msg.size_bytes() == 0);
            };
        };

        bsl::ut_given{} = []() {
            bsl::basic_string_view<bsl::char_type> const msg{};
            bsl::ut_then{} = [&msg]() {
                bsl::ut_check(msg.size_bytes() == 0);
            };
        };

        bsl::ut_given{} = []() {
            bsl::basic_string_view<bsl::char_type> msg{"Hello"};
            bsl::ut_then{} = [&msg]() {
                bsl::ut_check(msg.size_bytes() == 5 * sizeof(bsl::char_type));
            };
        };

        bsl::ut_given{} = []() {
            bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
            bsl::ut_then{} = [&msg]() {
                bsl::ut_check(msg.size_bytes() == 5 * sizeof(bsl::char_type));
            };
        };
    };

    bsl::ut_scenario{"remove_prefix"} = []() {
        bsl::ut_given{} = []() {
            bsl::basic_string_view<bsl::char_type> msg{};
            bsl::ut_when{} = [&msg]() {
                msg.remove_prefix(0);
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
                msg.remove_prefix(0);
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(msg == "Hello World");
                };
            };
        };

        bsl::ut_given{} = []() {
            bsl::basic_string_view<bsl::char_type> msg{"Hello World"};
            bsl::ut_when{} = [&msg]() {
                msg.remove_prefix(6);
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
                msg.remove_suffix(0);
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
                msg.remove_suffix(0);
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(msg == "Hello World");
                };
            };
        };

        bsl::ut_given{} = []() {
            bsl::basic_string_view<bsl::char_type> msg{"Hello World"};
            bsl::ut_when{} = [&msg]() {
                msg.remove_suffix(6);
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
                    bsl::ut_check(msg.substr(0, 0).empty());
                    bsl::ut_check(msg.substr(0, 3).empty());
                    bsl::ut_check(msg.substr(0, bsl::npos).empty());
                    bsl::ut_check(msg.substr(1, 0).empty());
                    bsl::ut_check(msg.substr(1, 3).empty());
                    bsl::ut_check(msg.substr(1, bsl::npos).empty());
                    bsl::ut_check(msg.substr(bsl::npos, 0).empty());
                    bsl::ut_check(msg.substr(bsl::npos, 3).empty());
                    bsl::ut_check(msg.substr(bsl::npos, bsl::npos).empty());
                };
            };
        };

        bsl::ut_given{} = []() {
            bsl::basic_string_view<bsl::char_type> msg{"Hello World"};
            bsl::ut_when{} = [&msg]() {
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(msg.substr(0, 0).empty());
                    bsl::ut_check(msg.substr(0, 3) == "Hel");
                    bsl::ut_check(msg.substr(0, bsl::npos) == "Hello World");
                    bsl::ut_check(msg.substr(1, 0).empty());
                    bsl::ut_check(msg.substr(1, 3) == "ell");
                    bsl::ut_check(msg.substr(1, bsl::npos) == "ello World");
                    bsl::ut_check(msg.substr(bsl::npos, 0).empty());
                    bsl::ut_check(msg.substr(bsl::npos, 3).empty());
                    bsl::ut_check(msg.substr(bsl::npos, bsl::npos).empty());
                };
            };
        };
    };

    return bsl::ut_success();
}

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
    static_assert(tests() == bsl::ut_success());
    return tests();
}
