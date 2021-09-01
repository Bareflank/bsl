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
            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{};
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

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{"", bsl::to_umx(0)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(msg.empty());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{"Hello", bsl::to_umx(0)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(msg.empty());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{"Hello", bsl::to_umx(5)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(msg == "Hello");
                };
            };
        };

        bsl::ut_scenario{"assignmen t"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
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
            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> mut_msg{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(nullptr == mut_msg.at_if(bsl::to_idx(0)));
                    bsl::ut_check(nullptr == mut_msg.at_if(bsl::npos));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(nullptr == msg.at_if(bsl::to_idx(0)));
                    bsl::ut_check(nullptr == msg.at_if(bsl::npos));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> mut_msg{"Hello"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check('H' == *mut_msg.at_if(bsl::to_idx(0)));
                    bsl::ut_check('e' == *mut_msg.at_if(bsl::to_idx(1)));
                    bsl::ut_check('l' == *mut_msg.at_if(bsl::to_idx(2)));
                    bsl::ut_check('l' == *mut_msg.at_if(bsl::to_idx(3)));
                    bsl::ut_check('o' == *mut_msg.at_if(bsl::to_idx(4)));
                    bsl::ut_check(nullptr == mut_msg.at_if(bsl::to_idx(5)));
                    bsl::ut_check(nullptr == mut_msg.at_if(bsl::npos));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check('H' == *msg.at_if(bsl::to_idx(0)));
                    bsl::ut_check('e' == *msg.at_if(bsl::to_idx(1)));
                    bsl::ut_check('l' == *msg.at_if(bsl::to_idx(2)));
                    bsl::ut_check('l' == *msg.at_if(bsl::to_idx(3)));
                    bsl::ut_check('o' == *msg.at_if(bsl::to_idx(4)));
                    bsl::ut_check(nullptr == msg.at_if(bsl::to_idx(5)));
                    bsl::ut_check(nullptr == msg.at_if(bsl::npos));
                };
            };
        };

        bsl::ut_scenario{"front_if"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> mut_msg{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(nullptr == mut_msg.front_if());
                };
            };

            bsl::ut_given{} = []() noexcept {
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
            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> mut_msg{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(nullptr == mut_msg.back_if());
                };
            };

            bsl::ut_given{} = []() noexcept {
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
            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> mut_msg{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(nullptr == mut_msg.data());
                };
            };

            bsl::ut_given{} = []() noexcept {
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
            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> mut_msg{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(nullptr == mut_msg.begin().get_if());
                    bsl::ut_check(bsl::to_umx(0) == mut_msg.begin().index());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(nullptr == msg.begin().get_if());
                    bsl::ut_check(bsl::to_umx(0) == msg.begin().index());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(nullptr == msg.cbegin().get_if());
                    bsl::ut_check(bsl::to_umx(0) == msg.cbegin().index());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> mut_msg{"Hello"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check('H' == *(mut_msg.begin().get_if()));
                    bsl::ut_check(bsl::to_umx(0) == mut_msg.begin().index());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check('H' == *(msg.begin().get_if()));
                    bsl::ut_check(bsl::to_umx(0) == msg.begin().index());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check('H' == *(msg.cbegin().get_if()));
                    bsl::ut_check(bsl::to_umx(0) == msg.cbegin().index());
                };
            };
        };

        bsl::ut_scenario{"end"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> mut_msg{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(nullptr == mut_msg.end().get_if());
                    bsl::ut_check(mut_msg.size() == mut_msg.end().index());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(nullptr == msg.end().get_if());
                    bsl::ut_check(msg.size() == msg.end().index());
                };
            };

            bsl::ut_given{} = []() noexcept {
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
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(msg.size() == msg.end().index());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(msg.size() == msg.cend().index());
                };
            };
        };

        bsl::ut_scenario{"rbegin"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> mut_msg{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(nullptr == mut_msg.rbegin().get_if());
                    bsl::ut_check(bsl::to_umx(0) == mut_msg.rbegin().index());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(nullptr == msg.rbegin().get_if());
                    bsl::ut_check(bsl::to_umx(0) == msg.rbegin().index());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(nullptr == msg.crbegin().get_if());
                    bsl::ut_check(bsl::to_umx(0) == msg.crbegin().index());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> mut_msg{"Hello"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check('o' == *(mut_msg.rbegin().get_if()));
                    bsl::ut_check(bsl::to_umx(4) == mut_msg.rbegin().index());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check('o' == *(msg.rbegin().get_if()));
                    bsl::ut_check(bsl::to_umx(4) == msg.rbegin().index());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check('o' == *(msg.crbegin().get_if()));
                    bsl::ut_check(bsl::to_umx(4) == msg.crbegin().index());
                };
            };
        };

        bsl::ut_scenario{"rend"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> mut_msg{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(nullptr == mut_msg.rend().get_if());
                    bsl::ut_check(mut_msg.size() == mut_msg.rend().index());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(nullptr == msg.rend().get_if());
                    bsl::ut_check(msg.size() == msg.rend().index());
                };
            };

            bsl::ut_given{} = []() noexcept {
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
            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> mut_msg{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_msg.empty());
                };
            };

            bsl::ut_given{} = []() noexcept {
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

        bsl::ut_scenario{"is_invalid"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> mut_msg{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_msg.is_invalid());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(msg.is_invalid());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> mut_msg{"Hello"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!mut_msg.is_invalid());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!msg.is_invalid());
                };
            };
        };

        bsl::ut_scenario{"is_valid"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> mut_msg{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!mut_msg.is_valid());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!msg.is_valid());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> mut_msg{"Hello"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_msg.is_valid());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(msg.is_valid());
                };
            };
        };

        bsl::ut_scenario{"size"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> mut_msg{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_msg.size() == bsl::to_umx(0));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(msg.size() == bsl::to_umx(0));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> mut_msg{"Hello"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_msg.size() == bsl::to_umx(5));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(msg.size() == bsl::to_umx(5));
                };
            };
        };

        bsl::ut_scenario{"length"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> mut_msg{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(bsl::to_umx(0) == mut_msg.length());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(bsl::to_umx(0) == msg.length());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> mut_msg{"Hello"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_msg.length() == bsl::to_umx(5));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(msg.length() == bsl::to_umx(5));
                };
            };
        };

        bsl::ut_scenario{"max_size"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> mut_msg{};
                bsl::ut_then{} = [&]() noexcept {
                    constexpr auto expected{bsl::safe_umx::max_value() / sizeof(bsl::char_type)};
                    bsl::ut_check(mut_msg.max_size() == expected.checked());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{};
                bsl::ut_then{} = [&]() noexcept {
                    constexpr auto expected{bsl::safe_umx::max_value() / sizeof(bsl::char_type)};
                    bsl::ut_check(msg.max_size() == expected.checked());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> mut_msg{"Hello"};
                bsl::ut_then{} = [&]() noexcept {
                    constexpr auto expected{bsl::safe_umx::max_value() / sizeof(bsl::char_type)};
                    bsl::ut_check(mut_msg.max_size() == expected.checked());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
                bsl::ut_then{} = [&]() noexcept {
                    constexpr auto expected{bsl::safe_umx::max_value() / sizeof(bsl::char_type)};
                    bsl::ut_check(msg.max_size() == expected.checked());
                };
            };
        };

        bsl::ut_scenario{"size_bytes"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> mut_msg{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(bsl::to_umx(0) == mut_msg.size_bytes());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(bsl::to_umx(0) == msg.size_bytes());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> mut_msg{"Hello"};
                bsl::ut_then{} = [&]() noexcept {
                    constexpr auto expected{bsl::to_umx(5) * sizeof(bsl::char_type)};
                    bsl::ut_check(mut_msg.size_bytes() == expected.checked());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{"Hello"};
                bsl::ut_then{} = [&]() noexcept {
                    constexpr auto expected{bsl::to_umx(5) * sizeof(bsl::char_type)};
                    bsl::ut_check(msg.size_bytes() == expected.checked());
                };
            };
        };

        bsl::ut_scenario{"remove_prefix"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> mut_msg{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_msg.remove_prefix(bsl::to_idx(0));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_msg.empty());
                    };
                };
            };

            bsl::ut_given{} = []() noexcept {
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
                    mut_msg.remove_prefix(bsl::to_idx(0));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_msg == "Hello World");
                    };
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> mut_msg{"Hello World"};
                bsl::ut_when{} = [&]() noexcept {
                    mut_msg.remove_prefix(bsl::to_idx(6));
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
        };

        bsl::ut_scenario{"remove_suffix"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> mut_msg{};
                bsl::ut_when{} = [&]() noexcept {
                    mut_msg.remove_suffix(bsl::to_idx(0));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_msg.empty());
                    };
                };
            };

            bsl::ut_given{} = []() noexcept {
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
                    mut_msg.remove_suffix(bsl::to_idx(0));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_msg == "Hello World");
                    };
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> mut_msg{"Hello World"};
                bsl::ut_when{} = [&]() noexcept {
                    mut_msg.remove_suffix(bsl::to_idx(6));
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
        };

        bsl::ut_scenario{"substr"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(msg.substr(bsl::to_idx(0), bsl::to_umx(0)).empty());
                        bsl::ut_check(msg.substr(bsl::to_idx(0), bsl::to_umx(3)).empty());
                        bsl::ut_check(msg.substr(bsl::to_idx(0), bsl::safe_umx::max_value()).empty());
                        bsl::ut_check(msg.substr(bsl::to_idx(1), bsl::to_umx(0)).empty());
                        bsl::ut_check(msg.substr(bsl::to_idx(1), bsl::to_umx(3)).empty());
                        bsl::ut_check(msg.substr(bsl::to_idx(1), bsl::safe_umx::max_value()).empty());
                        bsl::ut_check(msg.substr(bsl::npos, bsl::to_umx(0)).empty());
                        bsl::ut_check(msg.substr(bsl::npos, bsl::to_umx(3)).empty());
                        bsl::ut_check(msg.substr(bsl::npos, bsl::safe_umx::max_value()).empty());
                    };
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg{"Hello World"};
                bsl::ut_when{} = [&]() noexcept {
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(msg.substr(bsl::to_idx(0), bsl::to_umx(0)).empty());
                        bsl::ut_check(msg.substr(bsl::to_idx(0), bsl::to_umx(3)) == "Hel");
                        bsl::ut_check(msg.substr(bsl::to_idx(0), bsl::safe_umx::max_value()) == "Hello World");
                        bsl::ut_check(msg.substr(bsl::to_idx(1), bsl::to_umx(0)).empty());
                        bsl::ut_check(msg.substr(bsl::to_idx(1), bsl::to_umx(3)) == "ell");
                        bsl::ut_check(msg.substr(bsl::to_idx(1), bsl::safe_umx::max_value()) == "ello World");
                        bsl::ut_check(msg.substr(bsl::npos, bsl::to_umx(0)).empty());
                        bsl::ut_check(msg.substr(bsl::npos, bsl::to_umx(3)).empty());
                        bsl::ut_check(msg.substr(bsl::npos, bsl::safe_umx::max_value()).empty());
                    };
                };
            };
        };

        bsl::ut_scenario{"equals"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg0{};
                bsl::basic_string_view<bsl::char_type> const msg1{};
                bsl::basic_string_view<bsl::char_type> const msg2{""};
                bsl::basic_string_view<bsl::char_type> const msg3{""};
                bsl::basic_string_view<bsl::char_type> const msg4{"h"};
                bsl::basic_string_view<bsl::char_type> const msg5{"h"};
                bsl::basic_string_view<bsl::char_type> const msg6{"hello"};
                bsl::basic_string_view<bsl::char_type> const msg7{"hello"};
                bsl::basic_string_view<bsl::char_type> const msg8{"w"};
                bsl::basic_string_view<bsl::char_type> const msg9{"help"};
                bsl::basic_string_view<bsl::char_type> const msga{"helps"};
                bsl::ut_then{"same length, same contents"} = [&]() noexcept {
                    bsl::ut_check(msg0.equals(msg1));
                    bsl::ut_check(msg2.equals(msg3));
                    bsl::ut_check(msg4.equals(msg5));
                    bsl::ut_check(msg6.equals(msg7));
                };

                bsl::ut_then{"same length, different contents"} = [&]() noexcept {
                    bsl::ut_check(!msg4.equals(msg8));
                    bsl::ut_check(!msg8.equals(msg4));
                    bsl::ut_check(!msg6.equals(msga));
                    bsl::ut_check(!msga.equals(msg6));
                };

                bsl::ut_then{"invalid with anything"} = [&]() noexcept {
                    bsl::ut_check(msg0.equals(msg2));
                    bsl::ut_check(msg0.equals(msg4));
                    bsl::ut_check(msg0.equals(msg6));
                    bsl::ut_check(msg2.equals(msg0));
                    bsl::ut_check(msg4.equals(msg0));
                    bsl::ut_check(msg6.equals(msg0));
                };

                bsl::ut_then{"empty with anything"} = [&]() noexcept {
                    bsl::ut_check(msg2.equals(msg0));
                    bsl::ut_check(msg2.equals(msg4));
                    bsl::ut_check(msg2.equals(msg6));
                    bsl::ut_check(msg0.equals(msg2));
                    bsl::ut_check(msg4.equals(msg2));
                    bsl::ut_check(msg6.equals(msg2));
                };

                bsl::ut_then{"same contents, different lengths"} = [&]() noexcept {
                    bsl::ut_check(msg4.equals(msg6));
                    bsl::ut_check(msg6.equals(msg4));
                };

                bsl::ut_then{"different contents and lengths"} = [&]() noexcept {
                    bsl::ut_check(!msg4.equals(msg8));
                    bsl::ut_check(!msg6.equals(msg8));
                    bsl::ut_check(!msg8.equals(msg4));
                    bsl::ut_check(!msg8.equals(msg6));
                };

                bsl::ut_then{"different contents and lengths but close"} = [&]() noexcept {
                    bsl::ut_check(msg4.equals(msg9));
                    bsl::ut_check(!msg6.equals(msg9));
                    bsl::ut_check(msg9.equals(msg4));
                    bsl::ut_check(!msg9.equals(msg6));
                };
            };
        };

        bsl::ut_scenario{"substr equals"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg0{};
                bsl::basic_string_view<bsl::char_type> const msg1{};
                bsl::basic_string_view<bsl::char_type> const msg2{""};
                bsl::basic_string_view<bsl::char_type> const msg3{""};
                bsl::basic_string_view<bsl::char_type> const msg4{"h"};
                bsl::basic_string_view<bsl::char_type> const msg5{"h"};
                bsl::basic_string_view<bsl::char_type> const msg6{"hello"};
                bsl::basic_string_view<bsl::char_type> const msg7{"hello"};
                bsl::basic_string_view<bsl::char_type> const msg8{"w"};
                bsl::basic_string_view<bsl::char_type> const msg9{"help"};
                bsl::basic_string_view<bsl::char_type> const msga{"helps"};
                bsl::ut_then{"same length, same contents"} = [&]() noexcept {
                    bsl::ut_check(msg0.equals({}, bsl::safe_umx::max_value(), msg1));
                    bsl::ut_check(msg2.equals({}, bsl::safe_umx::max_value(), msg3));
                    bsl::ut_check(msg4.equals({}, bsl::safe_umx::max_value(), msg5));
                    bsl::ut_check(msg6.equals({}, bsl::safe_umx::max_value(), msg7));
                };

                bsl::ut_then{"same length, different contents"} = [&]() noexcept {
                    bsl::ut_check(!msg4.equals({}, bsl::safe_umx::max_value(), msg8));
                    bsl::ut_check(!msg8.equals({}, bsl::safe_umx::max_value(), msg4));
                    bsl::ut_check(!msg6.equals({}, bsl::safe_umx::max_value(), msga));
                    bsl::ut_check(!msga.equals({}, bsl::safe_umx::max_value(), msg6));
                };

                bsl::ut_then{"invalid with anything"} = [&]() noexcept {
                    bsl::ut_check(msg0.equals({}, bsl::safe_umx::max_value(), msg2));
                    bsl::ut_check(msg0.equals({}, bsl::safe_umx::max_value(), msg4));
                    bsl::ut_check(msg0.equals({}, bsl::safe_umx::max_value(), msg6));
                    bsl::ut_check(msg2.equals({}, bsl::safe_umx::max_value(), msg0));
                    bsl::ut_check(msg4.equals({}, bsl::safe_umx::max_value(), msg0));
                    bsl::ut_check(msg6.equals({}, bsl::safe_umx::max_value(), msg0));
                };

                bsl::ut_then{"empty with anything"} = [&]() noexcept {
                    bsl::ut_check(msg2.equals({}, bsl::safe_umx::max_value(), msg0));
                    bsl::ut_check(msg2.equals({}, bsl::safe_umx::max_value(), msg4));
                    bsl::ut_check(msg2.equals({}, bsl::safe_umx::max_value(), msg6));
                    bsl::ut_check(msg0.equals({}, bsl::safe_umx::max_value(), msg2));
                    bsl::ut_check(msg4.equals({}, bsl::safe_umx::max_value(), msg2));
                    bsl::ut_check(msg6.equals({}, bsl::safe_umx::max_value(), msg2));
                };

                bsl::ut_then{"same contents, different lengths"} = [&]() noexcept {
                    bsl::ut_check(msg4.equals({}, bsl::safe_umx::max_value(), msg6));
                    bsl::ut_check(msg6.equals({}, bsl::safe_umx::max_value(), msg4));
                };

                bsl::ut_then{"different contents and lengths"} = [&]() noexcept {
                    bsl::ut_check(!msg4.equals({}, bsl::safe_umx::max_value(), msg8));
                    bsl::ut_check(!msg6.equals({}, bsl::safe_umx::max_value(), msg8));
                    bsl::ut_check(!msg8.equals({}, bsl::safe_umx::max_value(), msg4));
                    bsl::ut_check(!msg8.equals({}, bsl::safe_umx::max_value(), msg6));
                };

                bsl::ut_then{"different contents and lengths but close"} = [&]() noexcept {
                    bsl::ut_check(msg4.equals({}, bsl::safe_umx::max_value(), msg9));
                    bsl::ut_check(!msg6.equals({}, bsl::safe_umx::max_value(), msg9));
                    bsl::ut_check(msg9.equals({}, bsl::safe_umx::max_value(), msg4));
                    bsl::ut_check(!msg9.equals({}, bsl::safe_umx::max_value(), msg6));
                };

                bsl::ut_then{"pos = npos means str == empty, and all true"} = [&]() noexcept {
                    bsl::ut_check(msg0.equals(bsl::npos, bsl::safe_umx::max_value(), msg1));
                    bsl::ut_check(msg2.equals(bsl::npos, bsl::safe_umx::max_value(), msg3));
                    bsl::ut_check(msg4.equals(bsl::npos, bsl::safe_umx::max_value(), msg5));
                    bsl::ut_check(msg6.equals(bsl::npos, bsl::safe_umx::max_value(), msg7));
                };

                bsl::ut_then{"count = 0 means str == empty, and all true"} = [&]() noexcept {
                    bsl::ut_check(msg0.equals({}, {}, msg1));
                    bsl::ut_check(msg2.equals({}, {}, msg3));
                    bsl::ut_check(msg4.equals({}, {}, msg5));
                    bsl::ut_check(msg6.equals({}, {}, msg7));
                };

                bsl::ut_then{"substr with contents the same"} = [&]() noexcept {
                    bsl::ut_check(msg6.equals(bsl::safe_idx::magic_0(), bsl::safe_umx::magic_2(), msg7));
                };

                bsl::ut_then{"substr with contents different"} = [&]() noexcept {
                    bsl::ut_check(!msg6.equals(bsl::safe_idx::magic_1(), bsl::safe_umx::magic_2(), msg7));
                };
            };
        };

        bsl::ut_scenario{"equals with C-string"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg0{};
                bsl::basic_string_view<bsl::char_type> const msg2{""};
                bsl::cstr_type const msg3{""};
                bsl::basic_string_view<bsl::char_type> const msg4{"h"};
                bsl::cstr_type const msg5{"h"};
                bsl::basic_string_view<bsl::char_type> const msg6{"hello"};
                bsl::cstr_type const msg7{"hello"};
                bsl::cstr_type const msg8{"w"};
                bsl::cstr_type const msg9{"help"};
                bsl::cstr_type const msga{"helps"};
                bsl::ut_then{"same length, same contents"} = [&]() noexcept {
                    bsl::ut_check(msg2.equals(msg3));
                    bsl::ut_check(msg4.equals(msg5));
                    bsl::ut_check(msg6.equals(msg7));
                };

                bsl::ut_then{"same length, different contents"} = [&]() noexcept {
                    bsl::ut_check(!msg4.equals(msg8));
                    bsl::ut_check(!msg6.equals(msga));
                };

                bsl::ut_then{"invalid with anything"} = [&]() noexcept {
                    bsl::ut_check(msg0.equals(msg3));
                    bsl::ut_check(msg0.equals(msg5));
                };

                bsl::ut_then{"empty with anything"} = [&]() noexcept {
                    bsl::ut_check(msg2.equals(msg3));
                    bsl::ut_check(msg2.equals(msg5));
                };

                bsl::ut_then{"same contents, different lengths"} = [&]() noexcept {
                    bsl::ut_check(msg4.equals(msg7));
                };

                bsl::ut_then{"different contents and lengths"} = [&]() noexcept {
                    bsl::ut_check(!msg4.equals(msg8));
                    bsl::ut_check(!msg6.equals(msg8));
                };

                bsl::ut_then{"different contents and lengths but close"} = [&]() noexcept {
                    bsl::ut_check(msg4.equals(msg9));
                    bsl::ut_check(!msg6.equals(msg9));
                };
            };
        };

        bsl::ut_scenario{"comparison"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg0{};
                bsl::basic_string_view<bsl::char_type> const msg1{};
                bsl::basic_string_view<bsl::char_type> const msg2{""};
                bsl::basic_string_view<bsl::char_type> const msg3{""};
                bsl::basic_string_view<bsl::char_type> const msg4{"h"};
                bsl::basic_string_view<bsl::char_type> const msg5{"h"};
                bsl::basic_string_view<bsl::char_type> const msg6{"hello"};
                bsl::basic_string_view<bsl::char_type> const msg7{"hello"};
                bsl::basic_string_view<bsl::char_type> const msg8{"w"};
                bsl::basic_string_view<bsl::char_type> const msg9{"help"};
                bsl::basic_string_view<bsl::char_type> const msga{"helps"};
                bsl::ut_then{"same length, same contents"} = [&]() noexcept {
                    bsl::ut_check(msg0 == msg1);
                    bsl::ut_check(msg2 == msg3);
                    bsl::ut_check(msg4 == msg5);
                    bsl::ut_check(msg6 == msg7);
                };

                bsl::ut_then{"same length, different contents"} = [&]() noexcept {
                    bsl::ut_check(!msg4.equals(msg8));
                    bsl::ut_check(!msg8.equals(msg4));
                    bsl::ut_check(!msg6.equals(msga));
                    bsl::ut_check(!msga.equals(msg6));
                };

                bsl::ut_then{"invalid with anything"} = [&]() noexcept {
                    bsl::ut_check(msg0 == msg2);
                    bsl::ut_check(msg0 != msg4);
                    bsl::ut_check(msg0 != msg6);
                    bsl::ut_check(msg2 == msg0);
                    bsl::ut_check(msg4 != msg0);
                    bsl::ut_check(msg6 != msg0);
                };

                bsl::ut_then{"empty with anything"} = [&]() noexcept {
                    bsl::ut_check(msg2 == msg0);
                    bsl::ut_check(msg2 != msg4);
                    bsl::ut_check(msg2 != msg6);
                    bsl::ut_check(msg0 == msg2);
                    bsl::ut_check(msg4 != msg2);
                    bsl::ut_check(msg6 != msg2);
                };

                bsl::ut_then{"same contents, different lengths"} = [&]() noexcept {
                    bsl::ut_check(msg4 != msg6);
                    bsl::ut_check(msg6 != msg4);
                };

                bsl::ut_then{"different contents and lengths"} = [&]() noexcept {
                    bsl::ut_check(msg4 != msg8);
                    bsl::ut_check(msg6 != msg8);
                    bsl::ut_check(msg8 != msg4);
                    bsl::ut_check(msg8 != msg6);
                };

                bsl::ut_then{"different contents and lengths but close"} = [&]() noexcept {
                    bsl::ut_check(msg4 != msg9);
                    bsl::ut_check(msg6 != msg9);
                    bsl::ut_check(msg9 != msg4);
                    bsl::ut_check(msg9 != msg6);
                };
            };
        };

        bsl::ut_scenario{"comparison with C-string"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::basic_string_view<bsl::char_type> const msg0{};
                bsl::basic_string_view<bsl::char_type> const msg2{""};
                bsl::cstr_type const msg3{""};
                bsl::basic_string_view<bsl::char_type> const msg4{"h"};
                bsl::cstr_type const msg5{"h"};
                bsl::basic_string_view<bsl::char_type> const msg6{"hello"};
                bsl::cstr_type const msg7{"hello"};
                bsl::cstr_type const msg8{"w"};
                bsl::cstr_type const msg9{"help"};
                bsl::cstr_type const msga{"helps"};
                bsl::ut_then{"same length, same contents"} = [&]() noexcept {
                    bsl::ut_check(msg2 == msg3);
                    bsl::ut_check(msg4 == msg5);
                    bsl::ut_check(msg6 == msg7);
                    bsl::ut_check(msg3 == msg2);
                    bsl::ut_check(msg5 == msg4);
                    bsl::ut_check(msg7 == msg6);
                };

                bsl::ut_then{"same length, different contents"} = [&]() noexcept {
                    bsl::ut_check(msg4 != msg8);
                    bsl::ut_check(msg6 != msga);
                    bsl::ut_check(msg8 != msg4);
                    bsl::ut_check(msga != msg6);
                };

                bsl::ut_then{"invalid with anything"} = [&]() noexcept {
                    bsl::ut_check(msg0 == msg3);
                    bsl::ut_check(msg0 != msg5);
                    bsl::ut_check(msg3 == msg0);
                    bsl::ut_check(msg5 != msg0);
                };

                bsl::ut_then{"empty with anything"} = [&]() noexcept {
                    bsl::ut_check(msg2 == msg3);
                    bsl::ut_check(msg2 != msg5);
                    bsl::ut_check(msg3 == msg2);
                    bsl::ut_check(msg5 != msg2);
                };

                bsl::ut_then{"same contents, different lengths"} = [&]() noexcept {
                    bsl::ut_check(msg4 != msg7);
                    bsl::ut_check(msg7 != msg4);
                };

                bsl::ut_then{"different contents and lengths"} = [&]() noexcept {
                    bsl::ut_check(msg4 != msg8);
                    bsl::ut_check(msg6 != msg8);
                    bsl::ut_check(msg8 != msg4);
                    bsl::ut_check(msg8 != msg6);
                };

                bsl::ut_then{"different contents and lengths but close"} = [&]() noexcept {
                    bsl::ut_check(msg4 != msg9);
                    bsl::ut_check(msg6 != msg9);
                    bsl::ut_check(msg9 != msg4);
                    bsl::ut_check(msg9 != msg6);
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
