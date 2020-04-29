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

#include <bsl/fmt_options.hpp>
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
    bsl::ut_scenario{"empty"} = []() {
        bsl::ut_given{} = []() {
            bsl::fmt_options ops{""};
            bsl::ut_then{} = [&ops]() {
                bsl::ut_check(ops.fill() == ' ');
                bsl::ut_check(ops.align() == bsl::fmt_align::fmt_align_default);
                bsl::ut_check(ops.sign() == bsl::fmt_sign::fmt_sign_neg_only);
                bsl::ut_check(!ops.alternate_form());
                bsl::ut_check(!ops.sign_aware());
                bsl::ut_check(ops.width() == bsl::to_umax(0));
                bsl::ut_check(ops.type() == bsl::fmt_type::fmt_type_default);
            };
        };
    };

    bsl::ut_scenario{"all fields"} = []() {
        bsl::ut_given{} = []() {
            bsl::fmt_options ops{"#<+#010d"};
            bsl::ut_then{} = [&ops]() {
                bsl::ut_check(ops.fill() == '#');
                bsl::ut_check(ops.align() == bsl::fmt_align::fmt_align_left);
                bsl::ut_check(ops.sign() == bsl::fmt_sign::fmt_sign_pos_neg);
                bsl::ut_check(ops.alternate_form());
                bsl::ut_check(ops.sign_aware());
                bsl::ut_check(ops.width() == bsl::to_umax(10));
                bsl::ut_check(ops.type() == bsl::fmt_type::fmt_type_d);
            };
        };

        bsl::ut_given{} = []() {
            bsl::fmt_options ops{"#<+#010dHello World"};
            bsl::ut_then{} = [&ops]() {
                bsl::ut_check(ops.fill() == '#');
                bsl::ut_check(ops.align() == bsl::fmt_align::fmt_align_left);
                bsl::ut_check(ops.sign() == bsl::fmt_sign::fmt_sign_pos_neg);
                bsl::ut_check(ops.alternate_form());
                bsl::ut_check(ops.sign_aware());
                bsl::ut_check(ops.width() == bsl::to_umax(10));
                bsl::ut_check(ops.type() == bsl::fmt_type::fmt_type_d);
            };
        };
    };

    bsl::ut_scenario{"fill-and-align"} = []() {
        bsl::ut_given{} = []() {
            bsl::fmt_options ops{"<"};
            bsl::ut_then{} = [&ops]() {
                bsl::ut_check(ops.fill() == ' ');
                bsl::ut_check(ops.align() == bsl::fmt_align::fmt_align_left);
            };
        };

        bsl::ut_given{} = []() {
            bsl::fmt_options ops{">"};
            bsl::ut_then{} = [&ops]() {
                bsl::ut_check(ops.fill() == ' ');
                bsl::ut_check(ops.align() == bsl::fmt_align::fmt_align_right);
            };
        };

        bsl::ut_given{} = []() {
            bsl::fmt_options ops{"^"};
            bsl::ut_then{} = [&ops]() {
                bsl::ut_check(ops.fill() == ' ');
                bsl::ut_check(ops.align() == bsl::fmt_align::fmt_align_center);
            };
        };

        bsl::ut_given{} = []() {
            bsl::fmt_options ops{"#<"};
            bsl::ut_then{} = [&ops]() {
                bsl::ut_check(ops.fill() == '#');
                bsl::ut_check(ops.align() == bsl::fmt_align::fmt_align_left);
            };
        };

        bsl::ut_given{} = []() {
            bsl::fmt_options ops{"#>"};
            bsl::ut_then{} = [&ops]() {
                bsl::ut_check(ops.fill() == '#');
                bsl::ut_check(ops.align() == bsl::fmt_align::fmt_align_right);
            };
        };

        bsl::ut_given{} = []() {
            bsl::fmt_options ops{"#^"};
            bsl::ut_then{} = [&ops]() {
                bsl::ut_check(ops.fill() == '#');
                bsl::ut_check(ops.align() == bsl::fmt_align::fmt_align_center);
            };
        };

        bsl::ut_given{} = []() {
            bsl::fmt_options ops{"H"};
            bsl::ut_then{} = [&ops]() {
                bsl::ut_check(ops.fill() == ' ');
                bsl::ut_check(ops.align() == bsl::fmt_align::fmt_align_default);
            };
        };

        bsl::ut_given{} = []() {
            bsl::fmt_options ops{"Hello World"};
            bsl::ut_then{} = [&ops]() {
                bsl::ut_check(ops.fill() == ' ');
                bsl::ut_check(ops.align() == bsl::fmt_align::fmt_align_default);
            };
        };

        bsl::ut_given{} = []() {
            bsl::fmt_options ops{""};
            bsl::ut_when{} = [&ops]() {
                ops.set_fill('#');
                ops.set_align(bsl::fmt_align::fmt_align_left);
                bsl::ut_then{} = [&ops]() {
                    bsl::ut_check(ops.fill() == '#');
                    bsl::ut_check(ops.align() == bsl::fmt_align::fmt_align_left);
                };
            };
        };
    };

    bsl::ut_scenario{"sign"} = []() {
        bsl::ut_given{} = []() {
            bsl::fmt_options ops{"+"};
            bsl::ut_then{} = [&ops]() {
                bsl::ut_check(ops.sign() == bsl::fmt_sign::fmt_sign_pos_neg);
            };
        };

        bsl::ut_given{} = []() {
            bsl::fmt_options ops{"-"};
            bsl::ut_then{} = [&ops]() {
                bsl::ut_check(ops.sign() == bsl::fmt_sign::fmt_sign_neg_only);
            };
        };

        bsl::ut_given{} = []() {
            bsl::fmt_options ops{" "};
            bsl::ut_then{} = [&ops]() {
                bsl::ut_check(ops.sign() == bsl::fmt_sign::fmt_sign_space_for_pos);
            };
        };

        bsl::ut_given{} = []() {
            bsl::fmt_options ops{"Hello World"};
            bsl::ut_then{} = [&ops]() {
                bsl::ut_check(ops.sign() == bsl::fmt_sign::fmt_sign_neg_only);
            };
        };

        bsl::ut_given{} = []() {
            bsl::fmt_options ops{""};
            bsl::ut_when{} = [&ops]() {
                ops.set_sign(bsl::fmt_sign::fmt_sign_pos_neg);
                bsl::ut_then{} = [&ops]() {
                    bsl::ut_check(ops.sign() == bsl::fmt_sign::fmt_sign_pos_neg);
                };
            };
        };
    };

    bsl::ut_scenario{"alt form"} = []() {
        bsl::ut_given{} = []() {
            bsl::fmt_options ops{"#"};
            bsl::ut_then{} = [&ops]() {
                bsl::ut_check(ops.alternate_form());
            };
        };

        bsl::ut_given{} = []() {
            bsl::fmt_options ops{"Hello World"};
            bsl::ut_then{} = [&ops]() {
                bsl::ut_check(!ops.alternate_form());
            };
        };

        bsl::ut_given{} = []() {
            bsl::fmt_options ops{""};
            bsl::ut_when{} = [&ops]() {
                ops.set_alternate_form(true);
                bsl::ut_then{} = [&ops]() {
                    bsl::ut_check(ops.alternate_form());
                };
            };
        };
    };

    bsl::ut_scenario{"sign aware"} = []() {
        bsl::ut_given{} = []() {
            bsl::fmt_options ops{"0"};
            bsl::ut_then{} = [&ops]() {
                bsl::ut_check(ops.sign_aware());
            };
        };

        bsl::ut_given{} = []() {
            bsl::fmt_options ops{"Hello World"};
            bsl::ut_then{} = [&ops]() {
                bsl::ut_check(!ops.sign_aware());
            };
        };

        bsl::ut_given{} = []() {
            bsl::fmt_options ops{""};
            bsl::ut_when{} = [&ops]() {
                ops.set_sign_aware(true);
                bsl::ut_then{} = [&ops]() {
                    bsl::ut_check(ops.sign_aware());
                };
            };
        };
    };

    bsl::ut_scenario{"width"} = []() {
        constexpr bsl::safe_uintmax digit1{bsl::to_umax(9)};
        constexpr bsl::safe_uintmax digit2{bsl::to_umax(99)};
        constexpr bsl::safe_uintmax digit3{bsl::to_umax(999)};

        bsl::ut_given{} = [&digit1]() {
            bsl::fmt_options ops{"9"};
            bsl::ut_then{} = [&ops, &digit1]() {
                bsl::ut_check(ops.width() == digit1);
            };
        };

        bsl::ut_given{} = [&digit2]() {
            bsl::fmt_options ops{"99"};
            bsl::ut_then{} = [&ops, &digit2]() {
                bsl::ut_check(ops.width() == digit2);
            };
        };

        bsl::ut_given{} = [&digit3]() {
            bsl::fmt_options ops{"999"};
            bsl::ut_then{} = [&ops, &digit3]() {
                bsl::ut_check(ops.width() == digit3);
            };
        };

        bsl::ut_given{} = [&digit3]() {
            bsl::fmt_options ops{"9999"};
            bsl::ut_then{} = [&ops, &digit3]() {
                bsl::ut_check(ops.width() == digit3);
            };
        };

        bsl::ut_given{} = [&digit3]() {
            bsl::fmt_options ops{"999999999999999999999999999999999999999"};
            bsl::ut_then{} = [&ops, &digit3]() {
                bsl::ut_check(ops.width() == digit3);
            };
        };

        bsl::ut_given{} = []() {
            bsl::fmt_options ops{"Hello World"};
            bsl::ut_then{} = [&ops]() {
                bsl::ut_check(ops.width() == bsl::to_umax(0));
            };
        };

        bsl::ut_given{} = []() {
            bsl::fmt_options ops{""};
            bsl::ut_when{} = [&ops]() {
                ops.set_width(bsl::to_umax(9));    // NOLINT
                bsl::ut_then{} = [&ops]() {
                    bsl::ut_check(ops.width() == bsl::to_umax(9));    // NOLINT
                };
            };
        };

        bsl::ut_given{} = []() {
            bsl::fmt_options ops{""};
            bsl::ut_when{} = [&ops]() {
                ops.set_width(bsl::to_umax(99));    // NOLINT
                bsl::ut_then{} = [&ops]() {
                    bsl::ut_check(ops.width() == bsl::to_umax(99));    // NOLINT
                };
            };
        };

        bsl::ut_given{} = []() {
            bsl::fmt_options ops{""};
            bsl::ut_when{} = [&ops]() {
                ops.set_width(bsl::to_umax(999));    // NOLINT
                bsl::ut_then{} = [&ops]() {
                    bsl::ut_check(ops.width() == bsl::to_umax(999));    // NOLINT
                };
            };
        };

        bsl::ut_given{} = []() {
            bsl::fmt_options ops{""};
            bsl::ut_when{} = [&ops]() {
                ops.set_width(bsl::to_umax(9999));    // NOLINT
                bsl::ut_then{} = [&ops]() {
                    bsl::ut_check(ops.width() == bsl::to_umax(999));    // NOLINT
                };
            };
        };

        bsl::ut_given{} = []() {
            bsl::fmt_options ops{""};
            bsl::ut_when{} = [&ops]() {
                ops.set_width(bsl::safe_uintmax::zero(true));
                bsl::ut_then{} = [&ops]() {
                    bsl::ut_check(ops.width() == bsl::to_umax(999));    // NOLINT
                };
            };
        };
    };

    bsl::ut_scenario{"type"} = []() {
        bsl::ut_given{} = []() {
            bsl::fmt_options ops{"b"};
            bsl::ut_then{} = [&ops]() {
                bsl::ut_check(ops.type() == bsl::fmt_type::fmt_type_b);
            };
        };

        bsl::ut_given{} = []() {
            bsl::fmt_options ops{"B"};
            bsl::ut_then{} = [&ops]() {
                bsl::ut_check(ops.type() == bsl::fmt_type::fmt_type_b);
            };
        };

        bsl::ut_given{} = []() {
            bsl::fmt_options ops{"c"};
            bsl::ut_then{} = [&ops]() {
                bsl::ut_check(ops.type() == bsl::fmt_type::fmt_type_c);
            };
        };

        bsl::ut_given{} = []() {
            bsl::fmt_options ops{"d"};
            bsl::ut_then{} = [&ops]() {
                bsl::ut_check(ops.type() == bsl::fmt_type::fmt_type_d);
            };
        };

        bsl::ut_given{} = []() {
            bsl::fmt_options ops{"s"};
            bsl::ut_then{} = [&ops]() {
                bsl::ut_check(ops.type() == bsl::fmt_type::fmt_type_s);
            };
        };

        bsl::ut_given{} = []() {
            bsl::fmt_options ops{"x"};
            bsl::ut_then{} = [&ops]() {
                bsl::ut_check(ops.type() == bsl::fmt_type::fmt_type_x);
            };
        };

        bsl::ut_given{} = []() {
            bsl::fmt_options ops{"X"};
            bsl::ut_then{} = [&ops]() {
                bsl::ut_check(ops.type() == bsl::fmt_type::fmt_type_x);
            };
        };

        bsl::ut_given{} = []() {
            bsl::fmt_options ops{"Hello World"};
            bsl::ut_then{} = [&ops]() {
                bsl::ut_check(ops.type() == bsl::fmt_type::fmt_type_default);
            };
        };

        bsl::ut_given{} = []() {
            bsl::fmt_options ops{""};
            bsl::ut_when{} = [&ops]() {
                ops.set_type(bsl::fmt_type::fmt_type_x);
                bsl::ut_then{} = [&ops]() {
                    bsl::ut_check(ops.type() == bsl::fmt_type::fmt_type_x);
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
