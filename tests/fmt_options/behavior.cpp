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
#include <bsl/fmt_options.hpp>
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
        bsl::ut_scenario{"empty"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::fmt_options const ops{""};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(' ' == ops.fill());
                    bsl::ut_check(bsl::fmt_align::fmt_align_default == ops.align());
                    bsl::ut_check(bsl::fmt_sign::fmt_sign_neg_only == ops.sign());
                    bsl::ut_check(!ops.alternate_form());
                    bsl::ut_check(!ops.sign_aware());
                    bsl::ut_check(ops.width() == bsl::to_umx(0));
                    bsl::ut_check(bsl::fmt_type::fmt_type_default == ops.type());
                };
            };
        };

        bsl::ut_scenario{"all fields"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::fmt_options const ops{"#<+#010d"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check('#' == ops.fill());
                    bsl::ut_check(bsl::fmt_align::fmt_align_left == ops.align());
                    bsl::ut_check(bsl::fmt_sign::fmt_sign_pos_neg == ops.sign());
                    bsl::ut_check(ops.alternate_form());
                    bsl::ut_check(ops.sign_aware());
                    bsl::ut_check(ops.width() == bsl::to_umx(10));
                    bsl::ut_check(bsl::fmt_type::fmt_type_d == ops.type());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::fmt_options const ops{"#<+#010dHello World"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check('#' == ops.fill());
                    bsl::ut_check(bsl::fmt_align::fmt_align_left == ops.align());
                    bsl::ut_check(bsl::fmt_sign::fmt_sign_pos_neg == ops.sign());
                    bsl::ut_check(ops.alternate_form());
                    bsl::ut_check(ops.sign_aware());
                    bsl::ut_check(ops.width() == bsl::to_umx(10));
                    bsl::ut_check(bsl::fmt_type::fmt_type_d == ops.type());
                };
            };
        };

        bsl::ut_scenario{"fill-and-align"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::fmt_options const ops{"<"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(' ' == ops.fill());
                    bsl::ut_check(bsl::fmt_align::fmt_align_left == ops.align());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::fmt_options const ops{">"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(' ' == ops.fill());
                    bsl::ut_check(bsl::fmt_align::fmt_align_right == ops.align());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::fmt_options const ops{"^"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(' ' == ops.fill());
                    bsl::ut_check(bsl::fmt_align::fmt_align_center == ops.align());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::fmt_options const ops{"#<"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check('#' == ops.fill());
                    bsl::ut_check(bsl::fmt_align::fmt_align_left == ops.align());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::fmt_options const ops{"#>"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check('#' == ops.fill());
                    bsl::ut_check(bsl::fmt_align::fmt_align_right == ops.align());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::fmt_options const ops{"#^"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check('#' == ops.fill());
                    bsl::ut_check(bsl::fmt_align::fmt_align_center == ops.align());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::fmt_options const ops{"H"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(' ' == ops.fill());
                    bsl::ut_check(bsl::fmt_align::fmt_align_default == ops.align());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::fmt_options const ops{"Hello World"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(' ' == ops.fill());
                    bsl::ut_check(bsl::fmt_align::fmt_align_default == ops.align());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::fmt_options mut_ops{""};
                bsl::ut_when{} = [&]() noexcept {
                    mut_ops.set_fill('#');
                    mut_ops.set_align(bsl::fmt_align::fmt_align_left);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check('#' == mut_ops.fill());
                        bsl::ut_check(bsl::fmt_align::fmt_align_left == mut_ops.align());
                    };
                };
            };
        };

        bsl::ut_scenario{"sign"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::fmt_options const ops{"+"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(bsl::fmt_sign::fmt_sign_pos_neg == ops.sign());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::fmt_options const ops{"-"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(bsl::fmt_sign::fmt_sign_neg_only == ops.sign());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::fmt_options const ops{" "};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(bsl::fmt_sign::fmt_sign_space_for_pos == ops.sign());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::fmt_options const ops{"Hello World"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(bsl::fmt_sign::fmt_sign_neg_only == ops.sign());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::fmt_options mut_ops{""};
                bsl::ut_when{} = [&]() noexcept {
                    mut_ops.set_sign(bsl::fmt_sign::fmt_sign_pos_neg);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(bsl::fmt_sign::fmt_sign_pos_neg == mut_ops.sign());
                    };
                };
            };
        };

        bsl::ut_scenario{"alt form"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::fmt_options const ops{"#"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(ops.alternate_form());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::fmt_options const ops{"Hello World"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!ops.alternate_form());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::fmt_options mut_ops{""};
                bsl::ut_when{} = [&]() noexcept {
                    mut_ops.set_alternate_form(true);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_ops.alternate_form());
                    };
                };
            };
        };

        bsl::ut_scenario{"sign aware"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::fmt_options const ops{"0"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(ops.sign_aware());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::fmt_options const ops{"Hello World"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!ops.sign_aware());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::fmt_options mut_ops{""};
                bsl::ut_when{} = [&]() noexcept {
                    mut_ops.set_sign_aware(true);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_ops.sign_aware());
                    };
                };
            };
        };

        bsl::ut_scenario{"width"} = []() noexcept {
            constexpr bsl::safe_umx digit1{bsl::to_umx(9)};
            constexpr bsl::safe_umx digit2{bsl::to_umx(99)};
            constexpr bsl::safe_umx digit3{bsl::to_umx(999)};

            bsl::ut_given{} = [&]() noexcept {
                bsl::fmt_options const ops{"9"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(ops.width() == digit1);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::fmt_options const ops{"99"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(ops.width() == digit2);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::fmt_options const ops{"999"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(ops.width() == digit3);
                };
            };

            bsl::ut_given_at_runtime{} = [&]() noexcept {
                bsl::fmt_options const ops{"9999"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(ops.width() == digit3);
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::fmt_options const ops{"Hello World"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(ops.width() == bsl::to_umx(0));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::fmt_options const ops{"/:"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(ops.width() == bsl::to_umx(0));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::fmt_options mut_ops{""};
                bsl::ut_when{} = [&]() noexcept {
                    mut_ops.set_width(bsl::to_umx(9));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_ops.width() == bsl::to_umx(9));
                    };
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::fmt_options mut_ops{""};
                bsl::ut_when{} = [&]() noexcept {
                    mut_ops.set_width(bsl::to_umx(99));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_ops.width() == bsl::to_umx(99));
                    };
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::fmt_options mut_ops{""};
                bsl::ut_when{} = [&]() noexcept {
                    mut_ops.set_width(bsl::to_umx(999));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_ops.width() == bsl::to_umx(999));
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::fmt_options mut_ops{""};
                bsl::ut_when{} = [&]() noexcept {
                    mut_ops.set_width(bsl::to_umx(9999));
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_ops.width() == bsl::to_umx(999));
                    };
                };
            };
        };

        bsl::ut_scenario{"type"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::fmt_options const ops{"b"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(bsl::fmt_type::fmt_type_b == ops.type());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::fmt_options const ops{"B"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(bsl::fmt_type::fmt_type_b == ops.type());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::fmt_options const ops{"c"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(bsl::fmt_type::fmt_type_c == ops.type());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::fmt_options const ops{"d"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(bsl::fmt_type::fmt_type_d == ops.type());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::fmt_options const ops{"s"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(bsl::fmt_type::fmt_type_s == ops.type());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::fmt_options const ops{"x"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(bsl::fmt_type::fmt_type_x == ops.type());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::fmt_options const ops{"X"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(bsl::fmt_type::fmt_type_x == ops.type());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::fmt_options const ops{"Hello World"};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(bsl::fmt_type::fmt_type_default == ops.type());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::fmt_options mut_ops{""};
                bsl::ut_when{} = [&]() noexcept {
                    mut_ops.set_type(bsl::fmt_type::fmt_type_x);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(bsl::fmt_type::fmt_type_x == mut_ops.type());
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
