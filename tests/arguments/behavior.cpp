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

#include <bsl/arguments.hpp>
#include <bsl/array.hpp>
#include <bsl/cstr_type.hpp>
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
    using namespace bsl;

    bsl::ut_scenario{"constructors"} = []() {
        bsl::ut_given{} = []() {
            array argv{"4", "-opt1", "8", "15", "16", "-opt2", "23", "42"};
            arguments const args{argv.size(), argv.data()};
            bsl::ut_then{} = [&args]() {
                bsl::ut_check(args.get<safe_uint64>(to_umax(0)) == to_u64(4));
                bsl::ut_check(args.get<bool>("-opt1"));
                bsl::ut_check(args.get<safe_uint64>(to_umax(1)) == to_u64(8));
                bsl::ut_check(args.get<safe_uint64>(to_umax(2)) == to_u64(15));
                bsl::ut_check(args.get<safe_uint64>(to_umax(3)) == to_u64(16));
                bsl::ut_check(args.get<bool>("-opt2"));
                bsl::ut_check(args.get<safe_uint64>(to_umax(4)) == to_u64(23));
                bsl::ut_check(args.get<safe_uint64>(to_umax(5)) == to_u64(42));
            };
        };

        bsl::ut_given{} = []() {
            array argv{"4", "-opt1", "8", "15", "16", "-opt2", "23", "42"};
            arguments const args{argv.size().get(), argv.data()};
            bsl::ut_then{} = [&args]() {
                bsl::ut_check(args.get<safe_uint64>(to_umax(0)) == to_u64(4));
                bsl::ut_check(args.get<bool>("-opt1"));
                bsl::ut_check(args.get<safe_uint64>(to_umax(1)) == to_u64(8));
                bsl::ut_check(args.get<safe_uint64>(to_umax(2)) == to_u64(15));
                bsl::ut_check(args.get<safe_uint64>(to_umax(3)) == to_u64(16));
                bsl::ut_check(args.get<bool>("-opt2"));
                bsl::ut_check(args.get<safe_uint64>(to_umax(4)) == to_u64(23));
                bsl::ut_check(args.get<safe_uint64>(to_umax(5)) == to_u64(42));
            };
        };
    };

    bsl::ut_scenario{"args"} = []() {
        bsl::ut_given{} = []() {
            array argv{"4", "-opt1", "8", "15", "16", "-opt2", "23", "42"};
            arguments const args{argv.size(), argv.data()};
            bsl::ut_then{} = [&args, &argv]() {
                bsl::ut_check(args.args().data() == argv.data());
                bsl::ut_check(args.args().size() == argv.size());
            };
        };
    };

    bsl::ut_scenario{"at"} = []() {
        bsl::ut_given{} = []() {
            array argv{"4", "-opt1", "8", "15", "16", "-opt2", "23", "42"};
            arguments const args{argv.size(), argv.data()};
            bsl::ut_then{} = [&args]() {
                bsl::ut_check(args.at<bsl::string_view>(to_umax(0)) == "4");
                bsl::ut_check(args.at<bsl::string_view>(to_umax(1)) == "8");
                bsl::ut_check(args.at<bsl::string_view>(to_umax(2)) == "15");
                bsl::ut_check(args.at<bsl::string_view>(to_umax(3)) == "16");
                bsl::ut_check(args.at<bsl::string_view>(to_umax(4)) == "23");
                bsl::ut_check(args.at<bsl::string_view>(to_umax(5)) == "42");
                bsl::ut_check(args.at<bsl::string_view>(to_umax(6)).empty());
            };
        };
    };

    bsl::ut_scenario{"front"} = []() {
        bsl::ut_given{} = []() {
            array argv{"4", "-opt1", "8", "15", "16", "-opt2", "23", "42"};
            arguments const args{argv.size(), argv.data()};
            bsl::ut_then{} = [&args]() {
                bsl::ut_check(args.front<bsl::string_view>() == "4");
            };
        };

        bsl::ut_given{} = []() {
            arguments const args{0, nullptr};
            bsl::ut_then{} = [&args]() {
                bsl::ut_check(args.front<bsl::string_view>().empty());
            };
        };
    };

    bsl::ut_scenario{"back"} = []() {
        bsl::ut_given{} = []() {
            array argv{"4", "-opt1", "8", "15", "16", "-opt2", "23", "42"};
            arguments const args{argv.size(), argv.data()};
            bsl::ut_then{} = [&args]() {
                bsl::ut_check(args.back<bsl::string_view>() == "42");
            };
        };

        bsl::ut_given{} = []() {
            arguments const args{0, nullptr};
            bsl::ut_then{} = [&args]() {
                bsl::ut_check(args.back<bsl::string_view>().empty());
            };
        };
    };

    bsl::ut_scenario{"empty"} = []() {
        bsl::ut_given{} = []() {
            array argv{"4", "-opt1", "8", "15", "16", "-opt2", "23", "42"};
            arguments const args{argv.size(), argv.data()};
            bsl::ut_then{} = [&args]() {
                bsl::ut_check(!args.empty());
            };
        };

        bsl::ut_given{} = []() {
            arguments const args{0, nullptr};
            bsl::ut_then{} = [&args]() {
                bsl::ut_check(args.empty());
            };
        };
    };

    bsl::ut_scenario{"operator bool"} = []() {
        bsl::ut_given{} = []() {
            arguments args{0, nullptr};
            bsl::ut_then{} = [&args]() {
                bsl::ut_check(!args);
            };
        };

        bsl::ut_given{} = []() {
            array argv{"4", "-opt1", "8", "15", "16", "-opt2", "23", "42"};
            arguments args{argv.size(), argv.data()};
            bsl::ut_then{} = [&args]() {
                bsl::ut_check(!!args);
            };
        };
    };

    bsl::ut_scenario{"size"} = []() {
        bsl::ut_given{} = []() {
            array argv{"4", "-opt1", "8", "15", "16", "-opt2", "23", "42"};
            arguments const args{argv.size(), argv.data()};
            bsl::ut_then{} = [&args]() {
                bsl::ut_check(args.size() == to_umax(6));
            };
        };

        bsl::ut_given{} = []() {
            arguments const args{0, nullptr};
            bsl::ut_then{} = [&args]() {
                bsl::ut_check(args.size().is_zero());
            };
        };
    };

    bsl::ut_scenario{"increment"} = []() {
        bsl::ut_given{} = []() {
            array argv{"4", "-opt1", "8", "15", "16", "-opt2", "23", "42"};
            arguments args{argv.size(), argv.data()};
            bsl::ut_when{} = [&args]() {
                ++args;
                bsl::ut_then{} = [&args]() {
                    bsl::ut_check(args.at<bsl::string_view>(to_umax(0)) == "8");
                    bsl::ut_check(args.at<bsl::string_view>(to_umax(1)) == "15");
                    bsl::ut_check(args.at<bsl::string_view>(to_umax(2)) == "16");
                    bsl::ut_check(args.at<bsl::string_view>(to_umax(3)) == "23");
                    bsl::ut_check(args.at<bsl::string_view>(to_umax(4)) == "42");
                    bsl::ut_check(args.at<bsl::string_view>(to_umax(5)).empty());
                };
            };

            bsl::ut_when{} = [&args]() {
                ++args;
                bsl::ut_then{} = [&args]() {
                    bsl::ut_check(args.at<bsl::string_view>(to_umax(0)) == "15");
                    bsl::ut_check(args.at<bsl::string_view>(to_umax(1)) == "16");
                    bsl::ut_check(args.at<bsl::string_view>(to_umax(2)) == "23");
                    bsl::ut_check(args.at<bsl::string_view>(to_umax(3)) == "42");
                    bsl::ut_check(args.at<bsl::string_view>(to_umax(4)).empty());
                };
            };

            bsl::ut_when{} = [&args]() {
                ++args;
                bsl::ut_then{} = [&args]() {
                    bsl::ut_check(args.at<bsl::string_view>(to_umax(0)) == "16");
                    bsl::ut_check(args.at<bsl::string_view>(to_umax(1)) == "23");
                    bsl::ut_check(args.at<bsl::string_view>(to_umax(2)) == "42");
                    bsl::ut_check(args.at<bsl::string_view>(to_umax(3)).empty());
                };
            };

            bsl::ut_when{} = [&args]() {
                ++args;
                bsl::ut_then{} = [&args]() {
                    bsl::ut_check(args.at<bsl::string_view>(to_umax(0)) == "23");
                    bsl::ut_check(args.at<bsl::string_view>(to_umax(1)) == "42");
                    bsl::ut_check(args.at<bsl::string_view>(to_umax(2)).empty());
                };
            };

            bsl::ut_when{} = [&args]() {
                ++args;
                bsl::ut_then{} = [&args]() {
                    bsl::ut_check(args.at<bsl::string_view>(to_umax(0)) == "42");
                    bsl::ut_check(args.at<bsl::string_view>(to_umax(1)).empty());
                };
            };

            bsl::ut_when{} = [&args]() {
                ++args;
                bsl::ut_then{} = [&args]() {
                    bsl::ut_check(args.at<bsl::string_view>(to_umax(0)).empty());
                };
            };
        };

        bsl::ut_given{} = []() {
            arguments const args{0, nullptr};
            bsl::ut_then{} = [&args]() {
                bsl::ut_check(args.size().is_zero());
            };
        };
    };

    bsl::ut_scenario{"output doesn't crash"} = []() {
        bsl::ut_given{} = []() {
            array argv{"4", "-opt1", "8", "15", "16", "-opt2", "23", "42"};
            arguments args{argv.size(), argv.data()};
            bsl::ut_then{} = [&args]() {
                bsl::debug() << args << '\n';
            };
        };

        bsl::ut_given{} = []() {
            array argv{"4", "-opt1", "8", "15", "16", "-opt2", "23", "42"};
            arguments const args{argv.size(), argv.data()};
            bsl::ut_then{} = [&args]() {
                bsl::debug() << args << '\n';
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
