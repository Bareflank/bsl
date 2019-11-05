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

#include <bsl/result.hpp>
#include <bsl/ut.hpp>

namespace
{
    struct monitor_stats final
    {
        bsl::intmax constructor;
        bsl::intmax copy_constructor;
        bsl::intmax move_constructor;
        bsl::intmax copy_assignment;
        bsl::intmax move_assignment;
        bsl::intmax destructor;
    };

    /// @class bsl::example_class_base
    ///
    /// <!-- description -->
    ///   @brief A simple class for monitoring construction and assignment
    ///     stats.
    ///
    class test_result_monitor final
    {
        monitor_stats *m_stats{};

    public:
        /// <!-- description -->
        ///   @brief default constructor
        ///
        explicit constexpr test_result_monitor(monitor_stats *stats) noexcept    // --
            : m_stats{stats}
        {
            m_stats->constructor++;
        }

        /// <!-- description -->
        ///   @brief copy constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object to copy
        ///
        constexpr test_result_monitor(test_result_monitor const &o) noexcept : m_stats{o.m_stats}
        {
            m_stats->copy_constructor++;
        }

        /// <!-- description -->
        ///   @brief copy constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object to copy
        ///
        constexpr test_result_monitor(test_result_monitor &&o) noexcept : m_stats{o.m_stats}
        {
            m_stats->move_constructor++;
        }

        /// <!-- description -->
        ///   @brief copy assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object to copy
        ///   @return *this
        ///
        [[maybe_unused]] constexpr test_result_monitor &
        operator=(test_result_monitor const &o) &noexcept
        {
            if (this == &o) {
                return *this;
            }

            m_stats = o.m_stats;
            m_stats->copy_assignment++;

            return *this;
        }

        /// <!-- description -->
        ///   @brief move assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object to move
        ///   @return *this
        ///
        [[maybe_unused]] constexpr test_result_monitor &
        operator=(test_result_monitor &&o) &noexcept
        {
            if (this == &o) {
                return *this;
            }

            m_stats = o.m_stats;
            m_stats->move_assignment++;

            return *this;
        }

        /// <!-- description -->
        ///   @brief destructor
        ///
        constexpr ~test_result_monitor() noexcept
        {
            m_stats->destructor++;
        }
    };
}

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
    bsl::ut_scenario{"make copy t"} = []() {
        monitor_stats stats{};
        bsl::ut_given{} = [&stats]() {
            test_result_monitor const t{&stats};
            bsl::result<test_result_monitor> const test{t};
            bsl::ut_then{} = [&test, &stats]() {
                bsl::ut_check(1 == stats.constructor);
                bsl::ut_check(1 == stats.copy_constructor);
                bsl::ut_check(0 == stats.move_constructor);
                bsl::ut_check(0 == stats.copy_assignment);
                bsl::ut_check(0 == stats.move_assignment);
                bsl::ut_check(test.success());
                bsl::ut_check(test.errc() == bsl::errc_success);
            };
        };

        bsl::ut_check(2 == stats.destructor);
    };

    bsl::ut_scenario{"make move t"} = []() {
        monitor_stats stats{};
        bsl::ut_given{} = [&stats]() {
            test_result_monitor t{&stats};
            bsl::result<test_result_monitor> const test{bsl::move(t)};
            bsl::ut_then{} = [&test, &stats]() {
                bsl::ut_check(1 == stats.constructor);
                bsl::ut_check(0 == stats.copy_constructor);
                bsl::ut_check(1 == stats.move_constructor);
                bsl::ut_check(0 == stats.copy_assignment);
                bsl::ut_check(0 == stats.move_assignment);
                bsl::ut_check(test.success());
                bsl::ut_check(test.errc() == bsl::errc_success);
            };
        };

        bsl::ut_check(2 == stats.destructor);
    };

    bsl::ut_scenario{"make in place"} = []() {
        monitor_stats stats{};
        bsl::ut_given{} = [&stats]() {
            bsl::result<test_result_monitor> const test{bsl::in_place, &stats};
            bsl::ut_then{} = [&test, &stats]() {
                bsl::ut_check(1 == stats.constructor);
                bsl::ut_check(0 == stats.copy_constructor);
                bsl::ut_check(0 == stats.move_constructor);
                bsl::ut_check(0 == stats.copy_assignment);
                bsl::ut_check(0 == stats.move_assignment);
                bsl::ut_check(test.success());
                bsl::ut_check(test.errc() == bsl::errc_success);
            };
        };

        bsl::ut_check(1 == stats.destructor);
    };

    bsl::ut_scenario{"make copy errc"} = []() {
        bsl::ut_given{} = []() {
            bsl::errc_type const myerror{42};
            bsl::result<test_result_monitor> const test{myerror};
            bsl::ut_then{} = [&test, &myerror]() {
                bsl::ut_check(test.failure());
                bsl::ut_check(test.errc() == myerror);
            };
        };
    };

    bsl::ut_scenario{"make move errc"} = []() {
        bsl::ut_given{} = []() {
            bsl::errc_type myerror{42};
            bsl::result<test_result_monitor> const test{bsl::move(myerror)};
            bsl::ut_then{} = [&test, &myerror]() {
                bsl::ut_check(test.failure());
                bsl::ut_check(test.errc() == myerror);
            };
        };
    };

    bsl::ut_scenario{"copy with t"} = []() {
        monitor_stats stats{};
        bsl::ut_given{} = [&stats]() {
            bsl::result<test_result_monitor> const test1{bsl::in_place, &stats};
            bsl::result<test_result_monitor> const test2{test1};
            bsl::ut_then{} = [&test1, &test2, &stats]() {
                bsl::ut_check(1 == stats.constructor);
                bsl::ut_check(1 == stats.copy_constructor);
                bsl::ut_check(0 == stats.move_constructor);
                bsl::ut_check(0 == stats.copy_assignment);
                bsl::ut_check(0 == stats.move_assignment);
                bsl::ut_check(test1.success());
                bsl::ut_check(test2.success());
            };
        };

        bsl::ut_check(2 == stats.destructor);
    };

    bsl::ut_scenario{"copy with errc"} = []() {
        bsl::ut_given{} = []() {
            bsl::result<test_result_monitor> const test1{bsl::errc_failure};
            bsl::result<test_result_monitor> const test2{test1};
            bsl::ut_then{} = [&test1, &test2]() {
                bsl::ut_check(test1.failure());
                bsl::ut_check(test2.failure());
            };
        };
    };

    bsl::ut_scenario{"move with t"} = []() {
        monitor_stats stats{};
        bsl::ut_given{} = [&stats]() {
            bsl::result<test_result_monitor> test1{bsl::in_place, &stats};
            bsl::result<test_result_monitor> const test2{bsl::move(test1)};
            bsl::ut_then{} = [&test2, &stats]() {
                bsl::ut_check(1 == stats.constructor);
                bsl::ut_check(0 == stats.copy_constructor);
                bsl::ut_check(1 == stats.move_constructor);
                bsl::ut_check(0 == stats.copy_assignment);
                bsl::ut_check(0 == stats.move_assignment);
                bsl::ut_check(test2.success());
            };
        };

        bsl::ut_check(2 == stats.destructor);
    };

    bsl::ut_scenario{"move with errc"} = []() {
        bsl::ut_given{} = []() {
            bsl::result<test_result_monitor> test1{bsl::errc_failure};
            bsl::result<test_result_monitor> const test2{bsl::move(test1)};
            bsl::ut_then{} = [&test2]() {
                bsl::ut_check(test2.failure());
            };
        };
    };

    bsl::ut_scenario{"copy assignment with t"} = []() {
        monitor_stats stats{};
        bsl::ut_given{} = [&stats]() {
            bsl::result<test_result_monitor> const test1{bsl::in_place, &stats};
            bsl::result<test_result_monitor> test2{bsl::in_place, &stats};
            bsl::ut_when{} = [&test1, &test2, &stats]() {
                test2 = test1;
                bsl::ut_then{} = [&test1, &test2, &stats]() {
                    bsl::ut_check(2 == stats.constructor);
                    bsl::ut_check(1 == stats.copy_constructor);
                    bsl::ut_check(1 == stats.move_constructor);
                    bsl::ut_check(0 == stats.copy_assignment);
                    bsl::ut_check(2 == stats.move_assignment);
                    bsl::ut_check(2 == stats.destructor);
                    bsl::ut_check(test1.success());
                    bsl::ut_check(test2.success());
                };
            };
        };

        bsl::ut_check(4 == stats.destructor);
    };

    bsl::ut_scenario{"move assignment with t"} = []() {
        monitor_stats stats{};
        bsl::ut_given{} = [&stats]() {
            bsl::result<test_result_monitor> test1{bsl::in_place, &stats};
            bsl::result<test_result_monitor> test2{bsl::in_place, &stats};
            bsl::ut_when{} = [&test1, &test2, &stats]() {
                test2 = bsl::move(test1);
                bsl::ut_then{} = [&test1, &test2, &stats]() {
                    bsl::ut_check(2 == stats.constructor);
                    bsl::ut_check(0 == stats.copy_constructor);
                    bsl::ut_check(2 == stats.move_constructor);
                    bsl::ut_check(0 == stats.copy_assignment);
                    bsl::ut_check(2 == stats.move_assignment);
                    bsl::ut_check(2 == stats.destructor);
                    bsl::ut_check(test1.success());
                    bsl::ut_check(test2.success());
                };
            };
        };

        bsl::ut_check(4 == stats.destructor);
    };

    bsl::ut_scenario{"copy assignment with e"} = []() {
        bsl::ut_given{} = []() {
            bsl::result<test_result_monitor> const test1{bsl::errc_failure};
            bsl::result<test_result_monitor> test2{bsl::errc_failure};
            bsl::ut_when{} = [&test1, &test2]() {
                test2 = test1;
                bsl::ut_then{} = [&test1, &test2]() {
                    bsl::ut_check(test1.failure());
                    bsl::ut_check(test2.failure());
                };
            };
        };
    };

    bsl::ut_scenario{"move assignment with e"} = []() {
        bsl::ut_given{} = []() {
            bsl::result<test_result_monitor> test1{bsl::errc_failure};
            bsl::result<test_result_monitor> test2{bsl::errc_failure};
            bsl::ut_when{} = [&test1, &test2]() {
                test2 = bsl::move(test1);
                bsl::ut_then{} = [&test1, &test2]() {
                    bsl::ut_check(test1.failure());
                    bsl::ut_check(test2.failure());
                };
            };
        };
    };

    bsl::ut_scenario{"copy assignment with t/e"} = []() {
        monitor_stats stats{};
        bsl::ut_given{} = [&stats]() {
            bsl::result<test_result_monitor> const test1{bsl::in_place, &stats};
            bsl::result<test_result_monitor> test2{bsl::errc_failure};
            bsl::ut_when{} = [&test1, &test2, &stats]() {
                test2 = test1;
                bsl::ut_then{} = [&test1, &test2, &stats]() {
                    bsl::ut_check(1 == stats.constructor);
                    bsl::ut_check(1 == stats.copy_constructor);
                    bsl::ut_check(1 == stats.move_constructor);
                    bsl::ut_check(0 == stats.copy_assignment);
                    bsl::ut_check(0 == stats.move_assignment);
                    bsl::ut_check(1 == stats.destructor);
                    bsl::ut_check(test1.success());
                    bsl::ut_check(test2.success());
                };
            };
        };

        bsl::ut_check(3 == stats.destructor);
    };

    bsl::ut_scenario{"copy assignment with e/t"} = []() {
        monitor_stats stats{};
        bsl::ut_given{} = [&stats]() {
            bsl::result<test_result_monitor> const test1{bsl::errc_failure};
            bsl::result<test_result_monitor> test2{bsl::in_place, &stats};
            bsl::ut_when{} = [&test1, &test2, &stats]() {
                test2 = test1;
                bsl::ut_then{} = [&test1, &test2, &stats]() {
                    bsl::ut_check(1 == stats.constructor);
                    bsl::ut_check(0 == stats.copy_constructor);
                    bsl::ut_check(1 == stats.move_constructor);
                    bsl::ut_check(0 == stats.copy_assignment);
                    bsl::ut_check(0 == stats.move_assignment);
                    bsl::ut_check(2 == stats.destructor);
                    bsl::ut_check(test1.failure());
                    bsl::ut_check(test2.failure());
                };
            };
        };

        bsl::ut_check(2 == stats.destructor);
    };

    bsl::ut_scenario{"move assignment with t/e"} = []() {
        monitor_stats stats{};
        bsl::ut_given{} = [&stats]() {
            bsl::result<test_result_monitor> test1{bsl::in_place, &stats};
            bsl::result<test_result_monitor> test2{bsl::errc_failure};
            bsl::ut_when{} = [&test1, &test2, &stats]() {
                test2 = bsl::move(test1);
                bsl::ut_then{} = [&test1, &test2, &stats]() {
                    bsl::ut_check(1 == stats.constructor);
                    bsl::ut_check(0 == stats.copy_constructor);
                    bsl::ut_check(2 == stats.move_constructor);
                    bsl::ut_check(0 == stats.copy_assignment);
                    bsl::ut_check(0 == stats.move_assignment);
                    bsl::ut_check(1 == stats.destructor);
                    bsl::ut_check(test1.success());
                    bsl::ut_check(test2.success());
                };
            };
        };

        bsl::ut_check(3 == stats.destructor);
    };

    bsl::ut_scenario{"move assignment with e/t"} = []() {
        monitor_stats stats{};
        bsl::ut_given{} = [&stats]() {
            bsl::result<test_result_monitor> test1{bsl::errc_failure};
            bsl::result<test_result_monitor> test2{bsl::in_place, &stats};
            bsl::ut_when{} = [&test1, &test2, &stats]() {
                test2 = bsl::move(test1);
                bsl::ut_then{} = [&test1, &test2, &stats]() {
                    bsl::ut_check(1 == stats.constructor);
                    bsl::ut_check(0 == stats.copy_constructor);
                    bsl::ut_check(1 == stats.move_constructor);
                    bsl::ut_check(0 == stats.copy_assignment);
                    bsl::ut_check(0 == stats.move_assignment);
                    bsl::ut_check(2 == stats.destructor);
                    bsl::ut_check(test1.failure());
                    bsl::ut_check(test2.failure());
                };
            };
        };

        bsl::ut_check(2 == stats.destructor);
    };

    bsl::ut_scenario{"equality success"} = []() {
        bsl::ut_given{} = []() {
            bsl::result<bool> test1{bsl::in_place, true};
            bsl::result<bool> test2{bsl::in_place, true};
            bsl::ut_then{} = [&test1, &test2]() {
                bsl::ut_check(test1 == test2);
            };
        };
    };

    bsl::ut_scenario{"equality success and failure"} = []() {
        bsl::ut_given{} = []() {
            bsl::result<bool> test1{bsl::in_place, true};
            bsl::result<bool> test2{bsl::errc_failure};
            bsl::ut_then{} = [&test1, &test2]() {
                bsl::ut_check(test1 != test2);
            };
        };

        bsl::ut_given{} = []() {
            bsl::result<bool> test1{bsl::errc_failure};
            bsl::result<bool> test2{bsl::in_place, true};
            bsl::ut_then{} = [&test1, &test2]() {
                bsl::ut_check(test1 != test2);
            };
        };
    };

    bsl::ut_scenario{"equality failure"} = []() {
        bsl::ut_given{} = []() {
            bsl::result<bool> test1{bsl::errc_failure};
            bsl::result<bool> test2{bsl::errc_failure};
            bsl::ut_then{} = [&test1, &test2]() {
                bsl::ut_check(test1 == test2);
            };
        };
    };

    bsl::ut_scenario{"not equal"} = []() {
        bsl::ut_given{} = []() {
            bsl::result<bool> test1{bsl::in_place, true};
            bsl::result<bool> test2{bsl::in_place, false};
            bsl::ut_then{} = [&test1, &test2]() {
                bsl::ut_check(test1 != test2);
            };
        };

        bsl::ut_given{} = []() {
            bsl::result<bool> test1{bsl::errc_failure};
            bsl::result<bool> test2{bsl::errc_nullptr_dereference};
            bsl::ut_then{} = [&test1, &test2]() {
                bsl::ut_check(test1 != test2);
            };
        };
    };

    bsl::ut_scenario{"get_if"} = []() {
        bsl::ut_given{} = []() {
            bsl::result<bool> test{bsl::in_place, true};
            bsl::ut_then{} = [&test]() {
                bsl::ut_check(test.get_if() != nullptr);
                bsl::ut_check(*test.get_if());
            };
        };

        bsl::ut_given{} = []() {
            bsl::result<bool> test{bsl::errc_failure};
            bsl::ut_then{} = [&test]() {
                bsl::ut_check(test.get_if() == nullptr);
            };
        };

        bsl::ut_given{} = []() {
            bsl::result<bool> const test{bsl::in_place, true};
            bsl::ut_then{} = [&test]() {
                bsl::ut_check(test.get_if() != nullptr);
                bsl::ut_check(*test.get_if());
            };
        };

        bsl::ut_given{} = []() {
            bsl::result<bool> const test{bsl::errc_failure};
            bsl::ut_then{} = [&test]() {
                bsl::ut_check(test.get_if() == nullptr);
            };
        };
    };

    bsl::ut_scenario{"errc"} = []() {
        bsl::ut_given{} = []() {
            bsl::result<bool> const test{bsl::in_place, true};
            bsl::ut_then{} = [&test]() {
                bsl::ut_check(test.errc() == bsl::errc_success);
            };
        };

        bsl::ut_given{} = []() {
            bsl::result<bool> const test{bsl::errc_failure};
            bsl::ut_then{} = [&test]() {
                bsl::ut_check(test.errc() == bsl::errc_failure);
            };
        };
    };

    bsl::ut_scenario{"success"} = []() {
        bsl::ut_given{} = []() {
            bsl::result<bool> const test{bsl::in_place, true};
            bsl::ut_then{} = [&test]() {
                bsl::ut_check(test.success());
            };
        };

        bsl::ut_given{} = []() {
            bsl::result<bool> const test{bsl::errc_failure};
            bsl::ut_then{} = [&test]() {
                bsl::ut_check(!test.success());
            };
        };
    };

    bsl::ut_scenario{"failure"} = []() {
        bsl::ut_given{} = []() {
            bsl::result<bool> const test{bsl::in_place, true};
            bsl::ut_then{} = [&test]() {
                bsl::ut_check(!test.failure());
            };
        };

        bsl::ut_given{} = []() {
            bsl::result<bool> const test{bsl::errc_failure};
            bsl::ut_then{} = [&test]() {
                bsl::ut_check(test.failure());
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
