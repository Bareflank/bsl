/// @copyright
/// Copyright (C) 2020 Assured Information Security, Inc.
///
/// @copyright
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and assoriated documentation files (the "Software"), to deal
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

#include <bsl/array.hpp>
#include <bsl/convert.hpp>
#include <bsl/npos.hpp>
#include <bsl/reverse_iterator.hpp>
#include <bsl/ut.hpp>

namespace
{
    constexpr bsl::array TEST_INIT{
        bsl::to_i32(4),
        bsl::to_i32(8),
        bsl::to_i32(5),
        bsl::to_i32(16),
        bsl::to_i32(23),
        bsl::to_i32(42)};

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
        bsl::ut_scenario{"constructor"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::reverse_iterator const ri{TEST_INIT.begin()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!ri.empty());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::reverse_iterator const ri{TEST_INIT.end()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!ri.empty());
                };
            };
        };

        bsl::ut_scenario{"base"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::reverse_iterator const ri{TEST_INIT.begin()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(ri.base() == TEST_INIT.begin());
                };
            };
        };

        bsl::ut_scenario{"data"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::reverse_iterator const ri{TEST_INIT.begin()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(ri.data() == TEST_INIT.data());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::reverse_iterator const ri{TEST_INIT.begin()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(ri.data() == TEST_INIT.data());
                };
            };
        };

        bsl::ut_scenario{"size"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::reverse_iterator const ri{TEST_INIT.begin()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(ri.size() == TEST_INIT.size());
                };
            };
        };

        bsl::ut_scenario{"index"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::reverse_iterator const ri{TEST_INIT.end()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(ri.index() == bsl::to_umax(5));
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::reverse_iterator const ri{TEST_INIT.begin()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(ri.index() == bsl::to_umax(6));
                };
            };
        };

        bsl::ut_scenario{"empty"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::reverse_iterator const ri{TEST_INIT.begin()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!ri.empty());
                };
            };
        };

        bsl::ut_scenario{"operator bool"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::reverse_iterator const ri{TEST_INIT.end()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!!ri);
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::reverse_iterator const ri{TEST_INIT.begin()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!ri);
                };
            };
        };

        bsl::ut_scenario{"is_end"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::reverse_iterator const ri{TEST_INIT.begin()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(ri.is_end());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::reverse_iterator const ri{TEST_INIT.end()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!ri.is_end());
                };
            };
        };

        bsl::ut_scenario{"get_if"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::contiguous_iterator<bool> const ci{nullptr, bsl::to_umax(0), bsl::to_umax(0)};
                bsl::reverse_iterator const ri{ci};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(ri.get_if() == nullptr);
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::contiguous_iterator<bool> const ci{nullptr, bsl::to_umax(0), bsl::to_umax(0)};
                bsl::reverse_iterator const ri{ci};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(ri.get_if() == nullptr);
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::reverse_iterator const ri{TEST_INIT.begin()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(ri.get_if() == nullptr);
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::reverse_iterator const ri{TEST_INIT.begin()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(ri.get_if() == nullptr);
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::reverse_iterator const ri{TEST_INIT.end()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(ri.get_if() == TEST_INIT.back_if());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::reverse_iterator const ri{TEST_INIT.end()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(ri.get_if() == TEST_INIT.back_if());
                };
            };
        };

        bsl::ut_scenario{"++ operator"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::reverse_iterator mut_ri{TEST_INIT.begin()};
                bsl::ut_when{} = [&]() noexcept {
                    ++mut_ri;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_ri.get_if() == nullptr);
                        bsl::ut_check(mut_ri.index() == TEST_INIT.size());
                    };
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::reverse_iterator mut_ri{TEST_INIT.iter(bsl::to_umax(1))};
                bsl::ut_when{} = [&]() noexcept {
                    ++mut_ri;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_ri.get_if() == nullptr);
                        bsl::ut_check(mut_ri.index() == TEST_INIT.size());
                    };
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::reverse_iterator mut_ri{TEST_INIT.iter(bsl::to_umax(2))};
                bsl::ut_when{} = [&]() noexcept {
                    ++mut_ri;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_ri.get_if() == TEST_INIT.front_if());
                        bsl::ut_check(mut_ri.index() == bsl::to_umax(0));
                    };
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::reverse_iterator mut_ri{TEST_INIT.end()};
                bsl::ut_when{} = [&]() noexcept {
                    ++mut_ri;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_ri.get_if() == TEST_INIT.at_if(bsl::to_umax(4)));
                        bsl::ut_check(mut_ri.index() == bsl::to_umax(4));
                    };
                };
            };
        };

        bsl::ut_scenario{"-- operator"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::reverse_iterator mut_ri{TEST_INIT.begin()};
                bsl::ut_when{} = [&]() noexcept {
                    --mut_ri;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_ri.get_if() == TEST_INIT.front_if());
                        bsl::ut_check(mut_ri.index() == bsl::to_umax(0));
                    };
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::reverse_iterator mut_ri{TEST_INIT.iter(bsl::to_umax(1))};
                bsl::ut_when{} = [&]() noexcept {
                    --mut_ri;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_ri.get_if() == TEST_INIT.at_if(bsl::to_umax(1)));
                        bsl::ut_check(mut_ri.index() == bsl::to_umax(1));
                    };
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::reverse_iterator mut_ri{TEST_INIT.iter(bsl::to_umax(bsl::to_umax(5)))};
                bsl::ut_when{} = [&]() noexcept {
                    --mut_ri;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_ri.get_if() == TEST_INIT.back_if());
                        bsl::ut_check(mut_ri.index() == bsl::to_umax(bsl::to_umax(5)));
                    };
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::reverse_iterator mut_ri{TEST_INIT.end()};
                bsl::ut_when{} = [&]() noexcept {
                    --mut_ri;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_ri.get_if() == TEST_INIT.back_if());
                        bsl::ut_check(mut_ri.index() == bsl::to_umax(bsl::to_umax(5)));
                    };
                };
            };
        };

        bsl::ut_scenario{"comparisons"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::reverse_iterator const ri1{TEST_INIT.begin()};
                bsl::reverse_iterator const ri2{TEST_INIT.begin()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(ri1 == ri2);
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::reverse_iterator const ri1{TEST_INIT.begin()};
                bsl::reverse_iterator const ri2{TEST_INIT.end()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(ri1 != ri2);
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::reverse_iterator const ri1{TEST_INIT.begin()};
                bsl::reverse_iterator const ri2{TEST_INIT.end()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(ri1 > ri2);
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::reverse_iterator const ri1{TEST_INIT.end()};
                bsl::reverse_iterator const ri2{TEST_INIT.begin()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(ri1 < ri2);
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
