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

#include "../array_init.hpp"

#include <bsl/array.hpp>
#include <bsl/convert.hpp>
#include <bsl/safe_idx.hpp>
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
    template<typename T>
    constexpr void
    tests_for_t(
        bsl::contiguous_iterator<T> const &ci_begin,
        bsl::contiguous_iterator<T> const &ci_end) noexcept
    {
        bsl::ut_scenario{"constructor"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bsl::reverse_iterator const ri{ci_begin};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!ri.empty());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::reverse_iterator const ri{ci_end};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!ri.empty());
                };
            };
        };

        bsl::ut_scenario{"base"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bsl::reverse_iterator const ri{ci_begin};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(ri.base() == ci_begin);
                };
            };
        };

        bsl::ut_scenario{"data"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bsl::reverse_iterator mut_ri{ci_begin};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_ri.data() == ci_begin.data());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::reverse_iterator const ri{ci_begin};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(ri.data() == ci_begin.data());
                };
            };
        };

        bsl::ut_scenario{"size"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bsl::reverse_iterator const ri{ci_begin};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(ri.size() == ci_begin.size());
                };
            };
        };

        bsl::ut_scenario{"index"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bsl::reverse_iterator const ri{ci_end};
                bsl::ut_then{} = [&]() noexcept {
                    auto const expected{(ci_begin.size() - bsl::safe_umx::magic_1()).checked()};
                    bsl::ut_check(ri.index() == expected);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::reverse_iterator const ri{ci_begin};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(ri.index() == ci_end.index());
                };
            };
        };

        bsl::ut_scenario{"empty"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bsl::reverse_iterator const ri{ci_begin};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!ri.empty());
                };
            };
        };

        bsl::ut_scenario{"is_invalid"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bsl::reverse_iterator const ri{ci_begin};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!ri.is_invalid());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::reverse_iterator const ri{ci_end};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!ri.is_invalid());
                };
            };
        };

        bsl::ut_scenario{"is_valid"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bsl::reverse_iterator const ri{ci_begin};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(ri.is_valid());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::reverse_iterator const ri{ci_end};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(ri.is_valid());
                };
            };
        };

        bsl::ut_scenario{"is_end"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bsl::reverse_iterator const ri{ci_begin};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(ri.is_end());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::reverse_iterator const ri{ci_end};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!ri.is_end());
                };
            };
        };

        bsl::ut_scenario{"get_if"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bsl::reverse_iterator const ri{ci_begin};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(ri.get_if() == nullptr);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::reverse_iterator const ri{ci_begin};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(ri.get_if() == nullptr);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::reverse_iterator const ri{ci_end};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(ri.get_if() != nullptr);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::reverse_iterator const ri{ci_end};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(ri.get_if() != nullptr);
                };
            };
        };

        bsl::ut_scenario{"++ operator"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bsl::reverse_iterator mut_ri{ci_begin};
                bsl::ut_when{} = [&]() noexcept {
                    ++mut_ri;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_ri.get_if() == nullptr);
                        bsl::ut_check(mut_ri.index() == ci_begin.size());
                    };
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::reverse_iterator mut_ri{ci_end};
                bsl::ut_when{} = [&]() noexcept {
                    ++mut_ri;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_ri.get_if() != nullptr);
                        bsl::ut_check(mut_ri.index() != ci_begin.size());
                    };
                };
            };
        };

        bsl::ut_scenario{"-- operator"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bsl::reverse_iterator mut_ri{ci_begin};
                bsl::ut_when{} = [&]() noexcept {
                    --mut_ri;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_ri.get_if() != nullptr);
                        bsl::ut_check(mut_ri.index() == bsl::to_umx(0));
                    };
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::reverse_iterator mut_ri{ci_end};
                bsl::ut_when{} = [&]() noexcept {
                    --mut_ri;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_ri.get_if() != nullptr);
                        bsl::ut_check(mut_ri.index() != bsl::to_umx(0));
                    };
                };
            };
        };

        bsl::ut_scenario{"comparisons"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bsl::reverse_iterator const ri1{ci_begin};
                bsl::reverse_iterator const ri2{ci_begin};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(ri1 == ri2);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::reverse_iterator const ri1{ci_begin};
                bsl::reverse_iterator const ri2{ci_end};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(ri1 != ri2);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::reverse_iterator const ri1{ci_begin};
                bsl::reverse_iterator const ri2{ci_end};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(ri1 > ri2);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::reverse_iterator const ri1{ci_end};
                bsl::reverse_iterator const ri2{ci_begin};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(ri1 < ri2);
                };
            };
        };

        bsl::ut_scenario{"make_reverse_iterator"} = [&]() noexcept {
            bsl::ut_check(bsl::make_reverse_iterator(ci_begin).is_end());
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
    [[nodiscard]] constexpr auto
    tests() noexcept -> bsl::exit_code
    {
        bsl::array mut_array{test::ARRAY_INIT};
        tests_for_t(mut_array.begin(), mut_array.end());

        bsl::ut_scenario{"get_if invalid returns null"} = [&]() noexcept {
            bsl::contiguous_iterator<bsl::safe_i32> mut_ci{nullptr, bsl::to_umx(0), bsl::to_idx(0)};

            bsl::reverse_iterator mut_ri{mut_ci};
            bsl::ut_check(mut_ri.get_if() == nullptr);

            bsl::reverse_iterator const ri{mut_ci};
            bsl::ut_check(ri.get_if() == nullptr);
        };

        bsl::string_view mut_string{"hello"};
        tests_for_t(mut_string.begin(), mut_string.end());

        bsl::ut_scenario{"get_if invalid returns null"} = [&]() noexcept {
            bsl::contiguous_iterator<bsl::char_type const> mut_ci{
                nullptr, bsl::to_umx(0), bsl::to_idx(0)};

            bsl::reverse_iterator mut_ri{mut_ci};
            bsl::ut_check(mut_ri.get_if() == nullptr);

            bsl::reverse_iterator const ri{mut_ci};
            bsl::ut_check(ri.get_if() == nullptr);
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
