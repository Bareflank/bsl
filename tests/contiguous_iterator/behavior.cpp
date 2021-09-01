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

#include "../array_init.hpp"

#include <bsl/array.hpp>
#include <bsl/contiguous_iterator.hpp>
#include <bsl/convert.hpp>
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
    template<typename T>
    constexpr void
    tests_for_t(T *const pudm_data, bsl::safe_umx const &size) noexcept
    {
        bsl::ut_scenario{"constructor"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                T *const pudm_null{};
                bsl::contiguous_iterator const ci{pudm_null, size, bsl::to_idx(0)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(ci.empty());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::contiguous_iterator const ci{pudm_data, bsl::to_umx(0), bsl::to_idx(0)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(ci.empty());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::contiguous_iterator const ci{pudm_data, size, bsl::to_idx(0)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(ci.data() == pudm_data);
                    bsl::ut_check(ci.size() == size);
                    bsl::ut_check(ci.index() == bsl::to_umx(0));
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::contiguous_iterator const ci{pudm_data, size, bsl::to_idx(size)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(ci.data() == pudm_data);
                    bsl::ut_check(ci.size() == size);
                    bsl::ut_check(ci.index() == size);
                };
            };
        };

        bsl::ut_scenario{"data"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bsl::contiguous_iterator mut_ci{pudm_data, size, bsl::to_idx(0)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_ci.data() == pudm_data);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::contiguous_iterator const ci{pudm_data, size, bsl::to_idx(0)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(ci.data() == pudm_data);
                };
            };
        };

        bsl::ut_scenario{"size"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bsl::contiguous_iterator const ci{pudm_data, size, bsl::to_idx(0)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(ci.size() == size);
                };
            };
        };

        bsl::ut_scenario{"index"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bsl::contiguous_iterator const ci{pudm_data, size, bsl::to_idx(0)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(ci.index() == bsl::to_umx(0));
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::contiguous_iterator const ci{pudm_data, size, bsl::to_idx(size)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(ci.index() == size);
                };
            };
        };

        bsl::ut_scenario{"empty"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                T *const pudm_null{};
                bsl::contiguous_iterator const ci{pudm_null, size, bsl::to_idx(0)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(ci.empty());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::contiguous_iterator const ci{pudm_data, bsl::to_umx(0), bsl::to_idx(0)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(ci.empty());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::contiguous_iterator const ci{pudm_data, size, bsl::to_idx(0)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!ci.empty());
                };
            };
        };

        bsl::ut_scenario{"is_invalid"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                T *const pudm_null{};
                bsl::contiguous_iterator const ci{pudm_null, size, bsl::to_idx(0)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(ci.is_invalid());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::contiguous_iterator const ci{pudm_data, bsl::to_umx(0), bsl::to_idx(0)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!ci.is_invalid());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::contiguous_iterator const ci{pudm_data, size, bsl::to_idx(0)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!ci.is_invalid());
                };
            };
        };

        bsl::ut_scenario{"is_valid"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                T *const pudm_null{};
                bsl::contiguous_iterator const ci{pudm_null, size, bsl::to_idx(0)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!ci.is_valid());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::contiguous_iterator const ci{pudm_data, bsl::to_umx(0), bsl::to_idx(0)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(ci.is_valid());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::contiguous_iterator const ci{pudm_data, size, bsl::to_idx(0)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(ci.is_valid());
                };
            };
        };

        bsl::ut_scenario{"is_end"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                T *const pudm_null{};
                bsl::contiguous_iterator const ci{pudm_null, size, bsl::to_idx(0)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(ci.is_end());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::contiguous_iterator const ci{pudm_data, size, bsl::to_idx(size)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(ci.is_end());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::contiguous_iterator const ci{pudm_data, size, bsl::to_idx(0)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!ci.is_end());
                };
            };
        };

        bsl::ut_scenario{"get_if"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                T *const pudm_null{};
                bsl::contiguous_iterator mut_ci{pudm_null, size, bsl::to_idx(0)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_ci.get_if() == nullptr);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                T *const pudm_null{};
                bsl::contiguous_iterator const ci{pudm_null, size, bsl::to_idx(0)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(ci.get_if() == nullptr);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                T *const pudm_null{};
                bsl::contiguous_iterator mut_ci{pudm_null, bsl::to_umx(0), bsl::to_idx(0)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_ci.get_if() == nullptr);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                T *const pudm_null{};
                bsl::contiguous_iterator const ci{pudm_null, bsl::to_umx(0), bsl::to_idx(0)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(ci.get_if() == nullptr);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::contiguous_iterator mut_ci{pudm_data, size, bsl::to_idx(0)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_ci.get_if() != nullptr);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::contiguous_iterator const ci{pudm_data, size, bsl::to_idx(0)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(ci.get_if() != nullptr);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::contiguous_iterator mut_ci{pudm_data, size, bsl::to_idx(size)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_ci.get_if() == nullptr);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::contiguous_iterator const ci{pudm_data, size, bsl::to_idx(size)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(ci.get_if() == nullptr);
                };
            };
        };

        bsl::ut_scenario{"* operator"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bsl::contiguous_iterator mut_ci{pudm_data, size, bsl::to_idx(0)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::discard(*mut_ci);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::contiguous_iterator const ci{pudm_data, size, bsl::to_idx(0)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::discard(*ci);
                };
            };
        };

        bsl::ut_scenario{"++ operator"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bsl::contiguous_iterator mut_ci{pudm_data, size, bsl::to_idx(0)};
                bsl::ut_when{} = [&]() noexcept {
                    ++mut_ci;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_ci.index() == bsl::to_idx(1));
                    };
                };

                bsl::ut_when{} = [&]() noexcept {
                    ++mut_ci;
                    ++mut_ci;
                    ++mut_ci;
                    ++mut_ci;
                    ++mut_ci;
                    ++mut_ci;
                    ++mut_ci;
                    ++mut_ci;
                    ++mut_ci;
                    ++mut_ci;
                    ++mut_ci;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_ci.index() == bsl::to_idx(size));
                    };
                };
            };
        };

        bsl::ut_scenario{"++ operator"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bsl::contiguous_iterator mut_ci{pudm_data, size, bsl::to_idx(size)};
                bsl::ut_when{} = [&]() noexcept {
                    --mut_ci;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_ci.index() == bsl::to_idx((size - 1_umx).checked()));
                    };
                };

                bsl::ut_when{} = [&]() noexcept {
                    --mut_ci;
                    --mut_ci;
                    --mut_ci;
                    --mut_ci;
                    --mut_ci;
                    --mut_ci;
                    --mut_ci;
                    --mut_ci;
                    --mut_ci;
                    --mut_ci;
                    --mut_ci;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_ci.index() == bsl::to_idx(0));
                    };
                };
            };
        };

        bsl::ut_scenario{"comparisons"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bsl::contiguous_iterator const ci1{pudm_data, size, bsl::to_idx(0)};
                bsl::contiguous_iterator const ci2{pudm_data, size, bsl::to_idx(0)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(ci1 == ci2);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::contiguous_iterator const ci1{pudm_data, size, bsl::to_idx(0)};
                bsl::contiguous_iterator const ci2{pudm_data, size, bsl::to_idx(1)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(ci1 != ci2);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::contiguous_iterator const ci1{pudm_data, size, bsl::to_idx(0)};
                bsl::contiguous_iterator const ci2{pudm_data, size, bsl::to_idx(1)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(ci1 < ci2);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::contiguous_iterator const ci1{pudm_data, size, bsl::to_idx(1)};
                bsl::contiguous_iterator const ci2{pudm_data, size, bsl::to_idx(0)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(ci1 > ci2);
                };
            };
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
        tests_for_t(mut_array.data(), mut_array.size());

        bsl::string_view mut_string{"hello"};
        tests_for_t(mut_string.data(), mut_string.size());

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
