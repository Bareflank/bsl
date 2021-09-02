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
#include "../carray_init.hpp"

#include <bsl/array.hpp>
#include <bsl/carray.hpp>
#include <bsl/convert.hpp>
#include <bsl/cstr_type.hpp>
#include <bsl/safe_idx.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/span.hpp>
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
    /// <!-- inputs/outputs -->
    ///   @return Always returns bsl::exit_success.
    ///
    [[nodiscard]] constexpr auto
    tests() noexcept -> bsl::exit_code
    {
        auto mut_arr{test::ARRAY_INIT};
        auto const arr{test::ARRAY_INIT};

        auto mut_args{test::CARRAY_INIT_STR_ARGS};
        auto const args{test::CARRAY_INIT_STR_ARGS};

        bsl::ut_scenario{"default constructor"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::safe_i32> mut_spn{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_spn.empty());
                    bsl::ut_check(mut_spn.is_invalid());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::safe_i32 const> const spn{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(spn.empty());
                    bsl::ut_check(spn.is_invalid());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::cstr_type> mut_spn{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_spn.empty());
                    bsl::ut_check(mut_spn.is_invalid());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::cstr_type const> const spn{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(spn.empty());
                    bsl::ut_check(spn.is_invalid());
                };
            };
        };

        bsl::ut_scenario{"ptr/count constructor"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bsl::span mut_spn{mut_arr.data(), 0_umx};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_spn.empty());
                    bsl::ut_check(!mut_spn.is_invalid());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span const spn{arr.data(), 0_umx};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(spn.empty());
                    bsl::ut_check(!spn.is_invalid());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span mut_spn{mut_args.data(), 0_umx};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_spn.empty());
                    bsl::ut_check(!mut_spn.is_invalid());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span const spn{args.data(), 0_umx};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(spn.empty());
                    bsl::ut_check(!spn.is_invalid());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span mut_spn{mut_arr.data(), mut_arr.size()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!mut_spn.empty());
                    bsl::ut_check(!mut_spn.is_invalid());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span const spn{arr.data(), arr.size()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!spn.empty());
                    bsl::ut_check(!spn.is_invalid());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span mut_spn{mut_args.data(), bsl::to_umx(mut_args.size())};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!mut_spn.empty());
                    bsl::ut_check(!mut_spn.is_invalid());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span const spn{args.data(), bsl::to_umx(args.size())};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!spn.empty());
                    bsl::ut_check(!spn.is_invalid());
                };
            };
        };

        bsl::ut_scenario{"array constructors"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bsl::span mut_spn{mut_arr};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!mut_spn.empty());
                    bsl::ut_check(!mut_spn.is_invalid());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span const spn{arr};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!spn.empty());
                    bsl::ut_check(!spn.is_invalid());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span mut_spn{mut_args};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!mut_spn.empty());
                    bsl::ut_check(!mut_spn.is_invalid());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span const spn{args};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!spn.empty());
                    bsl::ut_check(!spn.is_invalid());
                };
            };
        };

        bsl::ut_scenario{"at_if"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::safe_i32> mut_spn{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_spn.at_if(0_idx) == nullptr);
                    bsl::ut_check(mut_spn.at_if(bsl::npos) == nullptr);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::safe_i32 const> const spn{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(spn.at_if(0_idx) == nullptr);
                    bsl::ut_check(spn.at_if(bsl::npos) == nullptr);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::cstr_type> mut_spn{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_spn.at_if(0_idx) == nullptr);
                    bsl::ut_check(mut_spn.at_if(bsl::npos) == nullptr);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::cstr_type const> const spn{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(spn.at_if(0_idx) == nullptr);
                    bsl::ut_check(spn.at_if(bsl::npos) == nullptr);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span mut_spn{mut_arr.data(), 0_umx};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_spn.at_if(0_idx) == nullptr);
                    bsl::ut_check(mut_spn.at_if(bsl::npos) == nullptr);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span const spn{arr.data(), 0_umx};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(spn.at_if(0_idx) == nullptr);
                    bsl::ut_check(spn.at_if(bsl::npos) == nullptr);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span mut_spn{mut_args.data(), 0_umx};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_spn.at_if(0_idx) == nullptr);
                    bsl::ut_check(mut_spn.at_if(bsl::npos) == nullptr);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span const spn{args.data(), 0_umx};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(spn.at_if(0_idx) == nullptr);
                    bsl::ut_check(spn.at_if(bsl::npos) == nullptr);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span mut_spn{mut_arr};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(*mut_spn.at_if(0_idx) == 4_i32);
                    bsl::ut_check(*mut_spn.at_if(1_idx) == 8_i32);
                    bsl::ut_check(*mut_spn.at_if(2_idx) == 15_i32);
                    bsl::ut_check(*mut_spn.at_if(3_idx) == 16_i32);
                    bsl::ut_check(*mut_spn.at_if(4_idx) == 23_i32);
                    bsl::ut_check(*mut_spn.at_if(5_idx) == 42_i32);
                    bsl::ut_check(mut_spn.at_if(bsl::npos) == nullptr);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span const spn{arr};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(*spn.at_if(0_idx) == 4_i32);
                    bsl::ut_check(*spn.at_if(1_idx) == 8_i32);
                    bsl::ut_check(*spn.at_if(2_idx) == 15_i32);
                    bsl::ut_check(*spn.at_if(3_idx) == 16_i32);
                    bsl::ut_check(*spn.at_if(4_idx) == 23_i32);
                    bsl::ut_check(*spn.at_if(5_idx) == 42_i32);
                    bsl::ut_check(spn.at_if(bsl::npos) == nullptr);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span mut_spn{mut_args};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(*mut_spn.at_if(0_idx) == bsl::string_view{"-app=ignored"});
                    bsl::ut_check(*mut_spn.at_if(1_idx) == bsl::string_view{"pos1"});
                    bsl::ut_check(*mut_spn.at_if(2_idx) == bsl::string_view{"-4=16"});
                    bsl::ut_check(*mut_spn.at_if(3_idx) == bsl::string_view{"-8=23"});
                    bsl::ut_check(*mut_spn.at_if(4_idx) == bsl::string_view{"pos2"});
                    bsl::ut_check(*mut_spn.at_if(5_idx) == bsl::string_view{"-15=42"});
                    bsl::ut_check(*mut_spn.at_if(6_idx) == bsl::string_view{"-app=42"});
                    bsl::ut_check(*mut_spn.at_if(7_idx) == bsl::string_view{"-app=42"});
                    bsl::ut_check(*mut_spn.at_if(8_idx) == bsl::string_view{"-app=42"});
                    bsl::ut_check(mut_spn.at_if(bsl::npos) == nullptr);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span const spn{args};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(*spn.at_if(0_idx) == bsl::string_view{"-app=ignored"});
                    bsl::ut_check(*spn.at_if(1_idx) == bsl::string_view{"pos1"});
                    bsl::ut_check(*spn.at_if(2_idx) == bsl::string_view{"-4=16"});
                    bsl::ut_check(*spn.at_if(3_idx) == bsl::string_view{"-8=23"});
                    bsl::ut_check(*spn.at_if(4_idx) == bsl::string_view{"pos2"});
                    bsl::ut_check(*spn.at_if(5_idx) == bsl::string_view{"-15=42"});
                    bsl::ut_check(*spn.at_if(6_idx) == bsl::string_view{"-app=42"});
                    bsl::ut_check(*spn.at_if(7_idx) == bsl::string_view{"-app=42"});
                    bsl::ut_check(*spn.at_if(8_idx) == bsl::string_view{"-app=42"});
                    bsl::ut_check(spn.at_if(bsl::npos) == nullptr);
                };
            };
        };

        bsl::ut_scenario{"front_if"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::safe_i32> mut_spn{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_spn.front_if() == nullptr);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::safe_i32 const> const spn{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(spn.front_if() == nullptr);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::cstr_type> mut_spn{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_spn.front_if() == nullptr);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::cstr_type const> const spn{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(spn.front_if() == nullptr);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span mut_spn{mut_arr};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(*mut_spn.front_if() == 4_i32);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span const spn{arr};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(*spn.front_if() == 4_i32);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span mut_spn{mut_args};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(*mut_spn.front_if() == bsl::string_view{"-app=ignored"});
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span const spn{args};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(*spn.front_if() == bsl::string_view{"-app=ignored"});
                };
            };
        };

        bsl::ut_scenario{"back_if"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::safe_i32> mut_spn{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_spn.back_if() == nullptr);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::safe_i32 const> const spn{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(spn.back_if() == nullptr);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::cstr_type> mut_spn{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_spn.back_if() == nullptr);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::cstr_type const> const spn{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(spn.back_if() == nullptr);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span mut_spn{mut_arr};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(*mut_spn.back_if() == 42_i32);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span const spn{arr};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(*spn.back_if() == 42_i32);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span mut_spn{mut_args};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(*mut_spn.back_if() == bsl::string_view{"-app=42"});
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span const spn{args};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(*spn.back_if() == bsl::string_view{"-app=42"});
                };
            };
        };

        bsl::ut_scenario{"data"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::safe_i32> mut_spn{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_spn.data() == nullptr);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::safe_i32 const> const spn{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(spn.data() == nullptr);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::cstr_type> mut_spn{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_spn.data() == nullptr);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::cstr_type const> const spn{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(spn.data() == nullptr);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span mut_spn{mut_arr};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_spn.data() != nullptr);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span const spn{arr};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(spn.data() != nullptr);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span mut_spn{mut_args};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_spn.data() != nullptr);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span const spn{args};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(spn.data() != nullptr);
                };
            };
        };

        bsl::ut_scenario{"begin"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::safe_i32> mut_spn{};
                bsl::ut_then{} = [&]() noexcept {
                    auto mut_ci{mut_spn.begin()};
                    bsl::ut_check(mut_ci.is_invalid());
                    bsl::ut_check(mut_ci.get_if() == nullptr);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::safe_i32 const> const spn{};
                bsl::ut_then{} = [&]() noexcept {
                    auto const ci{spn.begin()};
                    bsl::ut_check(ci.is_invalid());
                    bsl::ut_check(ci.get_if() == nullptr);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::safe_i32 const> const spn{};
                bsl::ut_then{} = [&]() noexcept {
                    auto const ci{spn.cbegin()};
                    bsl::ut_check(ci.is_invalid());
                    bsl::ut_check(ci.get_if() == nullptr);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::cstr_type> mut_spn{};
                bsl::ut_then{} = [&]() noexcept {
                    auto mut_ci{mut_spn.begin()};
                    bsl::ut_check(mut_ci.is_invalid());
                    bsl::ut_check(mut_ci.get_if() == nullptr);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::cstr_type const> const spn{};
                bsl::ut_then{} = [&]() noexcept {
                    auto const ci{spn.begin()};
                    bsl::ut_check(ci.is_invalid());
                    bsl::ut_check(ci.get_if() == nullptr);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::cstr_type const> const spn{};
                bsl::ut_then{} = [&]() noexcept {
                    auto const ci{spn.cbegin()};
                    bsl::ut_check(ci.is_invalid());
                    bsl::ut_check(ci.get_if() == nullptr);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span mut_spn{mut_arr};
                bsl::ut_then{} = [&]() noexcept {
                    auto mut_ci{mut_spn.begin()};
                    bsl::ut_check(*(mut_ci.get_if()) == 4_i32);
                    bsl::ut_check(mut_ci.index() == 0_umx);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span const spn{arr};
                bsl::ut_then{} = [&]() noexcept {
                    auto const ci{spn.begin()};
                    bsl::ut_check(*(ci.get_if()) == 4_i32);
                    bsl::ut_check(ci.index() == 0_umx);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span const spn{arr};
                bsl::ut_then{} = [&]() noexcept {
                    auto const ci{spn.cbegin()};
                    bsl::ut_check(*(ci.get_if()) == 4_i32);
                    bsl::ut_check(ci.index() == 0_umx);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span mut_spn{mut_args};
                bsl::ut_then{} = [&]() noexcept {
                    auto mut_ci{mut_spn.begin()};
                    bsl::ut_check(*(mut_ci.get_if()) == bsl::string_view{"-app=ignored"});
                    bsl::ut_check(mut_ci.index() == 0_umx);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span const spn{args};
                bsl::ut_then{} = [&]() noexcept {
                    auto const ci{spn.cbegin()};
                    bsl::ut_check(*(ci.get_if()) == bsl::string_view{"-app=ignored"});
                    bsl::ut_check(ci.index() == 0_umx);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span const spn{args};
                bsl::ut_then{} = [&]() noexcept {
                    auto const ci{spn.cbegin()};
                    bsl::ut_check(*(ci.get_if()) == bsl::string_view{"-app=ignored"});
                    bsl::ut_check(ci.index() == 0_umx);
                };
            };
        };

        bsl::ut_scenario{"end"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::safe_i32> mut_spn{};
                bsl::ut_then{} = [&]() noexcept {
                    auto mut_ci{mut_spn.end()};
                    bsl::ut_check(mut_ci.is_invalid());
                    bsl::ut_check(mut_ci.get_if() == nullptr);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::safe_i32 const> const spn{};
                bsl::ut_then{} = [&]() noexcept {
                    auto const ci{spn.end()};
                    bsl::ut_check(ci.is_invalid());
                    bsl::ut_check(ci.get_if() == nullptr);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::safe_i32 const> const spn{};
                bsl::ut_then{} = [&]() noexcept {
                    auto const ci{spn.cend()};
                    bsl::ut_check(ci.is_invalid());
                    bsl::ut_check(ci.get_if() == nullptr);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::cstr_type> mut_spn{};
                bsl::ut_then{} = [&]() noexcept {
                    auto mut_ci{mut_spn.end()};
                    bsl::ut_check(mut_ci.is_invalid());
                    bsl::ut_check(mut_ci.get_if() == nullptr);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::cstr_type const> const spn{};
                bsl::ut_then{} = [&]() noexcept {
                    auto const ci{spn.end()};
                    bsl::ut_check(ci.is_invalid());
                    bsl::ut_check(ci.get_if() == nullptr);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::cstr_type const> const spn{};
                bsl::ut_then{} = [&]() noexcept {
                    auto const ci{spn.cend()};
                    bsl::ut_check(ci.is_invalid());
                    bsl::ut_check(ci.get_if() == nullptr);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span mut_spn{mut_arr};
                bsl::ut_then{} = [&]() noexcept {
                    auto mut_ci{mut_spn.end()};
                    bsl::ut_check(mut_ci.index() == mut_spn.size());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span const spn{arr};
                bsl::ut_then{} = [&]() noexcept {
                    auto const ci{spn.end()};
                    bsl::ut_check(ci.index() == spn.size());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span const spn{arr};
                bsl::ut_then{} = [&]() noexcept {
                    auto const ci{spn.cend()};
                    bsl::ut_check(ci.index() == spn.size());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span mut_spn{mut_args};
                bsl::ut_then{} = [&]() noexcept {
                    auto mut_ci{mut_spn.end()};
                    bsl::ut_check(mut_ci.index() == mut_spn.size());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span const spn{args};
                bsl::ut_then{} = [&]() noexcept {
                    auto const ci{spn.end()};
                    bsl::ut_check(ci.index() == spn.size());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span const spn{args};
                bsl::ut_then{} = [&]() noexcept {
                    auto const ci{spn.cend()};
                    bsl::ut_check(ci.index() == spn.size());
                };
            };
        };

        bsl::ut_scenario{"rbegin"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::safe_i32> mut_spn{};
                bsl::ut_then{} = [&]() noexcept {
                    auto mut_ri{mut_spn.rbegin()};
                    bsl::ut_check(mut_ri.is_invalid());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::safe_i32 const> const spn{};
                bsl::ut_then{} = [&]() noexcept {
                    auto const ri{spn.rbegin()};
                    bsl::ut_check(ri.is_invalid());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::safe_i32 const> const spn{};
                bsl::ut_then{} = [&]() noexcept {
                    auto const ri{spn.crbegin()};
                    bsl::ut_check(ri.is_invalid());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::cstr_type> mut_spn{};
                bsl::ut_then{} = [&]() noexcept {
                    auto mut_ri{mut_spn.rbegin()};
                    bsl::ut_check(mut_ri.is_invalid());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::cstr_type const> const spn{};
                bsl::ut_then{} = [&]() noexcept {
                    auto const ri{spn.rbegin()};
                    bsl::ut_check(ri.is_invalid());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::cstr_type const> const spn{};
                bsl::ut_then{} = [&]() noexcept {
                    auto const ri{spn.crbegin()};
                    bsl::ut_check(ri.is_invalid());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span mut_spn{mut_arr};
                bsl::ut_then{} = [&]() noexcept {
                    auto mut_ri{mut_spn.rbegin()};
                    bsl::ut_check(*(mut_ri.get_if()) == 42_i32);
                    bsl::ut_check(mut_ri.index() == 5_umx);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span const spn{arr};
                bsl::ut_then{} = [&]() noexcept {
                    auto const ri{spn.rbegin()};
                    bsl::ut_check(*(ri.get_if()) == 42_i32);
                    bsl::ut_check(ri.index() == 5_umx);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span const spn{arr};
                bsl::ut_then{} = [&]() noexcept {
                    auto const ri{spn.crbegin()};
                    bsl::ut_check(*(ri.get_if()) == 42_i32);
                    bsl::ut_check(ri.index() == 5_umx);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span mut_spn{mut_args};
                bsl::ut_then{} = [&]() noexcept {
                    auto mut_ri{mut_spn.rbegin()};
                    bsl::ut_check(*(mut_ri.get_if()) == bsl::string_view{"-app=42"});
                    bsl::ut_check(mut_ri.index() == 8_umx);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span const spn{args};
                bsl::ut_then{} = [&]() noexcept {
                    auto const ri{spn.rbegin()};
                    bsl::ut_check(*(ri.get_if()) == bsl::string_view{"-app=42"});
                    bsl::ut_check(ri.index() == 8_umx);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span const spn{args};
                bsl::ut_then{} = [&]() noexcept {
                    auto const ri{spn.crbegin()};
                    bsl::ut_check(*(ri.get_if()) == bsl::string_view{"-app=42"});
                    bsl::ut_check(ri.index() == 8_umx);
                };
            };
        };

        bsl::ut_scenario{"rend"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::safe_i32> mut_spn{};
                bsl::ut_then{} = [&]() noexcept {
                    auto mut_ri{mut_spn.rend()};
                    bsl::ut_check(mut_ri.is_invalid());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::safe_i32 const> const spn{};
                bsl::ut_then{} = [&]() noexcept {
                    auto const ri{spn.rend()};
                    bsl::ut_check(ri.is_invalid());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::safe_i32 const> const spn{};
                bsl::ut_then{} = [&]() noexcept {
                    auto const ri{spn.crend()};
                    bsl::ut_check(ri.is_invalid());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::cstr_type> mut_spn{};
                bsl::ut_then{} = [&]() noexcept {
                    auto mut_ri{mut_spn.rend()};
                    bsl::ut_check(mut_ri.is_invalid());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::cstr_type const> const spn{};
                bsl::ut_then{} = [&]() noexcept {
                    auto const ri{spn.rend()};
                    bsl::ut_check(ri.is_invalid());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::cstr_type const> const spn{};
                bsl::ut_then{} = [&]() noexcept {
                    auto const ri{spn.crend()};
                    bsl::ut_check(ri.is_invalid());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span mut_spn{mut_arr};
                bsl::ut_then{} = [&]() noexcept {
                    auto mut_ri{mut_spn.rend()};
                    bsl::ut_check(mut_ri.index() == mut_spn.size());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span const spn{arr};
                bsl::ut_then{} = [&]() noexcept {
                    auto const ri{spn.rend()};
                    bsl::ut_check(ri.index() == spn.size());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span const spn{arr};
                bsl::ut_then{} = [&]() noexcept {
                    auto const ri{spn.crend()};
                    bsl::ut_check(ri.index() == spn.size());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span mut_spn{mut_args};
                bsl::ut_then{} = [&]() noexcept {
                    auto mut_ri{mut_spn.rend()};
                    bsl::ut_check(mut_ri.index() == mut_spn.size());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span const spn{args};
                bsl::ut_then{} = [&]() noexcept {
                    auto const ri{spn.rend()};
                    bsl::ut_check(ri.index() == spn.size());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span const spn{args};
                bsl::ut_then{} = [&]() noexcept {
                    auto const ri{spn.crend()};
                    bsl::ut_check(ri.index() == spn.size());
                };
            };
        };

        bsl::ut_scenario{"empty"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::safe_i32> mut_spn{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_spn.empty());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::safe_i32 const> const spn{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(spn.empty());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::cstr_type> mut_spn{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_spn.empty());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::cstr_type const> const spn{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(spn.empty());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::safe_i32> mut_spn{mut_arr.data(), 0_umx};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_spn.empty());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::safe_i32 const> const spn{arr.data(), 0_umx};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(spn.empty());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::cstr_type> mut_spn{mut_args.data(), 0_umx};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_spn.empty());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::cstr_type const> const spn{args.data(), 0_umx};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(spn.empty());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span mut_spn{mut_arr};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!mut_spn.empty());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span const spn{arr};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!spn.empty());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span mut_spn{mut_args};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!mut_spn.empty());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span const spn{args};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!spn.empty());
                };
            };
        };

        bsl::ut_scenario{"is_invalid"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::safe_i32> mut_spn{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_spn.is_invalid());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::safe_i32 const> const spn{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(spn.is_invalid());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::cstr_type> mut_spn{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_spn.is_invalid());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::cstr_type const> const spn{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(spn.is_invalid());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::safe_i32> mut_spn{mut_arr.data(), 0_umx};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!mut_spn.is_invalid());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::safe_i32 const> const spn{arr.data(), 0_umx};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!spn.is_invalid());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::cstr_type> mut_spn{mut_args.data(), 0_umx};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!mut_spn.is_invalid());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::cstr_type const> const spn{args.data(), 0_umx};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!spn.is_invalid());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span mut_spn{mut_arr};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!mut_spn.is_invalid());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span const spn{arr};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!spn.is_invalid());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span mut_spn{mut_args};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!mut_spn.is_invalid());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span const spn{args};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!spn.is_invalid());
                };
            };
        };

        bsl::ut_scenario{"is_valid"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::safe_i32> mut_spn{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!mut_spn.is_valid());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::safe_i32 const> const spn{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!spn.is_valid());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::cstr_type> mut_spn{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!mut_spn.is_valid());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::cstr_type const> const spn{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!spn.is_valid());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::safe_i32> mut_spn{mut_arr.data(), 0_umx};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_spn.is_valid());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::safe_i32 const> const spn{arr.data(), 0_umx};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(spn.is_valid());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::cstr_type> mut_spn{mut_args.data(), 0_umx};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_spn.is_valid());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::cstr_type const> const spn{args.data(), 0_umx};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(spn.is_valid());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span mut_spn{mut_arr};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_spn.is_valid());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span const spn{arr};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(spn.is_valid());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span mut_spn{mut_args};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_spn.is_valid());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span const spn{args};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(spn.is_valid());
                };
            };
        };

        bsl::ut_scenario{"size"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::safe_i32> mut_spn{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_spn.size() == 0_umx);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::safe_i32 const> const spn{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(spn.size() == 0_umx);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::cstr_type> mut_spn{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_spn.size() == 0_umx);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::cstr_type const> const spn{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(spn.size() == 0_umx);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span mut_spn{mut_arr};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_spn.size() == 6_umx);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span const spn{arr};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(spn.size() == 6_umx);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span mut_spn{mut_args};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_spn.size() == 9_umx);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span const spn{args};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(spn.size() == 9_umx);
                };
            };
        };

        bsl::ut_scenario{"max_size"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::safe_i32> mut_spn{};
                bsl::ut_then{} = [&]() noexcept {
                    constexpr auto expected{bsl::safe_umx::max_value() / sizeof(bsl::safe_i32)};
                    bsl::ut_check(mut_spn.max_size() == expected.checked());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::safe_i32 const> const spn{};
                bsl::ut_then{} = [&]() noexcept {
                    constexpr auto expected{bsl::safe_umx::max_value() / sizeof(bsl::safe_i32)};
                    bsl::ut_check(spn.max_size() == expected.checked());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::cstr_type> mut_spn{};
                bsl::ut_then{} = [&]() noexcept {
                    constexpr auto expected{bsl::safe_umx::max_value() / sizeof(bsl::cstr_type)};
                    bsl::ut_check(mut_spn.max_size() == expected.checked());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::cstr_type const> const spn{};
                bsl::ut_then{} = [&]() noexcept {
                    constexpr auto expected{bsl::safe_umx::max_value() / sizeof(bsl::cstr_type)};
                    bsl::ut_check(spn.max_size() == expected.checked());
                };
            };
        };

        bsl::ut_scenario{"size_bytes"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::safe_i32> mut_spn{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_spn.size_bytes() == 0_umx);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::safe_i32 const> const spn{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(spn.size_bytes() == 0_umx);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::cstr_type> mut_spn{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_spn.size_bytes() == 0_umx);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::cstr_type const> const spn{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(spn.size_bytes() == 0_umx);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span mut_spn{mut_arr};
                bsl::ut_then{} = [&]() noexcept {
                    constexpr auto expected{6_umx * sizeof(bsl::safe_i32)};
                    bsl::ut_check(mut_spn.size_bytes() == expected.checked());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span const spn{arr};
                bsl::ut_then{} = [&]() noexcept {
                    constexpr auto expected{6_umx * sizeof(bsl::safe_i32)};
                    bsl::ut_check(spn.size_bytes() == expected.checked());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span mut_spn{mut_args};
                bsl::ut_then{} = [&]() noexcept {
                    constexpr auto expected{9_umx * sizeof(bsl::cstr_type)};
                    bsl::ut_check(mut_spn.size_bytes() == expected.checked());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span const spn{args};
                bsl::ut_then{} = [&]() noexcept {
                    constexpr auto expected{9_umx * sizeof(bsl::cstr_type)};
                    bsl::ut_check(spn.size_bytes() == expected.checked());
                };
            };
        };

        bsl::ut_scenario{"first"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::safe_i32> mut_spn{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_spn.first().is_invalid());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::safe_i32 const> const spn{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(spn.first().is_invalid());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::cstr_type> mut_spn{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_spn.first().is_invalid());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::cstr_type const> const spn{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(spn.first().is_invalid());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::safe_i32> mut_spn{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_spn.first(3_umx).is_invalid());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::safe_i32 const> const spn{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(spn.first(3_umx).is_invalid());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::cstr_type> mut_spn{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_spn.first(3_umx).is_invalid());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::cstr_type const> const spn{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(spn.first(3_umx).is_invalid());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span mut_spn{mut_arr};
                auto mut_sub{mut_spn.first()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(*mut_sub.front_if() == *mut_arr.front_if());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span const spn{arr};
                auto const sub{spn.first()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(*sub.front_if() == *arr.front_if());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span mut_spn{mut_args};
                auto mut_sub{mut_spn.first()};
                bsl::ut_then{} = [&]() noexcept {
                    auto const expected{bsl::string_view{*mut_args.at_if((0_idx).get())}};
                    bsl::ut_check(*mut_sub.front_if() == expected);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span const spn{args};
                auto const sub{spn.first()};
                bsl::ut_then{} = [&]() noexcept {
                    auto const expected{bsl::string_view{*args.at_if((0_idx).get())}};
                    bsl::ut_check(*sub.front_if() == expected);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span mut_spn{mut_arr};
                auto mut_sub{mut_spn.first(3_umx)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(*mut_sub.front_if() == *mut_arr.at_if((0_idx)));
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span const spn{arr};
                auto const sub{spn.first(3_umx)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(*sub.front_if() == *arr.at_if((0_idx)));
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span mut_spn{mut_args};
                auto mut_sub{mut_spn.first(3_umx)};
                bsl::ut_then{} = [&]() noexcept {
                    auto const expected{bsl::string_view{*mut_args.at_if((0_idx).get())}};
                    bsl::ut_check(*mut_sub.front_if() == expected);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span const spn{args};
                auto const sub{spn.first(3_umx)};
                bsl::ut_then{} = [&]() noexcept {
                    auto const expected{bsl::string_view{*args.at_if((0_idx).get())}};
                    bsl::ut_check(*sub.front_if() == expected);
                };
            };
        };

        bsl::ut_scenario{"last"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::safe_i32> mut_spn{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_spn.last().is_invalid());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::safe_i32 const> const spn{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(spn.last().is_invalid());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::cstr_type> mut_spn{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_spn.last().is_invalid());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::cstr_type const> const spn{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(spn.last().is_invalid());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::safe_i32> mut_spn{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_spn.last(3_umx).is_invalid());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::safe_i32 const> const spn{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(spn.last(3_umx).is_invalid());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::cstr_type> mut_spn{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_spn.last(3_umx).is_invalid());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::cstr_type const> const spn{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(spn.last(3_umx).is_invalid());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span mut_spn{mut_arr};
                auto mut_sub{mut_spn.last()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(*mut_sub.front_if() == *mut_arr.front_if());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span const spn{arr};
                auto const sub{spn.last()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(*sub.front_if() == *arr.front_if());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span mut_spn{mut_args};
                auto mut_sub{mut_spn.last()};
                bsl::ut_then{} = [&]() noexcept {
                    auto const expected{bsl::string_view{*mut_args.at_if((0_idx).get())}};
                    bsl::ut_check(*mut_sub.front_if() == expected);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span const spn{args};
                auto const sub{spn.last()};
                bsl::ut_then{} = [&]() noexcept {
                    auto const expected{bsl::string_view{*args.at_if((0_idx).get())}};
                    bsl::ut_check(*sub.front_if() == expected);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span mut_spn{mut_arr};
                auto mut_sub{mut_spn.last(3_umx)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(*mut_sub.front_if() == *mut_arr.at_if((3_idx)));
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span const spn{arr};
                auto const sub{spn.last(3_umx)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(*sub.front_if() == *arr.at_if((3_idx)));
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span mut_spn{mut_args};
                auto mut_sub{mut_spn.last(3_umx)};
                bsl::ut_then{} = [&]() noexcept {
                    auto const expected{bsl::string_view{*mut_args.at_if((6_idx).get())}};
                    bsl::ut_check(*mut_sub.front_if() == expected);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span const spn{args};
                auto const sub{spn.last(3_umx)};
                bsl::ut_then{} = [&]() noexcept {
                    auto const expected{bsl::string_view{*args.at_if((6_idx).get())}};
                    bsl::ut_check(*sub.front_if() == expected);
                };
            };
        };

        bsl::ut_scenario{"subspan"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::safe_i32> mut_spn{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_spn.subspan(0_idx).is_invalid());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::safe_i32 const> const spn{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(spn.subspan(0_idx).is_invalid());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::cstr_type> mut_spn{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_spn.subspan(0_idx).is_invalid());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::cstr_type const> const spn{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(spn.subspan(0_idx).is_invalid());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::safe_i32> mut_spn{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_spn.subspan(3_idx).is_invalid());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::safe_i32 const> const spn{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(spn.subspan(3_idx).is_invalid());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::cstr_type> mut_spn{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_spn.subspan(3_idx).is_invalid());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::cstr_type const> const spn{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(spn.subspan(3_idx).is_invalid());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span mut_spn{mut_arr};
                auto mut_sub{mut_spn.subspan(0_idx)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(*mut_sub.front_if() == *mut_arr.front_if());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span const spn{arr};
                auto const sub{spn.subspan(0_idx)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(*sub.front_if() == *arr.front_if());
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span mut_spn{mut_args};
                auto mut_sub{mut_spn.subspan(0_idx)};
                bsl::ut_then{} = [&]() noexcept {
                    auto const expected{bsl::string_view{*mut_args.at_if((0_idx).get())}};
                    bsl::ut_check(*mut_sub.front_if() == expected);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span const spn{args};
                auto const sub{spn.subspan(0_idx)};
                bsl::ut_then{} = [&]() noexcept {
                    auto const expected{bsl::string_view{*args.at_if((0_idx).get())}};
                    bsl::ut_check(*sub.front_if() == expected);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span mut_spn{mut_arr};
                auto mut_sub{mut_spn.subspan(3_idx)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(*mut_sub.front_if() == *mut_arr.at_if((3_idx)));
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span const spn{arr};
                auto const sub{spn.subspan(3_idx)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(*sub.front_if() == *arr.at_if((3_idx)));
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span mut_spn{mut_args};
                auto mut_sub{mut_spn.subspan(3_idx)};
                bsl::ut_then{} = [&]() noexcept {
                    auto const expected{bsl::string_view{*mut_args.at_if((3_idx).get())}};
                    bsl::ut_check(*mut_sub.front_if() == expected);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span const spn{args};
                auto const sub{spn.subspan(3_idx)};
                bsl::ut_then{} = [&]() noexcept {
                    auto const expected{bsl::string_view{*args.at_if((3_idx).get())}};
                    bsl::ut_check(*sub.front_if() == expected);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span mut_spn{mut_arr};
                auto mut_sub{mut_spn.subspan(3_idx, 1_umx)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_sub.size() == 1_umx);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span const spn{arr};
                auto const sub{spn.subspan(3_idx, 1_umx)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(sub.size() == 1_umx);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span mut_spn{mut_args};
                auto mut_sub{mut_spn.subspan(3_idx, 1_umx)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_sub.size() == 1_umx);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span const spn{args};
                auto const sub{spn.subspan(3_idx, 1_umx)};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(sub.size() == 1_umx);
                };
            };
        };

        bsl::ut_scenario{"equals"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                auto mut_arr1{test::ARRAY_INIT};
                auto mut_arr2{test::ARRAY_INIT};
                bsl::span mut_spn1{mut_arr1};
                bsl::span mut_spn2{mut_arr2};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_spn1 == mut_spn2);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                auto const arr1{test::ARRAY_INIT};
                auto const arr2{test::ARRAY_INIT};
                bsl::span const spn1{arr1};
                bsl::span const spn2{arr2};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(spn1 == spn2);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                auto mut_arr1{test::ARRAY_INIT};
                auto mut_arr2{test::ARRAY_INIT_RANDOM};
                bsl::span mut_spn1{mut_arr1};
                bsl::span mut_spn2{mut_arr2};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(mut_spn1 == mut_spn2));
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                auto const arr1{test::ARRAY_INIT};
                auto const arr2{test::ARRAY_INIT_RANDOM};
                bsl::span const spn1{arr1};
                bsl::span const spn2{arr2};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(spn1 == spn2));
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                auto mut_arr1{test::ARRAY_INIT};
                auto mut_arr2{test::ARRAY_INIT_SIZE_OF_1};
                bsl::span mut_spn1{mut_arr1};
                bsl::span mut_spn2{mut_arr2};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(mut_spn1 == mut_spn2));
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                auto const arr1{test::ARRAY_INIT};
                auto const arr2{test::ARRAY_INIT_SIZE_OF_1};
                bsl::span const spn1{arr1};
                bsl::span const spn2{arr2};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(spn1 == spn2));
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                auto mut_arr1{test::ARRAY_INIT_SIZE_OF_1};
                auto mut_arr2{test::ARRAY_INIT};
                bsl::span mut_spn1{mut_arr1};
                bsl::span mut_spn2{mut_arr2};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(mut_spn1 == mut_spn2));
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                auto const arr1{test::ARRAY_INIT_SIZE_OF_1};
                auto const arr2{test::ARRAY_INIT};
                bsl::span const spn1{arr1};
                bsl::span const spn2{arr2};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(spn1 == spn2));
                };
            };
        };

        bsl::ut_scenario{"not equals"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                auto mut_arr1{test::ARRAY_INIT};
                auto mut_arr2{test::ARRAY_INIT};
                bsl::span mut_spn1{mut_arr1};
                bsl::span mut_spn2{mut_arr2};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(mut_spn1 != mut_spn2));
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                auto const arr1{test::ARRAY_INIT};
                auto const arr2{test::ARRAY_INIT};
                bsl::span const spn1{arr1};
                bsl::span const spn2{arr2};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!(spn1 != spn2));
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                auto mut_arr1{test::ARRAY_INIT};
                auto mut_arr2{test::ARRAY_INIT_RANDOM};
                bsl::span mut_spn1{mut_arr1};
                bsl::span mut_spn2{mut_arr2};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_spn1 != mut_spn2);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                auto const arr1{test::ARRAY_INIT};
                auto const arr2{test::ARRAY_INIT_RANDOM};
                bsl::span const spn1{arr1};
                bsl::span const spn2{arr2};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(spn1 != spn2);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                auto mut_arr1{test::ARRAY_INIT};
                auto mut_arr2{test::ARRAY_INIT_SIZE_OF_1};
                bsl::span mut_spn1{mut_arr1};
                bsl::span mut_spn2{mut_arr2};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_spn1 != mut_spn2);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                auto const arr1{test::ARRAY_INIT};
                auto const arr2{test::ARRAY_INIT_SIZE_OF_1};
                bsl::span const spn1{arr1};
                bsl::span const spn2{arr2};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(spn1 != spn2);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                auto mut_arr1{test::ARRAY_INIT_SIZE_OF_1};
                auto mut_arr2{test::ARRAY_INIT};
                bsl::span mut_spn1{mut_arr1};
                bsl::span mut_spn2{mut_arr2};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(mut_spn1 != mut_spn2);
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                auto const arr1{test::ARRAY_INIT_SIZE_OF_1};
                auto const arr2{test::ARRAY_INIT};
                bsl::span const spn1{arr1};
                bsl::span const spn2{arr2};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(spn1 != spn2);
                };
            };
        };

        bsl::ut_scenario{"output doesn't crash"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::safe_i32> mut_spn{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::debug() << mut_spn << '\n';
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::safe_i32 const> const spn{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::debug() << spn << '\n';
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::cstr_type> mut_spn{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::debug() << mut_spn << '\n';
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span<bsl::cstr_type const> const spn{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::debug() << spn << '\n';
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span mut_spn{mut_arr};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::debug() << mut_spn << '\n';
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span const spn{arr};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::debug() << spn << '\n';
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span mut_spn{mut_args};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::debug() << mut_spn << '\n';
                };
            };

            bsl::ut_given{} = [&]() noexcept {
                bsl::span const spn{args};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::debug() << spn << '\n';
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
