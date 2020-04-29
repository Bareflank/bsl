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

#include <bsl/array.hpp>
#include <bsl/npos.hpp>
#include <bsl/ut.hpp>

namespace
{
    struct aggregate final
    {
        bsl::safe_int32 m_data;
    };

    constexpr bool
    operator==(aggregate const &lhs, aggregate const &rhs) noexcept
    {
        return lhs.m_data == rhs.m_data;
    }

    constexpr bsl::array<bsl::safe_int32, 6> test_arr{
        bsl::to_i32(4),
        bsl::to_i32(8),
        bsl::to_i32(15),
        bsl::to_i32(16),
        bsl::to_i32(23),
        bsl::to_i32(42)};

    constexpr bsl::array<aggregate, 6> test_aggregate_arr{
        bsl::to_i32(4),
        bsl::to_i32(8),
        bsl::to_i32(15),
        bsl::to_i32(16),
        bsl::to_i32(23),
        bsl::to_i32(42)};
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
    using namespace bsl;

    bsl::ut_scenario{"at_if"} = []() {
        bsl::ut_given{} = []() {
            array<safe_int32, 6> arr = test_arr;
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(*arr.at_if(to_umax(0)) == to_i32(4));
                bsl::ut_check(*arr.at_if(to_umax(1)) == to_i32(8));
                bsl::ut_check(*arr.at_if(to_umax(2)) == to_i32(15));
                bsl::ut_check(*arr.at_if(to_umax(3)) == to_i32(16));
                bsl::ut_check(*arr.at_if(to_umax(4)) == to_i32(23));
                bsl::ut_check(*arr.at_if(to_umax(5)) == to_i32(42));
                bsl::ut_check(arr.at_if(to_umax(6)) == nullptr);
                bsl::ut_check(arr.at_if(npos) == nullptr);
                bsl::ut_check(arr.at_if(safe_uintmax::zero(true)) == nullptr);
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> const arr = test_arr;
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(*arr.at_if(to_umax(0)) == to_i32(4));
                bsl::ut_check(*arr.at_if(to_umax(1)) == to_i32(8));
                bsl::ut_check(*arr.at_if(to_umax(2)) == to_i32(15));
                bsl::ut_check(*arr.at_if(to_umax(3)) == to_i32(16));
                bsl::ut_check(*arr.at_if(to_umax(4)) == to_i32(23));
                bsl::ut_check(*arr.at_if(to_umax(5)) == to_i32(42));
                bsl::ut_check(arr.at_if(to_umax(6)) == nullptr);
                bsl::ut_check(arr.at_if(npos) == nullptr);
                bsl::ut_check(arr.at_if(safe_uintmax::zero(true)) == nullptr);
            };
        };
    };

    bsl::ut_scenario{"front"} = []() {
        bsl::ut_given{} = []() {
            array<safe_int32, 6> arr = test_arr;
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(arr.front() == to_i32(4));
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> const arr = test_arr;
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(arr.front() == to_i32(4));
            };
        };
    };

    bsl::ut_scenario{"front_if"} = []() {
        bsl::ut_given{} = []() {
            array<safe_int32, 6> arr = test_arr;
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(*arr.front_if() == to_i32(4));
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> const arr = test_arr;
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(*arr.front_if() == to_i32(4));
            };
        };
    };

    bsl::ut_scenario{"back"} = []() {
        bsl::ut_given{} = []() {
            array<safe_int32, 6> arr = test_arr;
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(arr.back() == to_i32(42));
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> const arr = test_arr;
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(arr.back() == to_i32(42));
            };
        };
    };

    bsl::ut_scenario{"back_if"} = []() {
        bsl::ut_given{} = []() {
            array<safe_int32, 6> arr = test_arr;
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(*arr.back_if() == to_i32(42));
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> const arr = test_arr;
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(*arr.back_if() == to_i32(42));
            };
        };
    };

    bsl::ut_scenario{"data"} = []() {
        bsl::ut_given{} = []() {
            array<safe_int32, 6> arr = test_arr;
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(arr.data() != nullptr);
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> const arr = test_arr;
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(arr.data() != nullptr);
            };
        };
    };

    bsl::ut_scenario{"begin"} = []() {
        bsl::ut_given{} = []() {
            array<safe_int32, 6> arr = test_arr;
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(*(arr.begin().get_if()) == to_i32(4));
                bsl::ut_check(arr.begin().index() == to_umax(0));
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> const arr = test_arr;
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(*(arr.begin().get_if()) == to_i32(4));
                bsl::ut_check(arr.begin().index() == to_umax(0));
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> const arr = test_arr;
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(*(arr.cbegin().get_if()) == to_i32(4));
                bsl::ut_check(arr.cbegin().index() == to_umax(0));
            };
        };
    };

    bsl::ut_scenario{"end"} = []() {
        bsl::ut_given{} = []() {
            array<safe_int32, 6> arr = test_arr;
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(arr.end().get_if() == nullptr);
                bsl::ut_check(arr.end().index() == arr.size());
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> const arr = test_arr;
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(arr.end().get_if() == nullptr);
                bsl::ut_check(arr.end().index() == arr.size());
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> const arr = test_arr;
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(arr.cend().get_if() == nullptr);
                bsl::ut_check(arr.cend().index() == arr.size());
            };
        };
    };

    bsl::ut_scenario{"iter"} = []() {
        bsl::ut_given{} = []() {
            array<safe_int32, 6> arr = test_arr;
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(*(arr.iter(to_umax(1)).get_if()) == to_i32(8));
                bsl::ut_check(arr.iter(to_umax(1)).index() == to_umax(1));
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> const arr = test_arr;
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(*(arr.iter(to_umax(1)).get_if()) == to_i32(8));
                bsl::ut_check(arr.iter(to_umax(1)).index() == to_umax(1));
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> const arr = test_arr;
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(*(arr.citer(to_umax(1)).get_if()) == to_i32(8));
                bsl::ut_check(arr.citer(to_umax(1)).index() == to_umax(1));
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> arr = test_arr;
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(arr.iter(bsl::npos).get_if() == nullptr);
                bsl::ut_check(arr.iter(bsl::npos).index() == arr.size());
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> const arr = test_arr;
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(arr.iter(bsl::npos).get_if() == nullptr);
                bsl::ut_check(arr.iter(bsl::npos).index() == arr.size());
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> const arr = test_arr;
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(arr.citer(bsl::npos).get_if() == nullptr);
                bsl::ut_check(arr.citer(bsl::npos).index() == arr.size());
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> arr = test_arr;
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(arr.iter(safe_uintmax::zero(true)).get_if() == nullptr);
                bsl::ut_check(arr.iter(safe_uintmax::zero(true)).index() == arr.size());
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> const arr = test_arr;
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(arr.iter(safe_uintmax::zero(true)).get_if() == nullptr);
                bsl::ut_check(arr.iter(safe_uintmax::zero(true)).index() == arr.size());
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> const arr = test_arr;
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(arr.citer(safe_uintmax::zero(true)).get_if() == nullptr);
                bsl::ut_check(arr.citer(safe_uintmax::zero(true)).index() == arr.size());
            };
        };
    };

    bsl::ut_scenario{"rbegin"} = []() {
        bsl::ut_given{} = []() {
            array<safe_int32, 6> arr = test_arr;
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(*(arr.rbegin().get_if()) == to_i32(42));
                bsl::ut_check(arr.rbegin().index() == to_umax(5));
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> const arr = test_arr;
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(*(arr.rbegin().get_if()) == to_i32(42));
                bsl::ut_check(arr.rbegin().index() == to_umax(5));
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> const arr = test_arr;
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(*(arr.crbegin().get_if()) == to_i32(42));
                bsl::ut_check(arr.crbegin().index() == to_umax(5));
            };
        };
    };

    bsl::ut_scenario{"rend"} = []() {
        bsl::ut_given{} = []() {
            array<safe_int32, 6> arr = test_arr;
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(arr.rend().get_if() == nullptr);
                bsl::ut_check(arr.rend().index() == arr.size());
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> const arr = test_arr;
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(arr.rend().get_if() == nullptr);
                bsl::ut_check(arr.rend().index() == arr.size());
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> const arr = test_arr;
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(arr.crend().get_if() == nullptr);
                bsl::ut_check(arr.crend().index() == arr.size());
            };
        };
    };

    bsl::ut_scenario{"riter"} = []() {
        bsl::ut_given{} = []() {
            array<safe_int32, 6> arr = test_arr;
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(*(arr.riter(to_umax(1)).get_if()) == to_i32(8));
                bsl::ut_check(arr.riter(to_umax(1)).index() == to_umax(1));
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> const arr = test_arr;
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(*(arr.riter(to_umax(1)).get_if()) == to_i32(8));
                bsl::ut_check(arr.riter(to_umax(1)).index() == to_umax(1));
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> const arr = test_arr;
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(*(arr.criter(to_umax(1)).get_if()) == to_i32(8));
                bsl::ut_check(arr.criter(to_umax(1)).index() == to_umax(1));
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> arr = test_arr;
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(*(arr.riter(bsl::npos).get_if()) == to_i32(42));
                bsl::ut_check(arr.riter(bsl::npos).index() == to_umax(5));
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> const arr = test_arr;
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(*(arr.riter(bsl::npos).get_if()) == to_i32(42));
                bsl::ut_check(arr.riter(bsl::npos).index() == to_umax(5));
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> const arr = test_arr;
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(*(arr.criter(bsl::npos).get_if()) == to_i32(42));
                bsl::ut_check(arr.criter(bsl::npos).index() == to_umax(5));
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> arr = test_arr;
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(*(arr.riter(safe_uintmax::zero(true)).get_if()) == to_i32(42));
                bsl::ut_check(arr.riter(safe_uintmax::zero(true)).index() == to_umax(5));
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> const arr = test_arr;
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(*(arr.riter(safe_uintmax::zero(true)).get_if()) == to_i32(42));
                bsl::ut_check(arr.riter(safe_uintmax::zero(true)).index() == to_umax(5));
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> const arr = test_arr;
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(*(arr.criter(safe_uintmax::zero(true)).get_if()) == to_i32(42));
                bsl::ut_check(arr.criter(safe_uintmax::zero(true)).index() == to_umax(5));
            };
        };
    };

    bsl::ut_scenario{"empty"} = []() {
        bsl::ut_given{} = []() {
            array<safe_int32, 6> arr = test_arr;
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(!arr.empty());
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> const arr = test_arr;
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(!arr.empty());
            };
        };
    };

    bsl::ut_scenario{"operator bool"} = []() {
        bsl::ut_given{} = []() {
            array<safe_int32, 6> arr = test_arr;
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(!!arr);
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> const arr = test_arr;
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(!!arr);
            };
        };
    };

    bsl::ut_scenario{"size"} = []() {
        bsl::ut_given{} = []() {
            array<safe_int32, 6> arr = test_arr;
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(arr.size() == to_umax(6));
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> const arr = test_arr;
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(arr.size() == to_umax(6));
            };
        };
    };

    bsl::ut_scenario{"max_size"} = []() {
        bsl::ut_given{} = []() {
            array<safe_int32, 6> arr = test_arr;
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(arr.max_size() == safe_uintmax::max() / sizeof(safe_int32));
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> const arr = test_arr;
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(arr.max_size() == safe_uintmax::max() / sizeof(safe_int32));
            };
        };
    };

    bsl::ut_scenario{"size_bytes"} = []() {
        bsl::ut_given{} = []() {
            array<safe_int32, 6> arr = test_arr;
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(arr.size_bytes() == to_umax(6) * sizeof(bsl::uintmax));
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> const arr = test_arr;
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(arr.size_bytes() == to_umax(6) * sizeof(bsl::uintmax));
            };
        };
    };

    bsl::ut_scenario{"equals"} = []() {
        bsl::ut_given{} = []() {
            array<safe_int32, 6> const arr1 = test_arr;
            array<safe_int32, 6> const arr2 = test_arr;
            bsl::ut_then{} = [&arr1, &arr2]() {
                bsl::ut_check(arr1 == arr2);
            };
        };
    };

    bsl::ut_scenario{"equals"} = []() {
        bsl::ut_given{} = []() {
            bsl::array<aggregate, 6> const arr1 = test_aggregate_arr;
            bsl::array<aggregate, 6> const arr2 = test_aggregate_arr;
            bsl::ut_then{} = [&arr1, &arr2]() {
                bsl::ut_check(arr1 == arr2);
            };
        };
    };

    bsl::ut_scenario{"not equals"} = []() {
        bsl::ut_given{} = []() {
            array<safe_int32, 6> const arr1 = test_arr;
            array<safe_int32, 6> const arr2 = {};
            bsl::ut_then{} = [&arr1, &arr2]() {
                bsl::ut_check(arr1 != arr2);
            };
        };
    };

    bsl::ut_scenario{"not equals"} = []() {
        bsl::ut_given{} = []() {
            bsl::array<aggregate, 6> const arr1 = test_aggregate_arr;
            bsl::array<aggregate, 6> const arr2 = {};
            bsl::ut_then{} = [&arr1, &arr2]() {
                bsl::ut_check(arr1 != arr2);
            };
        };
    };

    bsl::ut_scenario{"output doesn't crash"} = []() {
        bsl::ut_given{} = []() {
            bsl::array<safe_int32, 1> const arr = {to_i32(42)};
            bsl::ut_then{} = [&arr]() {
                bsl::debug() << arr << '\n';
            };
        };

        bsl::ut_given{} = []() {
            array<safe_int32, 6> const arr = test_arr;
            bsl::ut_then{} = [&arr]() {
                bsl::debug() << arr << '\n';
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
