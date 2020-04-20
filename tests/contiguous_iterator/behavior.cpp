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

#include <bsl/contiguous_iterator.hpp>
#include <bsl/array.hpp>
#include <bsl/npos.hpp>
#include <bsl/ut.hpp>

namespace
{
    constexpr bsl::array<bsl::safe_int32, 6> arr{
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

    bsl::ut_scenario{"constructor"} = []() {
        bsl::ut_given{} = []() {
            contiguous_iterator<bool> ci{nullptr, arr.size(), to_umax(0)};
            bsl::ut_then{} = [&ci]() {
                bsl::ut_check(ci.empty());
            };
        };

        bsl::ut_given{} = []() {
            contiguous_iterator ci{arr.data(), to_umax(0), to_umax(0)};
            bsl::ut_then{} = [&ci]() {
                bsl::ut_check(ci.empty());
            };
        };

        bsl::ut_given{} = []() {
            contiguous_iterator ci{arr.data(), arr.size(), to_umax(0)};
            bsl::ut_then{} = [&ci]() {
                bsl::ut_check(ci.data() == arr.data());
                bsl::ut_check(ci.size() == arr.size());
                bsl::ut_check(ci.index() == to_umax(0));
            };
        };

        bsl::ut_given{} = []() {
            contiguous_iterator ci{arr.data(), arr.size(), npos};
            bsl::ut_then{} = [&ci]() {
                bsl::ut_check(ci.data() == arr.data());
                bsl::ut_check(ci.size() == arr.size());
                bsl::ut_check(ci.index() == arr.size());
            };
        };
    };

    bsl::ut_scenario{"data"} = []() {
        bsl::ut_given{} = []() {
            contiguous_iterator<bool> ci{nullptr, to_umax(0), to_umax(0)};
            bsl::ut_then{} = [&ci]() {
                bsl::ut_check(ci.data() == nullptr);
            };
        };

        bsl::ut_given{} = []() {
            contiguous_iterator ci{arr.data(), arr.size(), to_umax(0)};
            bsl::ut_then{} = [&ci]() {
                bsl::ut_check(ci.data() == arr.data());
            };
        };

        bsl::ut_given{} = []() {
            contiguous_iterator const ci{arr.data(), arr.size(), to_umax(0)};
            bsl::ut_then{} = [&ci]() {
                bsl::ut_check(ci.data() == arr.data());
            };
        };
    };

    bsl::ut_scenario{"size"} = []() {
        bsl::ut_given{} = []() {
            contiguous_iterator<bool> ci{nullptr, to_umax(0), to_umax(0)};
            bsl::ut_then{} = [&ci]() {
                bsl::ut_check(ci.size() == to_umax(0));    // NOLINT
            };
        };

        bsl::ut_given{} = []() {
            contiguous_iterator ci{arr.data(), arr.size(), to_umax(0)};
            bsl::ut_then{} = [&ci]() {
                bsl::ut_check(ci.size() == arr.size());
            };
        };
    };

    bsl::ut_scenario{"index"} = []() {
        bsl::ut_given{} = []() {
            contiguous_iterator<bool> ci{nullptr, to_umax(0), to_umax(0)};
            bsl::ut_then{} = [&ci]() {
                bsl::ut_check(ci.index() == to_umax(0));
            };
        };

        bsl::ut_given{} = []() {
            contiguous_iterator ci{arr.data(), arr.size(), to_umax(0)};
            bsl::ut_then{} = [&ci]() {
                bsl::ut_check(ci.index() == to_umax(0));
            };
        };

        bsl::ut_given{} = []() {
            contiguous_iterator ci{arr.data(), arr.size(), arr.size()};
            bsl::ut_then{} = [&ci]() {
                bsl::ut_check(ci.index() == arr.size());
            };
        };

        bsl::ut_given{} = []() {
            contiguous_iterator ci{arr.data(), arr.size(), npos};
            bsl::ut_then{} = [&ci]() {
                bsl::ut_check(ci.index() == arr.size());
            };
        };
    };

    bsl::ut_scenario{"empty"} = []() {
        bsl::ut_given{} = []() {
            contiguous_iterator<bool> ci{nullptr, to_umax(0), to_umax(0)};
            bsl::ut_then{} = [&ci]() {
                bsl::ut_check(ci.empty());
            };
        };

        bsl::ut_given{} = []() {
            contiguous_iterator ci{arr.data(), arr.size(), to_umax(0)};
            bsl::ut_then{} = [&ci]() {
                bsl::ut_check(!ci.empty());
            };
        };
    };

    bsl::ut_scenario{"is_end"} = []() {
        bsl::ut_given{} = []() {
            contiguous_iterator<bool> ci{nullptr, to_umax(0), to_umax(0)};
            bsl::ut_then{} = [&ci]() {
                bsl::ut_check(ci.is_end());
            };
        };

        bsl::ut_given{} = []() {
            contiguous_iterator ci{arr.data(), arr.size(), arr.size()};
            bsl::ut_then{} = [&ci]() {
                bsl::ut_check(ci.is_end());
            };
        };

        bsl::ut_given{} = []() {
            contiguous_iterator ci{arr.data(), arr.size(), to_umax(0)};
            bsl::ut_then{} = [&ci]() {
                bsl::ut_check(!ci.is_end());
            };
        };
    };

    bsl::ut_scenario{"get_if"} = []() {
        bsl::ut_given{} = []() {
            contiguous_iterator<bool> ci{nullptr, to_umax(0), to_umax(0)};
            bsl::ut_then{} = [&ci]() {
                bsl::ut_check(ci.get_if() == nullptr);
            };
        };

        bsl::ut_given{} = []() {
            contiguous_iterator<bool> const ci{nullptr, to_umax(0), to_umax(0)};
            bsl::ut_then{} = [&ci]() {
                bsl::ut_check(ci.get_if() == nullptr);
            };
        };

        bsl::ut_given{} = []() {
            contiguous_iterator ci{arr.data(), arr.size(), to_umax(0)};
            bsl::ut_then{} = [&ci]() {
                bsl::ut_check(ci.get_if() == arr.front_if());
            };
        };

        bsl::ut_given{} = []() {
            contiguous_iterator const ci{arr.data(), arr.size(), to_umax(0)};
            bsl::ut_then{} = [&ci]() {
                bsl::ut_check(ci.get_if() == arr.front_if());
            };
        };

        bsl::ut_given{} = []() {
            contiguous_iterator ci{arr.data(), arr.size(), to_umax(5)};
            bsl::ut_then{} = [&ci]() {
                bsl::ut_check(ci.get_if() == arr.back_if());
            };
        };

        bsl::ut_given{} = []() {
            contiguous_iterator const ci{arr.data(), arr.size(), to_umax(5)};
            bsl::ut_then{} = [&ci]() {
                bsl::ut_check(ci.get_if() == arr.back_if());
            };
        };

        bsl::ut_given{} = []() {
            contiguous_iterator ci{arr.data(), arr.size(), to_umax(6)};
            bsl::ut_then{} = [&ci]() {
                bsl::ut_check(ci.get_if() == nullptr);
            };
        };

        bsl::ut_given{} = []() {
            contiguous_iterator const ci{arr.data(), arr.size(), to_umax(6)};
            bsl::ut_then{} = [&ci]() {
                bsl::ut_check(ci.get_if() == nullptr);
            };
        };
    };

    bsl::ut_scenario{"++ operator"} = []() {
        bsl::ut_given{} = []() {
            contiguous_iterator<bool> ci{nullptr, to_umax(0), to_umax(0)};
            bsl::ut_when{} = [&ci]() {
                ++ci;
                bsl::ut_then{} = [&ci]() {
                    bsl::ut_check(ci.get_if() == nullptr);
                    bsl::ut_check(ci.index() == to_umax(0));
                };
            };
        };

        bsl::ut_given{} = []() {
            contiguous_iterator ci{arr.data(), arr.size(), to_umax(0)};
            bsl::ut_when{} = [&ci]() {
                ++ci;
                bsl::ut_then{} = [&ci]() {
                    bsl::ut_check(ci.get_if() == arr.at_if(to_umax(1)));
                    bsl::ut_check(ci.index() == to_umax(1));
                };
            };
        };

        bsl::ut_given{} = []() {
            contiguous_iterator ci{arr.data(), arr.size(), to_umax(4)};
            bsl::ut_when{} = [&ci]() {
                ++ci;
                bsl::ut_then{} = [&ci]() {
                    bsl::ut_check(ci.get_if() == arr.at_if(to_umax(5)));
                    bsl::ut_check(ci.index() == to_umax(5));
                };
            };
        };

        bsl::ut_given{} = []() {
            contiguous_iterator ci{arr.data(), arr.size(), to_umax(5)};
            bsl::ut_when{} = [&ci]() {
                ++ci;
                bsl::ut_then{} = [&ci]() {
                    bsl::ut_check(ci.get_if() == nullptr);
                    bsl::ut_check(ci.index() == arr.size());
                };
            };
        };

        bsl::ut_given{} = []() {
            contiguous_iterator ci{arr.data(), arr.size(), to_umax(6)};
            bsl::ut_when{} = [&ci]() {
                ++ci;
                bsl::ut_then{} = [&ci]() {
                    bsl::ut_check(ci.get_if() == nullptr);
                    bsl::ut_check(ci.index() == arr.size());
                };
            };

            bsl::ut_when{} = [&ci]() {
                ++ci;
                bsl::ut_then{} = [&ci]() {
                    bsl::ut_check(ci.get_if() == nullptr);
                    bsl::ut_check(ci.index() == arr.size());
                };
            };
        };
    };

    bsl::ut_scenario{"-- operator"} = []() {
        bsl::ut_given{} = []() {
            contiguous_iterator<bool> ci{nullptr, to_umax(0), to_umax(0)};
            bsl::ut_when{} = [&ci]() {
                --ci;
                bsl::ut_then{} = [&ci]() {
                    bsl::ut_check(ci.get_if() == nullptr);
                    bsl::ut_check(ci.index() == to_umax(0));
                };
            };
        };

        bsl::ut_given{} = []() {
            contiguous_iterator ci{arr.data(), arr.size(), to_umax(0)};
            bsl::ut_when{} = [&ci]() {
                --ci;
                bsl::ut_then{} = [&ci]() {
                    bsl::ut_check(ci.get_if() == arr.front_if());
                    bsl::ut_check(ci.index() == to_umax(0));
                };
            };

            bsl::ut_when{} = [&ci]() {
                --ci;
                bsl::ut_then{} = [&ci]() {
                    bsl::ut_check(ci.get_if() == arr.front_if());
                    bsl::ut_check(ci.index() == to_umax(0));
                };
            };
        };

        bsl::ut_given{} = []() {
            contiguous_iterator ci{arr.data(), arr.size(), to_umax(1)};
            bsl::ut_when{} = [&ci]() {
                --ci;
                bsl::ut_then{} = [&ci]() {
                    bsl::ut_check(ci.get_if() == arr.front_if());
                    bsl::ut_check(ci.index() == to_umax(0));
                };
            };
        };

        bsl::ut_given{} = []() {
            contiguous_iterator ci{arr.data(), arr.size(), to_umax(5)};
            bsl::ut_when{} = [&ci]() {
                --ci;
                bsl::ut_then{} = [&ci]() {
                    bsl::ut_check(ci.get_if() == arr.at_if(to_umax(4)));
                };
            };
        };

        bsl::ut_given{} = []() {
            contiguous_iterator ci{arr.data(), arr.size(), to_umax(6)};
            bsl::ut_when{} = [&ci]() {
                --ci;
                bsl::ut_then{} = [&ci]() {
                    bsl::ut_check(ci.get_if() == arr.at_if(to_umax(5)));
                };
            };
        };
    };

    bsl::ut_scenario{"comparisons"} = []() {
        bsl::ut_given{} = []() {
            contiguous_iterator ci1{arr.data(), arr.size(), to_umax(0)};
            contiguous_iterator ci2{arr.data(), arr.size(), to_umax(0)};
            bsl::ut_then{} = [&ci1, &ci2]() {
                bsl::ut_check(ci1 == ci2);
            };
        };

        bsl::ut_given{} = []() {
            contiguous_iterator ci1{arr.data(), arr.size(), to_umax(0)};
            contiguous_iterator ci2{arr.data(), arr.size(), to_umax(1)};
            bsl::ut_then{} = [&ci1, &ci2]() {
                bsl::ut_check(ci1 != ci2);
            };
        };

        bsl::ut_given{} = []() {
            contiguous_iterator ci1{arr.data(), arr.size(), to_umax(0)};
            contiguous_iterator ci2{arr.data() + 1, arr.size(), to_umax(0)};
            bsl::ut_then{} = [&ci1, &ci2]() {
                bsl::ut_check(ci1 != ci2);
            };
        };

        bsl::ut_given{} = []() {
            contiguous_iterator ci1{arr.data(), arr.size(), to_umax(0)};
            contiguous_iterator ci2{arr.data(), arr.size(), to_umax(1)};
            bsl::ut_then{} = [&ci1, &ci2]() {
                bsl::ut_check(ci1 < ci2);
                bsl::ut_check(ci1 <= ci2);
            };
        };

        bsl::ut_given{} = []() {
            contiguous_iterator ci1{arr.data(), arr.size(), to_umax(0)};
            contiguous_iterator ci2{arr.data(), arr.size(), to_umax(0)};
            bsl::ut_then{} = [&ci1, &ci2]() {
                bsl::ut_check(ci1 <= ci2);
            };
        };

        bsl::ut_given{} = []() {
            contiguous_iterator ci1{arr.data(), arr.size(), to_umax(1)};
            contiguous_iterator ci2{arr.data(), arr.size(), to_umax(0)};
            bsl::ut_then{} = [&ci1, &ci2]() {
                bsl::ut_check(ci1 > ci2);
                bsl::ut_check(ci1 >= ci2);
            };
        };

        bsl::ut_given{} = []() {
            contiguous_iterator ci1{arr.data(), arr.size(), to_umax(0)};
            contiguous_iterator ci2{arr.data(), arr.size(), to_umax(0)};
            bsl::ut_then{} = [&ci1, &ci2]() {
                bsl::ut_check(ci1 >= ci2);
            };
        };
    };

    bsl::ut_scenario{"output doesn't crash"} = []() {
        bsl::ut_given{} = []() {
            contiguous_iterator<bool> ci{nullptr, arr.size(), to_umax(0)};
            bsl::ut_then{} = [&ci]() {
                bsl::debug() << ci << '\n';
            };
        };

        bsl::ut_given{} = []() {
            contiguous_iterator ci{arr.data(), to_umax(0), to_umax(0)};
            bsl::ut_then{} = [&ci]() {
                bsl::debug() << ci << '\n';
            };
        };

        bsl::ut_given{} = []() {
            contiguous_iterator ci{arr.data(), arr.size(), to_umax(0)};
            bsl::ut_then{} = [&ci]() {
                bsl::debug() << ci << '\n';
            };
        };

        bsl::ut_given{} = []() {
            contiguous_iterator ci{arr.data(), arr.size(), to_umax(6)};
            bsl::ut_then{} = [&ci]() {
                bsl::debug() << ci << '\n';
            };
        };

        bsl::ut_given{} = []() {
            contiguous_iterator ci{arr.data(), arr.size(), npos};
            bsl::ut_then{} = [&ci]() {
                bsl::debug() << ci << '\n';
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
