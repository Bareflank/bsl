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

#include <bsl/ifmap.hpp>
#include <bsl/ut.hpp>

/// <!-- description -->
///   @brief Main function for this unit test. If a call to ut_check() fails
///     the application will fast fail. If all calls to ut_check() pass, this
///     function will successfully return with bsl::exit_success.
///
/// <!-- inputs/outputs -->
///   @return Always returns bsl::exit_success.
///
[[nodiscard]] auto
main() noexcept -> bsl::exit_code
{
    bsl::ut_scenario{"constructor"} = []() {
        bsl::ut_given{} = []() {
            bsl::ifmap map{};
            bsl::ut_then{} = [&map]() {
                bsl::ut_check(!map);
            };
        };

        bsl::ut_given{} = []() {
            bsl::ifmap map{"blah"};
            bsl::ut_then{} = [&map]() {
                bsl::ut_check(!map);
            };
        };

        bsl::ut_given{} = []() {
            bsl::ifmap map{"test.txt"};
            bsl::string_view str{static_cast<bsl::cstr_type>(map.data()), map.size()};
            bsl::ut_then{} = [&str]() {
                bsl::ut_check(str == "hello world");
            };
        };
    };

    bsl::ut_scenario{"data"} = []() {
        bsl::ut_given{} = []() {
            bsl::ifmap map{"blah"};
            bsl::ut_then{} = [&map]() {
                bsl::ut_check(map.data() == nullptr);
            };
        };

        bsl::ut_given{} = []() {
            bsl::ifmap map{"test.txt"};
            bsl::ut_then{} = [&map]() {
                bsl::ut_check(map.data() != nullptr);
            };
        };
    };

    bsl::ut_scenario{"empty"} = []() {
        bsl::ut_given{} = []() {
            bsl::ifmap map{"blah"};
            bsl::ut_then{} = [&map]() {
                bsl::ut_check(map.empty());
            };
        };

        bsl::ut_given{} = []() {
            bsl::ifmap map{"test.txt"};
            bsl::ut_then{} = [&map]() {
                bsl::ut_check(!map.empty());
            };
        };
    };

    bsl::ut_scenario{"operator bool"} = []() {
        bsl::ut_given{} = []() {
            bsl::ifmap map{"blah"};
            bsl::ut_then{} = [&map]() {
                bsl::ut_check(!map);
            };
        };

        bsl::ut_given{} = []() {
            bsl::ifmap map{"test.txt"};
            bsl::ut_then{} = [&map]() {
                bsl::ut_check(!!map);
            };
        };
    };

    bsl::ut_scenario{"size"} = []() {
        bsl::ut_given{} = []() {
            bsl::ifmap map{"blah"};
            bsl::ut_then{} = [&map]() {
                bsl::ut_check(map.size().is_zero());
            };
        };

        bsl::ut_given{} = []() {
            bsl::ifmap map{"test.txt"};
            bsl::ut_then{} = [&map]() {
                bsl::ut_check(map.size().is_pos());
            };
        };
    };

    bsl::ut_scenario{"max_size"} = []() {
        bsl::ut_given{} = []() {
            bsl::ifmap map{"test.txt"};
            bsl::ut_then{} = [&map]() {
                bsl::ut_check(map.max_size().is_pos());
            };
        };
    };

    bsl::ut_scenario{"size_bytes"} = []() {
        bsl::ut_given{} = []() {
            bsl::ifmap map{"blah"};
            bsl::ut_then{} = [&map]() {
                bsl::ut_check(map.size_bytes().is_zero());
            };
        };

        bsl::ut_given{} = []() {
            bsl::ifmap map{"test.txt"};
            bsl::ut_then{} = [&map]() {
                bsl::ut_check(map.size_bytes().is_pos());
            };
        };
    };

    return bsl::ut_success();
}
