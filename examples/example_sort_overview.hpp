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
#include <bsl/convert.hpp>
#include <bsl/sort.hpp>

namespace bsl
{
    /// <!-- description -->
    ///   @brief Provides the example's main function
    ///
    inline void
    example_sort_overview() noexcept
    {
        constexpr auto val1{4_i32};
        constexpr auto val2{8_i32};
        constexpr auto val3{15_i32};
        constexpr auto val4{16_i32};
        constexpr auto val5{23_i32};
        constexpr auto val6{42_i32};

        bsl::array mut_data{val6, val3, val4, val2, val5, val1};
        bsl::sort(mut_data);

        if (mut_data.front() == val1) {
            bsl::print() << "success\n";
        }
        else {
            bsl::error() << "failure\n";
        }

        if (mut_data.back() == val6) {
            bsl::print() << "success\n";
        }
        else {
            bsl::error() << "failure\n";
        }
    }
}
