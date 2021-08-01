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

#include <bsl/convert.hpp>
#include <bsl/debug.hpp>
#include <bsl/make_integer_sequence.hpp>

namespace bsl
{
    /// <!-- description -->
    ///   @brief Provides the example's main function
    ///
    inline void
    example_make_integer_sequence_overview() noexcept
    {
        constexpr auto size{6_umx};
        constexpr auto max{5_umx};
        constexpr auto min{0_umx};

        if constexpr (bsl::make_integer_sequence<bsl::uintmx, size.get()>::size() == size.get()) {
            bsl::print() << "success\n";
        }
        else {
            bsl::error() << "failure\n";
        }

        if constexpr (bsl::make_integer_sequence<bsl::uintmx, size.get()>::max() == max.get()) {
            bsl::print() << "success\n";
        }
        else {
            bsl::error() << "failure\n";
        }

        if constexpr (bsl::make_integer_sequence<bsl::uintmx, size.get()>::min() == min.get()) {
            bsl::print() << "success\n";
        }
        else {
            bsl::error() << "failure\n";
        }
    }
}
