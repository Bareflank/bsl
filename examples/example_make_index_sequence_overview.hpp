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

#include <bsl/make_index_sequence.hpp>
#include <bsl/debug.hpp>

namespace bsl
{
    /// <!-- description -->
    ///   @brief Provides the example's main function
    ///
    inline void
    example_make_index_sequence_overview() noexcept
    {
        constexpr bsl::safe_uintmax size{bsl::to_umax(6)};
        constexpr bsl::safe_uintmax max{bsl::to_umax(5)};
        constexpr bsl::safe_uintmax min{bsl::to_umax(0)};

        if constexpr (bsl::make_index_sequence<size.get()>::size() == size.get()) {
            bsl::print() << "success\n";
        }
        else {
            bsl::error() << "failure\n";
        }

        if constexpr (bsl::make_index_sequence<size.get()>::max() == max.get()) {
            bsl::print() << "success\n";
        }
        else {
            bsl::error() << "failure\n";
        }

        if constexpr (bsl::make_index_sequence<size.get()>::min() == min.get()) {
            bsl::print() << "success\n";
        }
        else {
            bsl::error() << "failure\n";
        }
    }
}
