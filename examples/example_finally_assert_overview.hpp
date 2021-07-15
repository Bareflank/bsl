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

#include <bsl/debug.hpp>
#include <bsl/finally_assert.hpp>

namespace bsl
{
    /// <!-- description -->
    ///   @brief Provides the example's main function
    ///
    inline void
    example_finally_assert_overview() noexcept
    {
        bool mut_executed1{};
        bool mut_executed2{};

        {
            bsl::finally_assert mut_test1{[&mut_executed1]() noexcept {
                mut_executed1 = true;
            }};

            bsl::finally_assert mut_test2{[&mut_executed2]() noexcept {
                mut_executed2 = true;
            }};

            mut_test2.ignore();
        }

        if constexpr (BSL_RELEASE_MODE) {
            if (mut_executed1) {
                bsl::error() << "failure1\n";
            }
            else {
                bsl::print() << "success2\n";
            }

            if (mut_executed2) {
                bsl::error() << "failure3\n";
            }
            else {
                bsl::print() << "success4\n";
            }
        }
        else {
            if (mut_executed1) {
                bsl::print() << "success5\n";
            }
            else {
                bsl::error() << "failure6\n";
            }

            if (mut_executed2) {
                bsl::error() << "failure7\n";
            }
            else {
                bsl::print() << "success8\n";
            }
        }
    }
}
