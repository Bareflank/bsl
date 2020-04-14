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

#ifndef EXAMPLE_FOREACH_OVERVIEW_HPP
#define EXAMPLE_FOREACH_OVERVIEW_HPP

#include <bsl/for_each.hpp>
#include <bsl/string_view.hpp>
#include <bsl/debug.hpp>

namespace bsl
{
    /// <!-- description -->
    ///   @brief Provides the example's main function
    ///
    inline void
    example_for_each_overview() noexcept
    {
        constexpr bsl::string_view msg{"Hello"};
        constexpr bsl::uintmax i1{1U};
        constexpr bsl::uintmax i4{4U};
        constexpr char_type co{'o'};

        // ---------------------------------------------------------------------
        bsl::print() << "example 1:\n";
        bsl::for_each(msg, [](auto &e) noexcept {
            bsl::print() << e;
        });
        bsl::print() << "\n\n";

        // ---------------------------------------------------------------------
        bsl::print() << "example 2:\n";
        bsl::for_each(msg, [](auto &e, auto const i) noexcept {
            bsl::print() << "element [" << i << "] == " << e << bsl::endl;
        });
        bsl::print() << bsl::endl;

        // ---------------------------------------------------------------------
        bsl::print() << "example 3:\n";
        bsl::for_each(msg, [](auto &e) noexcept -> bool {
            if (co == e) {
                return bsl::for_each_break;
            }

            bsl::print() << e;
            return for_each_continue;
        });
        bsl::print() << "\n\n";

        // ---------------------------------------------------------------------
        bsl::print() << "example 4:\n";
        bsl::for_each(msg.begin(), msg.end(), [](auto &e) noexcept {
            bsl::print() << e;
        });
        bsl::print() << "\n\n";

        // ---------------------------------------------------------------------
        bsl::print() << "example 5:\n";
        bsl::for_each(msg.iter(i1), msg.iter(i4), [](auto &e) noexcept {
            bsl::print() << e;
        });
        bsl::print() << "\n\n";

        // ---------------------------------------------------------------------
        bsl::print() << "example 6:\n";
        bsl::for_each(msg.rbegin(), msg.rend(), [](auto &e) noexcept {
            bsl::print() << e;
        });
        bsl::print() << "\n\n";

        // ---------------------------------------------------------------------
        bsl::print() << "example 7:\n";
        bsl::for_each(msg.rbegin(), msg.rend(), [](auto &e, auto const i) noexcept {
            bsl::print() << "element [" << i << "] == " << e << bsl::endl;
        });
    }
}

#endif
