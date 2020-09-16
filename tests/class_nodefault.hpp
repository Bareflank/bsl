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

#ifndef TESTS_CLASS_NODEFAULT_HPP
#define TESTS_CLASS_NODEFAULT_HPP

#include <bsl/discard.hpp>

namespace test
{
    class class_nodefault final
    {
    public:
        // Need to test a default
        // NOLINTNEXTLINE(hicpp-use-equals-default, modernize-use-equals-default)
        constexpr class_nodefault() noexcept
        {}

        // Need to test a default
        // NOLINTNEXTLINE(hicpp-use-equals-default, modernize-use-equals-default)
        constexpr ~class_nodefault() noexcept
        {}

        constexpr class_nodefault(class_nodefault const &o) noexcept
        {
            bsl::discard(o);
        }

        [[maybe_unused]] constexpr auto
        operator=(class_nodefault const &o) &noexcept -> class_nodefault &
        {
            bsl::discard(o);
            return *this;
        }

        constexpr class_nodefault(class_nodefault &&o) noexcept
        {
            bsl::discard(o);
        }

        [[maybe_unused]] constexpr auto
        operator=(class_nodefault &&o) &noexcept -> class_nodefault &
        {
            bsl::discard(o);
            return *this;
        }
    };
}

#endif
