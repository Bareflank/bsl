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
///
/// @file cstdint.hpp
///

#ifndef BSL_CSTDINT_HPP
#define BSL_CSTDINT_HPP

#include "is_same.hpp"

// We are implementing cstdint
// NOLINTNEXTLINE(hicpp-deprecated-headers, modernize-deprecated-headers)
#include <stdint.h>

namespace bsl
{
    /// NOTE:
    /// - Currently, these are designed to mimic the same types provided
    ///   by Rust. This means that there is no intmax_t, intptr_t or
    ///   uintptr_t.
    ///
    /// - The lack of intmax_t is fine because most of the time we will
    ///   need int32_t only. If more is needed, being explicit with
    ///   int64_t is better than using intmax_t.
    ///
    /// - The intptr_t type makes absolutely no sense, but uintptr_t is the
    ///   size of (void *), and that does not have to be the same thing as
    ///   a uintmax_t, which is the register size. On all of the archiectures
    ///   that we care about, this is these types are the same and so it
    ///   works, but it is possible that in the future this might not true,
    ///   in which case something will have to be addressed in Rust as well.
    ///

    /// @brief defines an 8bit signed integer
    using int8 = ::int8_t;
    /// @brief defines an 16bit signed integer
    using int16 = ::int16_t;
    /// @brief defines an 32bit signed integer
    using int32 = ::int32_t;
    /// @brief defines an 64bit signed integer
    using int64 = ::int64_t;

    /// @brief defines an 8bit unsigned integer
    using uint8 = ::uint8_t;
    /// @brief defines an 16bit unsigned integer
    using uint16 = ::uint16_t;
    /// @brief defines an 32bit unsigned integer
    using uint32 = ::uint32_t;
    /// @brief defines an 64bit unsigned integer
    using uint64 = ::uint64_t;

    /// @brief defines a unsigned integer with the maximum possible size
    using uintmx = ::uintmax_t;

    /// @brief ensure that uint8 is a proper byte type
    static_assert(is_same<bsl::uint8, unsigned char>::value);
    /// @brief ensure that int32 is really just int
    static_assert(is_same<bsl::int32, int>::value);
}

#endif
