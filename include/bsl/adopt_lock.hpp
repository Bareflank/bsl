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
/// @file adopt_lock.hpp
///

#ifndef BSL_ADOPT_LOCK_HPP
#define BSL_ADOPT_LOCK_HPP

namespace bsl
{
    /// @class bsl::adopt_lock_t
    ///
    /// <!-- description -->
    ///   @brief Assume the calling thread already has ownership of the mutex
    ///     or spinlock
    ///
    class adopt_lock_t final
    {
    public:
        /// <!-- description -->
        ///   @brief Default constructor that ensures construction of
        ///     this type must be explicit
        ///
        explicit constexpr adopt_lock_t() noexcept = default;
    };

    /// @brief reduces the verbosity of bsl::adopt_lock_t
    constexpr adopt_lock_t adopt_lock{};
}

#endif
