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
/// @file move.hpp
///

#ifndef BSL_MOVE_HPP
#define BSL_MOVE_HPP

#include "remove_reference.hpp"

namespace bsl
{
    template<typename V>
    class fmt;

    /// <!-- description -->
    ///   @brief Used to indicate that an object "val" may be "moved from",
    ///     i.e. allowing the efficient transfer of resources from "val" to
    ///     another object.
    ///   @include example_move_overview.hpp
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type that defines the value being moved
    ///   @param val the value being moved
    ///   @return returns an xvalue expression that identifies "val"
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    move(T &&val) noexcept -> bsl::remove_reference_t<T> &&
    {
        return static_cast<bsl::remove_reference_t<T> &&>(val);
    }

    /// <!-- description -->
    ///   @brief Used to prevent a move of bsl::fmt as it must always be a
    ///     temporary r-value.
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam V the type of value being formatted for output
    ///   @param val the value being moved
    ///
    template<typename V>
    constexpr auto move(fmt<V> &&val) noexcept -> void = delete;
}

#endif
