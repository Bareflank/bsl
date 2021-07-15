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
/// @file exchange.hpp
///

#ifndef BSL_EXCHANGE_HPP
#define BSL_EXCHANGE_HPP

#include "forward.hpp"
#include "move.hpp"

namespace bsl
{
    /// <!-- description -->
    ///   @brief Replaces the value of obj with new_value and returns the old
    ///     value of obj.
    ///   @include example_exchange_overview.hpp
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type that defines the obj being exchanged
    ///   @tparam U the type that defines the new value for obj
    ///   @param mut_obj the object whose value will be set to new_value
    ///   @param mut_new_value the new value to set the obj to
    ///   @return returns the old value of obj prior to the exchange
    ///
    /// <!-- exceptions -->
    ///   @throw throws if obj's move constructor or obj's copy/move
    ///     assignment throws
    ///
    template<typename T, typename U = T>
    [[nodiscard]] constexpr auto
    exchange(T &mut_obj, U &&mut_new_value) noexcept(false) -> T
    {
        T const old_value{bsl::move(mut_obj)};
        mut_obj = bsl::forward<U>(mut_new_value);
        return old_value;
    }

}

#endif
