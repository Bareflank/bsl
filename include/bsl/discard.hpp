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
/// @file discard.hpp
///

#ifndef BSL_DISCARD_HPP
#define BSL_DISCARD_HPP

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-parameter"

namespace bsl
{
    /// <!-- description -->
    ///   @brief This function discards a parameter that it is given. This is
    ///     the same as executing a static cast. The reason this exists is
    ///     it better documents the intent to discard the result of a function
    ///     or an intentionally unused parameter. This function also exists
    ///     because in some cases, we must pass the address of a discard as
    ///     as a template parameter, which cannot be done with a static cast.
    ///   @include example_discard_overview.hpp
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of arg to ignore
    ///   @param pudm_udm_a the arg to ignore
    ///
    template<typename T>
    constexpr void
    discard(T &&pudm_udm_a) noexcept
    {}
}

#pragma clang diagnostic pop

#endif
