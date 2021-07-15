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
#include <bsl/discard.hpp>
#include <bsl/forward.hpp>
#include <bsl/is_lvalue_reference.hpp>
#include <bsl/move.hpp>

namespace bsl
{
    /// <!-- description -->
    ///   @brief If this function is given an lvalue reference, it returns
    ///     true. Otherwise this function will return false.
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T The type being queired
    ///   @param pudm_udm_val the value of the type being provided
    ///   @return If this function is given an lvalue reference, it returns
    ///     true. Otherwise this function will return false.
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    example_detector(T &&pudm_udm_val) noexcept -> bool
    {
        bsl::discard(pudm_udm_val);
        return bsl::is_lvalue_reference<decltype(pudm_udm_val)>::value;
    }

    /// <!-- description -->
    ///   @brief Forwards the provided argument to the detector using
    ///     bsl::forward, which will preserve the lvalue/rvalueness of the
    ///     provided argument.
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T The type being queired
    ///   @param pudm_udm_val the value of the type being provided
    ///   @return If this function is given an lvalue reference, it returns
    ///     true. Otherwise this function will return false.
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    example_forwarder(T &&pudm_udm_val) noexcept -> bool
    {
        return example_detector(bsl::forward<T>(pudm_udm_val));
    }

    /// <!-- description -->
    ///   @brief Provides the example's main function
    ///
    inline void
    example_forward_overview() noexcept
    {
        constexpr auto val1{42_i32};
        auto mut_val2{val1};

        if constexpr (example_forwarder(val1)) {
            bsl::print() << "success\n";
        }
        else {
            bsl::error() << "failure\n";
        }

        if (!example_forwarder(bsl::move(mut_val2))) {
            bsl::print() << "success\n";
        }
        else {
            bsl::error() << "failure\n";
        }
    }
}
