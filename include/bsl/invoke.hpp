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
/// @file invoke.hpp
///

#ifndef BSL_INVOKE_HPP
#define BSL_INVOKE_HPP

#include "bsl/details/invoke_impl.hpp"
#include "bsl/forward.hpp"

namespace bsl
{
    /// <!-- description -->
    ///   @brief Invokes the callable object "pudm_udm_func" with arguments "val".
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam FUNC the type that defines the function being called
    ///   @tparam TN the types that define the arguments passed to the
    ///     provided function when called.
    ///   @param pudm_udm_func a pointer to the function being called.
    ///   @param pudm_udm_valn the arguments passed to the function f when called.
    ///   @return Returns the result of calling "pudm_udm_func" with "pudm_udm_valn"
    ///
    /// <!-- inputs/outputs -->
    ///   @throw throws if the provided function throws
    ///
    template<typename FUNC, typename... TN>
    [[maybe_unused]] constexpr auto
    invoke(FUNC &&pudm_udm_func, TN &&...pudm_udm_valn) noexcept(    // --
        noexcept(details::invoke_impl<FUNC, TN...>::call(            // --
            bsl::forward<FUNC>(pudm_udm_func),                       // --
            bsl::forward<TN>(pudm_udm_valn)...)))                    // --
        -> decltype(details::invoke_impl<FUNC, TN...>::call(         // --
            bsl::forward<FUNC>(pudm_udm_func),                       // --
            bsl::forward<TN>(pudm_udm_valn)...))                     // --
    {                                                                // --
        return details::invoke_impl<FUNC, TN...>::call(              // --
            bsl::forward<FUNC>(pudm_udm_func),                       // --
            bsl::forward<TN>(pudm_udm_valn)...);                     // --
    }
}

#endif
