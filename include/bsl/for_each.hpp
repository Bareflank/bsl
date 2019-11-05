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
/// @file for_each.hpp
///

#ifndef BSL_FOREACH_HPP
#define BSL_FOREACH_HPP

#include "details/for_each_impl.hpp"
#include "forward.hpp"

namespace bsl
{
    /// @brief Tells a foreach to stop its execution (same as "break")
    constexpr bool for_each_break{false};
    /// @brief Tells a foreach to continue its execution (same as "continue")
    constexpr bool for_each_continue{true};

    /// <!-- description -->
    ///   @brief Loops over a view or a pair of iterators, calling a provided
    ///     function on each iteration. The provided function can take on
    ///     the following signatures:
    ///     - void(T &elem)
    ///     - void(T &elem, bsl::uintmax index)
    ///     - bool(T &elem)
    ///     - bool(T &elem, bsl::uintmax index)
    ///     The boolean versions of this function allow you to return either
    ///     bsl::for_each_break (to break from the loop) or
    ///     for_each_continue (to continue the loop). Note that if you are
    ///     using the void versions of the loop, you can continue by simply
    ///     returning. The bool versions are only needed if you need to break
    ///     from the loop, in which case bsl::for_each_continue should be used
    ///     to return from the function. In addition to the different function
    ///     signatures that you can provide, you can also provide bsl::for_each
    ///     with either a subclass of a bsl::view, or two iterators (a begin
    ///     and end iterator), which will be used to perform the loop. The
    ///     bsl::for_each function acts like a ranged for loop when given a
    ///     subclass of a bsl::view, and acts like a traditional for loop when
    ///     given two iterators. Note that you can use a reverse iterator to
    ///     loop in reverse, and you can use the BSL specific iter() functions
    ///     that allow you to create your own begin and end iterators so that
    ///     you can control the position and number of elements the loop will
    ///     perform. For more information, see the following example:
    ///   @include example_for_each_overview.hpp
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam ARGS the types of arguments passed to bsl::for_each.
    ///   @param args can either be a subclass of bsl::view and a lambda, or
    ///      a pair of iterators and a lambda.
    ///
    template<typename... ARGS>
    constexpr void
    for_each(ARGS &&... args) noexcept(noexcept(    // --
        details::for_each_impl<ARGS...>::call(bsl::forward<ARGS>(args)...)))
    {
        details::for_each_impl<ARGS...>::call(bsl::forward<ARGS>(args)...);
    }
}

#endif
