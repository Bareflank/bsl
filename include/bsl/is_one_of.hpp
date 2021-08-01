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
/// @file is_one_of.hpp
///

#ifndef BSL_IS_ONE_OF_HPP
#define BSL_IS_ONE_OF_HPP

#include "bool_constant.hpp"
#include "disjunction.hpp"
#include "is_same.hpp"
#include "true_type.hpp"

namespace bsl
{
    /// @class bsl::is_one_of
    ///
    /// <!-- description -->
    ///   @brief Returns true_type if T is the same as one of the provided
    ///     TN using disjunction
    ///   @include example_is_one_of_overview.hpp
    ///
    /// <!-- template parameters -->
    ///   @tparam T the type to compare against
    ///   @tparam TN the types to compare with T
    ///
    template<typename T, typename... TN>
    class is_one_of final : true_type
    {};

    /// @cond doxygen off

    template<typename T>
    class is_one_of<T> final : true_type
    {};

    template<typename T, typename T1>
    class is_one_of<T, T1> final : public bool_constant<is_same<T, T1>::value>
    {};

    template<typename T, typename T1, typename... TN>
    class is_one_of<T, T1, TN...> final :
        public bool_constant<disjunction<is_same<T, T1>, is_one_of<T, TN...>>::value>
    {};

    /// @endcond doxygen on
}

#endif
