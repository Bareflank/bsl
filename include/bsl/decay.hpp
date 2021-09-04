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
/// @file decay.hpp
///

#ifndef BSL_DECAY_HPP
#define BSL_DECAY_HPP

#include "bsl/add_pointer.hpp"
#include "bsl/is_array.hpp"
#include "bsl/is_function.hpp"
#include "bsl/remove_cv.hpp"
#include "bsl/remove_extent.hpp"
#include "bsl/remove_reference.hpp"

namespace bsl
{
    /// @class bsl::decay
    ///
    /// <!-- description -->
    ///   @brief Applies lvalue-to-rvalue, array-to-pointer, and
    ///     function-to-pointer implicit conversions to the type T,
    ///     removes cv-qualifiers, and defines the resulting type as the
    ///     member typedef type.
    ///   @include example_decay_overview.hpp
    ///
    /// <!-- template parameters -->
    ///   @tparam T the type to decay
    ///   @tparam IS_T_ARRAY defaults to true if T is an array type
    ///   @tparam IS_T_FUNCTION defaults to true if T is an function type
    ///
    template<
        typename T,
        bool IS_T_ARRAY = is_array<remove_reference_t<T>>::value,
        bool IS_T_FUNCTION = is_function<remove_reference_t<T>>::value>
    struct decay final
    {
        /// @brief provides the member typedef "type"
        using type = remove_cv_t<remove_reference_t<T>>;
    };

    /// @brief a helper that reduces the verbosity of bsl::decay
    ///
    /// <!-- template parameters -->
    ///   @tparam T the type to decay
    ///
    template<typename T>
    using decay_t = typename decay<T>::type;

    /// @cond doxygen off

    template<typename T>
    struct decay<T, true, true> final
    {
        /// @brief provides the member typedef "type"
        using type = remove_extent_t<remove_reference_t<T>> *;
    };

    template<typename T>
    struct decay<T, true, false> final
    {
        /// @brief provides the member typedef "type"
        using type = remove_extent_t<remove_reference_t<T>> *;
    };

    template<typename T>
    struct decay<T, false, true> final
    {
        /// @brief provides the member typedef "type"
        using type = add_pointer_t<remove_reference_t<T>>;
    };

    /// @endcond doxygen on
}

#endif
