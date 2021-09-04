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
/// @file is_destructible.hpp
///

#ifndef BSL_IS_DESTRUCTIBLE_HPP
#define BSL_IS_DESTRUCTIBLE_HPP

#include "bsl/bool_constant.hpp"    // IWYU pragma: export
#include "bsl/details/is_destructible_type.hpp"
#include "bsl/is_detected.hpp"
#include "bsl/is_function.hpp"
#include "bsl/is_reference.hpp"
#include "bsl/is_unbounded_array.hpp"
#include "bsl/is_void.hpp"
#include "bsl/remove_all_extents.hpp"

namespace bsl
{
    namespace details
    {
        /// <!-- description -->
        ///   @brief Checks if a type "T" is destructible and if so, returns
        ///     true, otherwise returns false.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T the type to query
        ///   @return If "T" is destructible, returns true, otherwise returns
        ///     false.
        ///
        template<typename T>
        [[nodiscard]] constexpr auto
        check_is_destructible() noexcept -> bool
        {
            if constexpr (is_reference<T>::value) {
                return true;
            }

            if constexpr (is_void<T>::value) {
                return false;
            }

            if constexpr (is_function<T>::value) {
                return false;
            }

            if constexpr (is_unbounded_array<T>::value) {
                return false;
            }

            return is_detected<is_destructible_type, remove_all_extents_t<T>>::value;
        }
    }

    /// @class bsl::is_destructible
    ///
    /// <!-- description -->
    ///   @brief If the provided type is destructible, provides the
    ///     member constant value equal to true. Otherwise the member constant
    ///     value is false.
    ///   @include example_is_destructible_overview.hpp
    ///
    /// <!-- template parameters -->
    ///   @tparam T the type to query
    ///
    template<typename T>
    class is_destructible final :    // --
        public bool_constant<details::check_is_destructible<T>()>
    {};
}

#endif
