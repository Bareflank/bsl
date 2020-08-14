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
/// @file common_type.hpp
///

#ifndef BSL_COMMON_TYPE_HPP
#define BSL_COMMON_TYPE_HPP

#include "decay.hpp"
#include "declval.hpp"

namespace bsl
{
    /// @class bsl::common_type
    ///
    /// <!-- description -->
    ///   @brief Provides the member typedef type which is the type that is
    ///     common between all provided types. For more information, please
    ///     see std::common_type
    ///   @include example_common_type_overview.hpp
    ///
    template<typename...>
    struct common_type;

    /// @brief a helper that reduces the verbosity of bsl::common_type
    template<typename... T>
    using common_type_t = typename common_type<T...>::type;

    /// @cond doxygen off

    template<typename T>
    struct common_type<T> final
    {
        /// @brief provides the member typedef "type"
        using type = decay_t<T>;
    };

    template<typename T1, typename T2>
    struct common_type<T1, T2> final
    {
        /// @brief provides the member typedef "type"
        // The ternary operator is one of the few ways that you can
        // implement this type traits (if not the only way), so in this
        // case it makes sense to allow. Also, it is not actually being
        // executed, so not testing is needed here. It is only used as a
        // means to impelement this type trait as a side effect of how
        // this operator is view by the compiler.
        // NOLINTNEXTLINE(bsl-ternary-operator-forbidden)
        using type = decay_t<decltype(true ? declval<T1>() : declval<T2>())>;
    };

    template<typename T1, typename T2, typename... R>
    struct common_type<T1, T2, R...> final
    {
        /// @brief provides the member typedef "type"
        using type = common_type_t<common_type_t<T1, T2>, R...>;
    };

    /// @endcond doxygen on
}

#endif
