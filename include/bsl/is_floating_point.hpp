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
/// @file is_floating_point.hpp
///

#ifndef BSL_IS_FLOATING_POINT_HPP
#define BSL_IS_FLOATING_POINT_HPP

#include "cstdint.hpp"
#include "true_type.hpp"
#include "false_type.hpp"

namespace bsl
{
    /// @class bsl::is_floating_point
    ///
    /// <!-- description -->
    ///   @brief If the provided type is a floating point type (taking into
    ///     account const qualifications), provides the member constant value
    ///     equal to true. Otherwise the member constant value is false.
    ///
    ///   SUPPRESSION: PRQA 2427 - false positive
    ///   - We suppress this because A3-9-1 states that you should not use
    ///     any of the fundamental types. This is a false positive because
    ///     A3-9-1 is only referring to the integer types as there are
    ///     fixed width versions that should be used instead. This is not
    ///     refering to the floating point types which do not have the
    ///     same set of typedefs.
    ///
    /// <!-- template parameters -->
    ///   @tparam T the type to query
    ///
    template<typename T>
    class is_floating_point final : public false_type
    {};

    /// @cond doxygen off

    template<>
    class is_floating_point<float> final : public true_type    // PRQA S 2427
    {};

    template<>
    class is_floating_point<float const> final : public true_type    // PRQA S 2427
    {};

    template<>
    class is_floating_point<double> final : public true_type    // PRQA S 2427
    {};

    template<>
    class is_floating_point<double const> final : public true_type    // PRQA S 2427
    {};

    /// @endcond doxygen on
}

#endif
