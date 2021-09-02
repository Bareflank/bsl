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
/// @file errc_type.hpp
///

#ifndef BSL_ERRC_TYPE_HPP
#define BSL_ERRC_TYPE_HPP

#include "bsl/basic_errc_type.hpp"    // IWYU pragma: export
#include "bsl/cstdint.hpp"            // IWYU pragma: export
#include "bsl/is_pod.hpp"

namespace bsl
{
    /// @brief provides the default errc_type prototype
    /// @related bsl::basic_errc_type
    using errc_type = basic_errc_type<>;

    /// @brief Defines the "no error" case
    // NOLINTNEXTLINE(bsl-name-case)
    constexpr errc_type errc_success{0};
    /// @brief Defines the general unchecked error case
    // NOLINTNEXTLINE(bsl-name-case)
    constexpr errc_type errc_failure{-1};
    /// @brief Defines the general precondition error case
    // NOLINTNEXTLINE(bsl-name-case)
    constexpr errc_type errc_precondition{-2};
    /// @brief Defines the general postcondition error case
    // NOLINTNEXTLINE(bsl-name-case)
    constexpr errc_type errc_postcondition{-3};
    /// @brief Defines the general assertion error case
    // NOLINTNEXTLINE(bsl-name-case)
    constexpr errc_type errc_assetion{-4};

    /// @brief Defines an invalid argument error code
    // NOLINTNEXTLINE(bsl-name-case)
    constexpr errc_type errc_invalid_argument{-10};
    /// @brief Defines an out of bounds error code
    // NOLINTNEXTLINE(bsl-name-case)
    constexpr errc_type errc_index_out_of_bounds{-11};

    /// @brief Defines an unsigned wrap error
    // NOLINTNEXTLINE(bsl-name-case)
    constexpr errc_type errc_unsigned_wrap{-30};
    /// @brief Defines a narrow overflow error
    // NOLINTNEXTLINE(bsl-name-case)
    constexpr errc_type errc_narrow_overflow{-31};
    /// @brief Defines a signed overflow error
    // NOLINTNEXTLINE(bsl-name-case)
    constexpr errc_type errc_signed_overflow{-32};
    /// @brief Defines a divide by zero error
    // NOLINTNEXTLINE(bsl-name-case)
    constexpr errc_type errc_divide_by_zero{-33};
    /// @brief Defines an out of bounds error code
    // NOLINTNEXTLINE(bsl-name-case)
    constexpr errc_type errc_nullptr_dereference{-34};

    /// @brief Defines when a resource is busy
    // NOLINTNEXTLINE(bsl-name-case)
    constexpr errc_type errc_busy{-50};
    /// @brief Defines when a resource already_exists
    // NOLINTNEXTLINE(bsl-name-case)
    constexpr errc_type errc_already_exists{-51};
    /// @brief Defines when something is unsupported
    // NOLINTNEXTLINE(bsl-name-case)
    constexpr errc_type errc_unsupported{-52};

    /// @brief sanity check to make sure the error type is compatible with c
    static_assert(is_pod<errc_type>::value);
    /// @brief sanity check to make sure the error type is compatible with c
    static_assert(sizeof(errc_type) == sizeof(bsl::int32));
}

#endif
