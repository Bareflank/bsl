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
/// @file construct_at.hpp
///

#ifndef BSL_CONSTRUCT_AT_HPP
#define BSL_CONSTRUCT_AT_HPP

#include "bsl/cstdint.hpp"
#include "bsl/declval.hpp"
#include "bsl/expects.hpp"
#include "bsl/forward.hpp"
// IWYU pragma: no_include <new>

/// <!-- description -->
///   @brief This function implements the placement new operator. Note that
///     this function is passed a count and pointer, both of which are ignored.
///
/// <!-- inputs/outputs -->
///   @param count ignored
///   @param pmut_mut_ptr the ptr to return
///   @return returns ptr
///
[[maybe_unused]] constexpr auto
operator new(bsl::uintmx const count, void *pmut_mut_ptr) noexcept -> void *
{
    bsl::expects(static_cast<bsl::uintmx>(0) != count);
    bsl::expects(nullptr != pmut_mut_ptr);

    return pmut_mut_ptr;
}

// Currently, the new operator is only allowed in a constexpr if the constexpr
// originates from the std namespace, which is why this is needed.
// NOLINTNEXTLINE(cert-dcl58-cpp)
namespace std
{
    /// <!-- description -->
    ///   @brief Implements a constexpr version of placement new. that can
    ///     be used by BSL's APIs to support constexpr based APIs
    ///
    /// <!-- notes -->
    ///   @note C++20 right now only allows for constexpr placement new to
    ///     occur from the standard library (a practice I hope changes in the
    ///     next release as that is horrible). For this reason, we implement
    ///     the placement new from the std namespace (uhg) and then call this
    ///     from our BSL function. This rule is so easy to bypass, I am at
    ///     a loss as to why they did this, but at least this approach works
    ///     so that third party libraries can still take advantage of this
    ///     C++20 feature.
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of object to initialize
    ///   @tparam ARGS the types of args to initialize T with
    ///   @param pmut_ptr a pointer to the object to initialize
    ///   @param pudm_udm_a the args to initialize T with
    ///   @return returns a pointer to the newly constructed T
    ///
    /// <!-- exceptions -->
    ///   @throw throws if T throws during construction
    ///
    template<typename T, typename... ARGS>
    [[nodiscard]] constexpr auto
    construct_at_impl(void *const pmut_ptr, ARGS &&...pudm_udm_a)    // --
        noexcept(noexcept(new (pmut_ptr) T{bsl::declval<ARGS>()...})) -> T *
    {
        bsl::expects(nullptr != pmut_ptr);
        return new (pmut_ptr) T{bsl::forward<ARGS>(pudm_udm_a)...};
    }
}

namespace bsl
{
    /// <!-- description -->
    ///   @brief Implements a constexpr version of placement new. that can
    ///     be used by BSL's APIs to support constexpr based APIs
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of object to initialize
    ///   @tparam ARGS the types of args to initialize T with
    ///   @param pmut_ptr a pointer to the object to initialize
    ///   @param pudm_udm_a the args to initialize T with
    ///   @return returns a pointer to the newly constructed T
    ///
    /// <!-- exceptions -->
    ///   @throw throws if T throws during construction
    ///
    template<typename T, typename... ARGS>
    [[nodiscard]] constexpr auto
    construct_at(void *const pmut_ptr, ARGS &&...pudm_udm_a)    // --
        noexcept(noexcept(std::construct_at_impl<T, ARGS...>(pmut_ptr, bsl::declval<ARGS>()...)))
            -> T *
    {
        expects(nullptr != pmut_ptr);
        return std::construct_at_impl<T, ARGS...>(pmut_ptr, bsl::forward<ARGS>(pudm_udm_a)...);
    }
}

#endif
