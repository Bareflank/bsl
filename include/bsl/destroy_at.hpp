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
/// @file destroy_at.hpp
///

#ifndef BSL_DESTROY_AT_HPP
#define BSL_DESTROY_AT_HPP

#include "touch.hpp"
#include "unlikely.hpp"

namespace bsl
{
    /// <!-- description -->
    ///   @brief Calls the destructor of the object pointed to by ptr
    ///   @include example_destroy_at_overview.hpp
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T defines the type pointer to by ptr
    ///   @param pmut_ptr a pointer to the object to destroy
    ///
    /// <!-- exceptions -->
    ///   @throw throws if T throws during destruction
    ///
    template<typename T>
    constexpr void
    destroy_at(T *const pmut_ptr) noexcept(noexcept(pmut_ptr->T::~T()))
    {
        if (unlikely(nullptr == pmut_ptr)) {
            unlikely_invalid_argument_failure();
        }
        else {
            pmut_ptr->T::~T();
        }
    }
}

#endif
