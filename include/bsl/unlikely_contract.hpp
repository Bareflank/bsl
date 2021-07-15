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
/// @file unlikely_assert.hpp
///

#ifndef BSL_UNLIKELY_ASSERT_HPP
#define BSL_UNLIKELY_ASSERT_HPP

namespace bsl
{
    /// <!-- description -->
    ///   @brief Used to tell the user during compile-time that an
    ///     unlikely_assert would have been triggered. Mocks should use this
    ///     version of bsl::unlikely when their counterparts use the assert
    ///     version of unlikely. Remember that the assert versions are removed
    ///     in release builds because it is exected that they will never
    ///     occur. If a unit test triggers one, it means that something caused
    ///     this contract to be violated, which could cause runtime issues as
    ///     a check for something that can occur is missing.
    ///
    inline void
    unlikely_contract_failure() noexcept
    {}

    /// <!-- description -->
    ///   @brief Implements a wrapper around __builtin_expect. Unlike the
    ///     bsl::unlikely version, this version should be used by mocks to
    ///     ensure that anything labeled with assert cannot occur during a
    ///     compile-time unit test.
    ///   @include example_unlikely_overview.hpp
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam ARG the type that define the provided argument
    ///   @param pudm_udm_a the arguments check
    ///   @return Returns the boolean output of __builtin_expect, or false
    ///     if in release mode.
    ///
    template<typename ARG>
    [[nodiscard]] constexpr auto
    unlikely_contract(ARG &&pudm_udm_a) noexcept -> bool
    {
        unlikely_contract_failure();
        return __builtin_expect(!!(pudm_udm_a), 0L) != 0L;
    }
}

#endif
