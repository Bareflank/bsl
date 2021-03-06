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
/// @file adopt_lock_t.hpp
///

#ifndef BSL_ADOPT_LOCK_HPP
#define BSL_ADOPT_LOCK_HPP

namespace bsl
{
    /// @class bsl::adopt_lock_t
    ///
    /// <!-- description -->
    ///   @brief Assume the calling thread already has ownership of the mutex
    ///     or spinlock
    ///
    class adopt_lock_t final
    {
    public:
        /// <!-- description -->
        ///   @brief Default constructor that ensures construction of
        ///     this type must be explicit
        ///
        explicit constexpr adopt_lock_t() noexcept = default;

        /// <!-- description -->
        ///   @brief Destroyes a previously created bsl::adopt_lock_t
        ///
        constexpr ~adopt_lock_t() noexcept = default;

        /// <!-- description -->
        ///   @brief copy constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///
        constexpr adopt_lock_t(adopt_lock_t const &o) noexcept = default;

        /// <!-- description -->
        ///   @brief move constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being moved
        ///
        constexpr adopt_lock_t(adopt_lock_t &&o) noexcept = default;

        /// <!-- description -->
        ///   @brief copy assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr auto operator=(adopt_lock_t const &o) &noexcept
            -> adopt_lock_t & = default;

        /// <!-- description -->
        ///   @brief move assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being moved
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr auto operator=(adopt_lock_t &&o) &noexcept
            -> adopt_lock_t & = default;
    };

    /// @brief reduces the verbosity of bsl::adopt_lock_t
    // We want our implementation to mimic C++ here.
    // NOLINTNEXTLINE(bsl-name-case)
    constexpr adopt_lock_t adopt_lock{};
}

#endif
