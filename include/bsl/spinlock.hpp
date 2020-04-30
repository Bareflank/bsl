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
/// @file spinlock.hpp
///

#ifndef BSL_SPIN_LOCK_HPP
#define BSL_SPIN_LOCK_HPP

#include "is_constant_evaluated.hpp"

namespace bsl
{
    /// @class bsl::spinlock
    ///
    /// <!-- description -->
    ///   @brief Implements a spinlock. Similar to a mutex, a spin lock
    ///     provides the ability to guard a critical resource. Unlike a
    ///     mutex, a spinlock never calls "yield", meaning it will loop
    ///     infinitely until the lock is acquired. For this reason, a
    ///     spinlock should not be used if you have an operating system
    ///     with a yield system call. In addition, the bsl::spinlock does
    ///     not attempt any backoff algorithms, but it does use pause, and
    ///     attempts to handle caching properly.
    ///   @include example_spinlock_overview.hpp
    ///
    class spinlock final
    {
        /// @brief stores whether or not the lock is acquired
        _Atomic bool m_flag;

    public:
        /// <!-- description -->
        ///   @brief Default constructor. This ensures the spinlock type is a
        ///     POD type, allowing it to be constructed as a global resource.
        ///   @include spinlock/example_spinlock_default_constructor.hpp
        ///
        BSL_CONSTEXPR spinlock() noexcept = default;

        /// <!-- description -->
        ///   @brief Creates a bsl::spinlock, and sets the initial lock
        ///     state of the spinlock.
        ///   @include spinlock/example_spinlock_constructor_val.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param val the initial state of the lock. Set to true for locked
        ///     and false for unlocked.
        ///
        explicit BSL_CONSTEXPR
        spinlock(bool const val) noexcept
        {
            if (is_constant_evaluated()) {
                return;
            }

            __c11_atomic_store(&m_flag, val, __ATOMIC_RELEASE);
        }

        /// <!-- description -->
        ///   @brief Destructor
        ///
        BSL_CONSTEXPR ~spinlock() noexcept = default;

        /// <!-- description -->
        ///   @brief copy constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///
        constexpr spinlock(spinlock const &o) noexcept = delete;

        /// <!-- description -->
        ///   @brief move constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being moved
        ///
        constexpr spinlock(spinlock &&o) noexcept = default;

        /// <!-- description -->
        ///   @brief copy assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///   @return a reference to *this
        ///
        spinlock &operator=(spinlock const &o) &noexcept = delete;

        /// <!-- description -->
        ///   @brief move assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being moved
        ///   @return a reference to *this
        ///
        spinlock &operator=(spinlock &&o) &noexcept = default;

        /// <!-- description -->
        ///   @brief Locks the spinlock. This will not return until the
        ///     spinlock can be successfully acquired.
        ///   @include spinlock/example_spinlock_lock.hpp
        ///
        constexpr void
        lock() noexcept
        {
            if (is_constant_evaluated()) {
                return;
            }

            while (true) {
                if (!__c11_atomic_exchange(&m_flag, true, __ATOMIC_ACQUIRE)) {    // PRQA S 1-10000
                    return;
                }

                while (__c11_atomic_load(&m_flag, __ATOMIC_RELAXED)) {    // PRQA S 1-10000
                    __builtin_ia32_pause();
                }
            }
        }

        /// <!-- description -->
        ///   @brief Attempts to lock the spinlock. This is a no-blocking
        ///     version of lock(), and will return immediately, indicating
        ///     if the lock was successfully acquired.
        ///   @include spinlock/example_spinlock_try_lock.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if the lock was successfully acquired,
        ///     false otherwise.
        ///
        [[nodiscard]] constexpr bool
        try_lock() noexcept
        {
            if (is_constant_evaluated()) {
                return true;
            }

            return (!__c11_atomic_load(&m_flag, __ATOMIC_RELAXED)) &&            // PRQA S 1-10000
                   (!__c11_atomic_exchange(&m_flag, true, __ATOMIC_ACQUIRE));    // PRQA S 1-10000
        }

        /// <!-- description -->
        ///   @brief Unlocks the spinlock.
        ///   @include spinlock/example_spinlock_unlock.hpp
        ///
        constexpr void
        unlock() noexcept
        {
            if (is_constant_evaluated()) {
                return;
            }

            __c11_atomic_store(&m_flag, false, __ATOMIC_RELEASE);
        }
    };
}

#endif
