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
/// @file debug.hpp
///

#ifndef BSL_DEBUG_HPP
#define BSL_DEBUG_HPP

#include "details/out_type_alert.hpp"
#include "details/out_type_debug.hpp"
#include "details/out_type_empty.hpp"
#include "details/out_type_error.hpp"
#include "details/out_type_print.hpp"
#include "details/out.hpp"

#include "bool_constant.hpp"
#include "char_type.hpp"
#include "conditional.hpp"
#include "cstdint.hpp"
#include "disjunction.hpp"
#include "fmt.hpp"

namespace bsl
{
    /// @brief defines "-v" verbose mode
    constexpr bsl::uintmax v{1U};
    /// @brief defines "-vv" verbose mode
    constexpr bsl::uintmax vv{2U};
    /// @brief defines "-vvv" verbose mode
    constexpr bsl::uintmax vvv{3U};

    /// @brief newline constant
    constexpr bsl::char_type endl{'\n'};

    /// @brief used to disable debugging for debug() and alert()
    template<bsl::uintmax DL, typename T>
    using out_t =
        conditional_t <
        disjunction<
            bool_constant<DL<BSL_DEBUG_LEVEL>, bool_constant<DL == BSL_DEBUG_LEVEL>>::value,
            out<T>,
            out<details::out_type_empty>>;

    namespace details
    {
        /// <!-- description -->
        ///   @brief Returns the current thread id
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T defaults to void. Provides the ability to specialize
        ///     this function to provide your own custom implementation.
        ///   @return Returns the current thread id
        ///
        template<typename T = void>
        [[nodiscard]] constexpr auto
        thread_id() noexcept -> safe_uintmax
        {
            return safe_uintmax::zero();
        }
    }

    /// <!-- description -->
    ///   @brief Returns and instance of bsl::out<T>. This version of
    ///     bsl::out<T> does not print a label and does not accept
    ///     a debug level (as it cannot be turned off). All output
    ///     is redirected to bsl::details::putc_stdout and
    ///     bsl::details::puts_stdout. See bsl::fmt for formatting
    ///     documentation and examples.
    ///   @include debug/example_debug_print.hpp
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns and instance of bsl::out<T>
    ///
    [[nodiscard]] constexpr auto
    print() noexcept -> out<details::out_type_print>
    {
        return {};
    }

    /// <!-- description -->
    ///   @brief Returns and instance of bsl::out<T>. This version of
    ///     bsl::out<T> prints "DEBUG: " when created and accepts
    ///     a debug level, allowing it to be disabled. All output
    ///     is redirected to bsl::details::putc_stdout and
    ///     bsl::details::puts_stdout. See bsl::fmt for formatting
    ///     documentation and examples.
    ///   @include debug/example_debug_debug.hpp
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns and instance of bsl::out<T>
    ///
    template<bsl::uintmax DL = 0>
    [[nodiscard]] constexpr auto
    debug() noexcept -> out_t<DL, details::out_type_debug>
    {
        // False positive
        // NOLINTNEXTLINE(cppcoreguidelines-init-variables)
        out_t<DL, details::out_type_debug> o{};

        if constexpr (!o) {
            return o;
        }

        o << '[' << bsl::cyan << details::thread_id() << bsl::reset_color << "]: ";
        return o;
    }

    /// <!-- description -->
    ///   @brief Returns and instance of bsl::out<T>. This version of
    ///     bsl::out<T> prints "ALERT: " when created and accepts
    ///     a debug level, allowing it to be disabled. All output
    ///     is redirected to bsl::details::putc_stderr and
    ///     bsl::details::puts_stderr. See bsl::fmt for formatting
    ///     documentation and examples.
    ///   @include debug/example_debug_alert.hpp
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns and instance of bsl::out<T>
    ///
    template<bsl::uintmax DL = 0>
    [[nodiscard]] constexpr auto
    alert() noexcept -> out_t<DL, details::out_type_alert>
    {
        // False positive
        // NOLINTNEXTLINE(cppcoreguidelines-init-variables)
        out_t<DL, details::out_type_alert> o{};

        if constexpr (!o) {
            return o;
        }

        o << '[' << bsl::cyan << details::thread_id() << bsl::reset_color << "]: ";
        return o;
    }

    /// <!-- description -->
    ///   @brief Returns and instance of bsl::out<T>. This version of
    ///     bsl::out<T> prints "ERROR: " when created and does not accept
    ///     a debug level (as it cannot be turned off). All output
    ///     is redirected to bsl::details::putc_stderr and
    ///     bsl::details::puts_stderr. See bsl::fmt for formatting
    ///     documentation and examples.
    ///   @include debug/example_debug_error.hpp
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns and instance of bsl::out<T>
    ///
    [[nodiscard]] constexpr auto
    error() noexcept -> out<details::out_type_error>
    {
        // False positive
        // NOLINTNEXTLINE(cppcoreguidelines-init-variables)
        out<details::out_type_error> o{};

        o << '[' << bsl::cyan << details::thread_id() << bsl::reset_color << "]: ";
        return o;
    }
}

#endif
