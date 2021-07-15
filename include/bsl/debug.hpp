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

#include "bool_constant.hpp"
#include "char_type.hpp"
#include "color.hpp"
#include "conditional.hpp"
#include "cstdint.hpp"
#include "details/out.hpp"
#include "details/out_type_alert.hpp"
#include "details/out_type_debug.hpp"
#include "details/out_type_empty.hpp"
#include "details/out_type_error.hpp"
#include "details/out_type_print.hpp"
#include "disjunction.hpp"
#include "fmt.hpp"
#include "is_constant_evaluated.hpp"
#include "safe_integral.hpp"
#include "source_location.hpp"

#include <bsl/details/print_thread_id.hpp>

namespace bsl
{
    /// @brief defines the default verbose mode
    constexpr bsl::uintmax CRITICAL_ONLY{static_cast<bsl::uintmax>(0)};
    /// @brief defines "-v" verbose mode
    constexpr bsl::uintmax V{static_cast<bsl::uintmax>(1)};
    /// @brief defines "-vv" verbose mode
    constexpr bsl::uintmax VV{static_cast<bsl::uintmax>(2)};
    /// @brief defines "-vvv" verbose mode
    constexpr bsl::uintmax VVV{static_cast<bsl::uintmax>(3)};

    /// @brief newline constant
    constexpr bsl::char_type endl{'\n'};

    namespace details
    {
        /// @brief used to disable debugging for debug() and alert()
        ///
        /// <!-- template parameters -->
        ///   @tparam DL the debug level this out statement uses
        ///   @tparam T the type of out statement being used
        ///
        template<bsl::uintmax DL, typename T>
        using out_type =    // --
            conditional_t <
            disjunction<
                bool_constant<DL<BSL_DEBUG_LEVEL>, bool_constant<BSL_DEBUG_LEVEL == DL>>::value,
                out<T>,
                out<out_type_empty>>;
    }

    /// <!-- description -->
    ///   @brief Returns true if the debug level was set to at least V or
    ///     higher.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns true if the debug level was set to at least V or
    ///     higher.
    ///
    [[nodiscard]] constexpr auto
    debug_level_is_at_least_v() noexcept -> bool
    {
        // NOLINTNEXTLINE(misc-redundant-expression)
        return bool_constant<BSL_DEBUG_LEVEL >= bsl::V>::value;
    }

    /// <!-- description -->
    ///   @brief Returns true if the debug level was set to at least V or
    ///     higher.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns true if the debug level was set to at least V or
    ///     higher.
    ///
    [[nodiscard]] constexpr auto
    debug_level_is_at_least_vv() noexcept -> bool
    {
        // NOLINTNEXTLINE(misc-redundant-expression)
        return bool_constant<BSL_DEBUG_LEVEL >= bsl::VV>::value;
    }

    /// <!-- description -->
    ///   @brief Returns true if the debug level was set to at least V or
    ///     higher.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns true if the debug level was set to at least V or
    ///     higher.
    ///
    [[nodiscard]] constexpr auto
    debug_level_is_at_least_vvv() noexcept -> bool
    {
        // NOLINTNEXTLINE(misc-redundant-expression)
        return bool_constant<BSL_DEBUG_LEVEL >= bsl::VVV>::value;
    }

    /// <!-- description -->
    ///   @brief Returns and instance of bsl::out<T>. This version of
    ///     bsl::out<T> does not print a label and does not accept
    ///     a debug level (as it cannot be turned off). All output
    ///     is redirected to bsl::details::putc_stdout and
    ///     bsl::details::puts_stdout. See fmt for formatting
    ///     documentation and examples.
    ///   @include debug/example_debug_print.hpp
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam DL the debug level for this out statement
    ///   @return Returns and instance of bsl::out<T>
    ///
    template<bsl::uintmax DL = CRITICAL_ONLY>
    [[nodiscard]] constexpr auto
    print() noexcept -> details::out_type<DL, details::out_type_print>
    {
        // False positive
        // NOLINTNEXTLINE(cppcoreguidelines-init-variables)
        return details::out_type<DL, details::out_type_print>{};
    }

    /// <!-- description -->
    ///   @brief Returns and instance of bsl::out<T>. This version of
    ///     bsl::out<T> prints "DEBUG: " when created and accepts
    ///     a debug level, allowing it to be disabled. All output
    ///     is redirected to bsl::details::putc_stdout and
    ///     bsl::details::puts_stdout. See fmt for formatting
    ///     documentation and examples.
    ///   @include debug/example_debug_debug.hpp
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam DL the debug level for this out statement
    ///   @return Returns and instance of bsl::out<T>
    ///
    template<bsl::uintmax DL = CRITICAL_ONLY>
    [[nodiscard]] constexpr auto
    debug() noexcept -> details::out_type<DL, details::out_type_debug>
    {
        // False positive
        // NOLINTNEXTLINE(cppcoreguidelines-init-variables)
        details::out_type<DL, details::out_type_debug> const o{};

        if (is_constant_evaluated()) {
            return o;
        }

        if constexpr (!o) {
            return o;
        }

        o << bsl::bold_green << "DEBUG" << bsl::reset_color;
        details::print_thread_id(o);
        o << ": ";

        return o;
    }

    /// <!-- description -->
    ///   @brief Returns and instance of bsl::out<T>. This version of
    ///     bsl::out<T> prints "ALERT: " when created and accepts
    ///     a debug level, allowing it to be disabled. All output
    ///     is redirected to bsl::details::putc_stderr and
    ///     bsl::details::puts_stderr. See fmt for formatting
    ///     documentation and examples.
    ///   @include debug/example_debug_alert.hpp
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam DL the debug level for this out statement
    ///   @return Returns and instance of bsl::out<T>
    ///
    template<bsl::uintmax DL = CRITICAL_ONLY>
    [[nodiscard]] constexpr auto
    alert() noexcept -> details::out_type<DL, details::out_type_alert>
    {
        // False positive
        // NOLINTNEXTLINE(cppcoreguidelines-init-variables)
        details::out_type<DL, details::out_type_alert> const o{};

        if (is_constant_evaluated()) {
            return o;
        }

        if constexpr (!o) {
            return o;
        }

        o << bsl::bold_yellow << "ALERT" << bsl::reset_color;
        details::print_thread_id(o);
        o << ": ";

        return o;
    }

    /// <!-- description -->
    ///   @brief Returns and instance of bsl::out<T>. This version of
    ///     bsl::out<T> prints "ERROR: " when created and does not accept
    ///     a debug level (as it cannot be turned off). All output
    ///     is redirected to bsl::details::putc_stderr and
    ///     bsl::details::puts_stderr. See fmt for formatting
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
        out<details::out_type_error> const o{};

        o << bsl::bold_red << "ERROR" << bsl::reset_color;
        details::print_thread_id(o);
        o << ": ";

        return o;
    }

    /// <!-- description -->
    ///   @brief Outputs the provided bsl::source_location to the provided
    ///     output type.
    ///   @related bsl::source_location
    ///   @include source_location/example_source_location_ostream.hpp
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of outputter provided
    ///   @param o the instance of the outputter used to output the value.
    ///   @param sloc the bsl::source_location to output
    ///   @return return o
    ///
    template<typename T>
    [[maybe_unused]] constexpr auto
    operator<<(out<T> const o, source_location const &sloc) noexcept -> out<T>
    {
        if (is_constant_evaluated()) {
            return o;
        }

        if constexpr (!o) {
            return o;
        }

        if constexpr (BSL_DEBUG_LEVEL != bsl::CRITICAL_ONLY) {
            o << "  --> "                                                       // --
              << bsl::yellow << sloc.file_name() << bsl::reset_color            // --
              << bsl::cyan << " [" << sloc.line() << ']' << bsl::reset_color    // --
              << ": "                                                           // --
              << sloc.function_name()                                           // --
              << bsl::endl;                                                     // --
        }

        return o;
    }

    /// <!-- description -->
    ///   @brief This provides a less verbose version of
    ///     bsl::source_location::current() to help reduce how large this
    ///     code must be. They are equivalent, and should not produce any
    ///     additional overhead in release mode.
    ///
    /// <!-- inputs/outputs -->
    ///   @param sloc the source_location object corresponding to
    ///     the location of the call site.
    ///   @return the source_location object corresponding to
    ///     the location of the call site.
    ///
    [[nodiscard]] constexpr auto
    here(source_location const &sloc = source_location::current()) noexcept -> source_location
    {
        return sloc;
    }

    /// <!-- description -->
    ///   @brief Returns fmt{"#04x", val}
    ///
    /// <!-- inputs/outputs -->
    ///   @param val the value to input into fmt
    ///   @return Returns fmt{"#04x", val}
    ///
    [[nodiscard]] constexpr auto
    hex(safe_uint8 const &val) noexcept -> fmt<safe_uint8>
    {
        constexpr fmt_options ops{"#04x"};
        return fmt{ops, val};
    }

    /// <!-- description -->
    ///   @brief Returns fmt{"#04x", val}
    ///
    /// <!-- inputs/outputs -->
    ///   @param val the value to input into fmt
    ///   @return Returns fmt{"#04x", val}
    ///
    [[nodiscard]] constexpr auto
    hex(bsl::uint8 const val) noexcept -> fmt<bsl::uint8>
    {
        constexpr fmt_options ops{"#04x"};
        return fmt{ops, val};
    }

    /// <!-- description -->
    ///   @brief Returns fmt{"#06x", val}
    ///
    /// <!-- inputs/outputs -->
    ///   @param val the value to input into fmt
    ///   @return Returns fmt{"#06x", val}
    ///
    [[nodiscard]] constexpr auto
    hex(safe_uint16 const &val) noexcept -> fmt<safe_uint16>
    {
        constexpr fmt_options ops{"#06x"};
        return fmt{ops, val};
    }

    /// <!-- description -->
    ///   @brief Returns fmt{"#06x", val}
    ///
    /// <!-- inputs/outputs -->
    ///   @param val the value to input into fmt
    ///   @return Returns fmt{"#06x", val}
    ///
    [[nodiscard]] constexpr auto
    hex(bsl::uint16 const val) noexcept -> fmt<bsl::uint16>
    {
        constexpr fmt_options ops{"#06x"};
        return fmt{ops, val};
    }

    /// <!-- description -->
    ///   @brief Returns fmt{"#010x", val}
    ///
    /// <!-- inputs/outputs -->
    ///   @param val the value to input into fmt
    ///   @return Returns fmt{"#010x", val}
    ///
    [[nodiscard]] constexpr auto
    hex(safe_uint32 const &val) noexcept -> fmt<safe_uint32>
    {
        constexpr fmt_options ops{"#010x"};
        return fmt{ops, val};
    }

    /// <!-- description -->
    ///   @brief Returns fmt{"#010x", val}
    ///
    /// <!-- inputs/outputs -->
    ///   @param val the value to input into fmt
    ///   @return Returns fmt{"#010x", val}
    ///
    [[nodiscard]] constexpr auto
    hex(bsl::uint32 const val) noexcept -> fmt<bsl::uint32>
    {
        constexpr fmt_options ops{"#010x"};
        return fmt{ops, val};
    }

    /// <!-- description -->
    ///   @brief Returns fmt{"#018x", val}
    ///
    /// <!-- inputs/outputs -->
    ///   @param val the value to input into fmt
    ///   @return Returns fmt{"#018x", val}
    ///
    [[nodiscard]] constexpr auto
    hex(safe_uint64 const &val) noexcept -> fmt<safe_uint64>
    {
        constexpr fmt_options ops{"#018x"};
        return fmt{ops, val};
    }

    /// <!-- description -->
    ///   @brief Returns fmt{"#018x", val}
    ///
    /// <!-- inputs/outputs -->
    ///   @param val the value to input into fmt
    ///   @return Returns fmt{"#018x", val}
    ///
    [[nodiscard]] constexpr auto
    hex(bsl::uint64 const val) noexcept -> fmt<bsl::uint64>
    {
        constexpr fmt_options ops{"#018x"};
        return fmt{ops, val};
    }
}

#endif
