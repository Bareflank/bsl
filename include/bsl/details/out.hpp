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
/// @file out.hpp
///

#ifndef BSL_OUT_HPP
#define BSL_OUT_HPP

#include "out_type_alert.hpp"
#include "out_type_debug.hpp"
#include "out_type_empty.hpp"
#include "out_type_error.hpp"
#include "out_type_print.hpp"
#include "putc_stdout.hpp"
#include "putc_stderr.hpp"
#include "puts_stdout.hpp"
#include "puts_stderr.hpp"

#include "../color.hpp"
#include "../char_type.hpp"
#include "../cstr_type.hpp"
#include "../is_same.hpp"

namespace bsl
{
    /// @class bsl::out
    ///
    /// <!-- description -->
    ///   @brief Used to output characters and strings to stdout and stderr.
    ///     This class accepts "labels" which determines whether the output
    ///     goes to stdout or stderr and whether or not a prefix is printed
    ///     such as "DEBUG". Note that this class is written such that it
    ///     is completely compiled out during compilation as it has not
    ///     member variables, or non-static member functions (i.e., everything
    ///     is a constexpr). Note that you should not use this class
    ///     directly but instead should use one of the functions from debug.hpp
    //.     which ensures debug levels are handled properly. The only time
    //      your code might use this class is when defining your own fmt_impl
    //      function for overloading fmt.
    ///
    /// <!-- notes -->
    ///   @note This class exists in the details folder because it is
    ///     private to the BSL, but it does not exist in the details namespace
    ///     as it is used by the fmt_impl functions which can be overloaded
    ///     by the user.
    ///
    /// <!-- template parameters -->
    ///   @tparam T Defines the type of label used.
    ///
    template<typename T>
    class out final
    {
    public:
        /// <!-- description -->
        ///   @brief Default constructor. Creates a bsl::out, which ensures
        ///     synchronization of other bsl::out operations as well as
        ///     adds a label if needed.
        ///
        constexpr out() noexcept
        {
            if constexpr (is_debug()) {
                write(bsl::bold_green);
                write("DEBUG ");
                write(bsl::reset_color);
            }

            if constexpr (is_alert()) {
                write(bsl::bold_yellow);
                write("ALERT ");
                write(bsl::reset_color);
            }

            if constexpr (is_error()) {
                write(bsl::bold_red);
                write("ERROR ");
                write(bsl::reset_color);
            }
        }

        /// <!-- description -->
        ///   @brief Returns true if this bsl::out represents an empty out
        ///     operation which will ignore all commands given to it. This
        ///     occurs when the debug statement's debug level is greater
        ///     than the current global debug level.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if this bsl::out represents an empty out
        ///     operation which will ignore all commands given to it. This
        ///     occurs when the debug statement's debug level is greater
        ///     than the current global debug level.
        ///
        [[nodiscard]] static constexpr bool
        empty() noexcept
        {
            return is_same<T, details::out_type_empty>::value;
        }

        /// <!-- description -->
        ///   @brief Returns !empty()
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns !empty()
        ///
        [[nodiscard]] constexpr explicit operator bool() const noexcept
        {
            return !is_same<T, details::out_type_empty>::value;
        }

        /// <!-- description -->
        ///   @brief Returns true if this bsl::out functions as a print()
        ///     which outputs to stdout and does not contain a label.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if this bsl::out functions as a print()
        ///     which outputs to stdout and does not contain a label.
        ///
        [[nodiscard]] static constexpr bool
        is_print() noexcept
        {
            return is_same<T, details::out_type_print>::value;
        }

        /// <!-- description -->
        ///   @brief Returns true if this bsl::out functions as a debug()
        ///     which outputs to stdout and contains the "DEBUG" label.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if this bsl::out functions as a debug()
        ///     which outputs to stdout and contains the "DEBUG" label.
        ///
        [[nodiscard]] static constexpr bool
        is_debug() noexcept
        {
            return is_same<T, details::out_type_debug>::value;
        }

        /// <!-- description -->
        ///   @brief Returns true if this bsl::out functions as an alert()
        ///     which outputs to stderr and contains the "ALERT" label.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if this bsl::out functions as an alert()
        ///     which outputs to stderr and contains the "ALERT" label.
        ///
        [[nodiscard]] static constexpr bool
        is_alert() noexcept
        {
            return is_same<T, details::out_type_alert>::value;
        }

        /// <!-- description -->
        ///   @brief Returns true if this bsl::out functions as an error()
        ///     which outputs to stderr and contains the "ERROR" label.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if this bsl::out functions as an error()
        ///     which outputs to stderr and contains the "ERROR" label.
        ///
        [[nodiscard]] static constexpr bool
        is_error() noexcept
        {
            return is_same<T, details::out_type_error>::value;
        }

        /// <!-- description -->
        ///   @brief Outputs a character to either stdout or stderr,
        ///     depending on the bsl::out's label.
        ///
        /// <!-- inputs/outputs -->
        ///   @param c the character to output
        ///
        static constexpr void
        write(char_type const c) noexcept
        {
            if constexpr (is_print()) {
                details::putc_stdout(c);
            }

            if constexpr (is_debug()) {
                details::putc_stdout(c);
            }

            if constexpr (is_alert()) {
                details::putc_stderr(c);
            }

            if constexpr (is_error()) {
                details::putc_stderr(c);
            }
        }

        /// <!-- description -->
        ///   @brief Outputs a string to either stdout or stderr,
        ///     depending on the bsl::out's label. The string must end in
        ///     a '\0'.
        ///
        /// <!-- inputs/outputs -->
        ///   @param str the string to output
        ///
        static constexpr void
        write(cstr_type const str) noexcept
        {
            if constexpr (is_print()) {
                details::puts_stdout(str);
            }

            if constexpr (is_debug()) {
                details::puts_stdout(str);
            }

            if constexpr (is_alert()) {
                details::puts_stderr(str);
            }

            if constexpr (is_error()) {
                details::puts_stderr(str);
            }
        }
    };
}

#endif
