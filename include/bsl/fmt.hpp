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
/// @file fmt.hpp
///

#ifndef BSL_FMT_HPP
#define BSL_FMT_HPP

#include "details/fmt_impl_char_type.hpp"
#include "details/fmt_impl_cstr_type.hpp"
#include "details/fmt_impl_bool.hpp"
#include "details/fmt_impl_integral.hpp"
#include "details/fmt_impl_null_pointer.hpp"
#include "details/fmt_impl_void_pointer.hpp"

#include "details/out.hpp"

#include "cstdint.hpp"
#include "enable_if.hpp"
#include "forward.hpp"
#include "fmt_options.hpp"
#include "is_bool.hpp"
#include "is_integral.hpp"
#include "is_null_pointer.hpp"
#include "is_same.hpp"
#include "is_pointer.hpp"
#include "move.hpp"

namespace bsl
{
    /// @class bsl::fmt
    ///
    /// <!-- description -->
    ///   @brief The bsl::fmt implements a similar syntax to that of
    ///     std::format, We adopt a similar approach with some tweaks of
    ///     course to ensure AUTOSAR compliance include:
    ///     - printf style syntax is not supported and instead we use the
    ///       std::cout approach with << operators, but using the std::format
    ///       compressed syntax approach. This addresses most of the issues
    ///       of both libraries. The std::cout << approach ensures that the
    ///       position of an argument is coupled with the argument itself,
    ///       meaning there is no need to "verify" that the number of arguments
    ///       or the position of an argument matches the format string,
    ///       which is an issue with std::format. The rest of the std::cout
    ///       library is horrible in almost every way. All of the formatters
    ///       are global, and the syntax is obnoxiously verbose.
    ///       The std::format syntax addresses both of these.
    ///     - Since our approach uses << instead of a printf style format
    ///       string, there is no need for "{}" or ":" as positioning is
    ///       handled by the code itself, so these are not included to further
    ///       reduce the verbosity (although AUTOSAR requires that you use
    ///       the full bsl::fmt{} syntax, so its a wash).
    ///     - Octal is not supported as it is not supported by AUTOSAR.
    ///     - Floating point is currently not supported, but that can be
    ///       changed in the future if needed as that is not an AUTOSAR
    ///       limitation, it was simply not required in the first iteration
    ///       of this library. If you need floating point support, please
    ///       contact us.
    ///     - In our library, there is no difference between x/X and b/B.
    ///       If you need this, and know what it means please contact us.
    ///       This was mainly done because we prefer 0x with uppercase
    ///       letters which is currently not an option with std::format.
    ///
    /// <b>General Syntax:</b><br>
    /// @code
    /// fill-and-align(optional) sign(optional) #(optional) 0(optional) width(optional) type(optional)
    /// @endcode
    ///
    /// The sign, # and 0 options are only valid when an integer type is being
    /// formatted.
    ///
    /// <b>Rules for Optional Field [fill-and-align]:</b><br>
    /// The fill-and-align option tells bsl::fmt how to align the resulting
    /// output. The fill states what character should be used as padding
    /// (defaults to a space), and can be any character (except for '\0'
    /// which would result in UB). The align character determines the
    /// type of justification (either left, right or center). If the width
    /// field is missing, the fill-and-align field has no effect. In addition,
    /// if this field is combined with the '0' sign aware field, this field
    /// has no effect.
    /// - '<': Forces the field to be aligned to the start of the available
    ///   space. This is the default for non-integer types
    /// - '>': Forces the field to be aligned to the end of the available
    ///   space. This is the default for integer types
    /// - '^': Forces the field to be centered within the available space.
    ///   If the alignment results in an uneven number of fill characters,
    ///   the right side of the alignment gets the extra fill character.
    ///
    /// @include fmt/example_fmt_align.hpp
    ///
    /// Results in the following output:
    /// @code
    /// 42
    ///         42
    ///     42
    /// 42........
    /// ........42
    /// ....42....
    /// ==============================
    /// ------------------------------
    /// ______________________________
    /// @endcode
    ///
    /// <b>Rules for Optional Field [sign]:</b><br>
    /// The sign option states how an integer type should display its positive
    /// or negative sign.
    /// - '+': Indicates that '+' is inserted for positive numbers
    ///   while '-' is inserted for negative numbers.
    /// - '-': Indicates that only '-' is inserted for negative numbers
    /// - ' ': Indicates that ' ' is inserted for positive numbers
    ///   while '-' is inserted for negative numbers.
    ///
    /// @include fmt/example_fmt_sign.hpp
    ///
    /// Results in the following output:
    /// @code
    /// +42
    /// -42
    /// 42
    /// -42
    ///  42
    /// -42
    /// @endcode
    ///
    /// <b>Rules for Optional Field [#]:</b><br>
    /// The # option enables the alternative form for integer types. If the
    /// type field is missing, this option is ignored.
    /// - 's': ignored
    /// - 'c': ignored
    /// - 'b': Indicates that "0b" should be inserted for binary numbers
    /// - 'B': Indicates that "0b" should be inserted for binary numbers
    /// - 'd': ignored
    /// - 'x': Indicates that "0x" should be inserted for hexidecimal numbers
    /// - 'X': Indicates that "0x" should be inserted for hexidecimal numbers
    ///
    /// @include fmt/example_fmt_alt_form.hpp
    ///
    /// Results in the following output:
    /// @code
    /// 0b101010
    /// 42
    /// 0x2A
    /// @endcode
    ///
    /// <b>Rules for Optional Field [0]:</b><br>
    /// The 0 option enables the use of sign aware 0 padding. If this field
    /// is combined with the fill-and-align field, the fill-and-align field
    /// is ignored. The problem with fill-and-align is that if you want to,
    /// for example, output the hexidecimal number 0x2A as 0x002A, there is
    /// no way to do that with fill-and-align as the 0s would be on the
    /// wrong side of '0x'. Therefore, this option ignores fill-and-align
    /// and instead uses the width field to determine how many 0s to add to
    /// the output in the correct position within the output. Like
    /// fill-and-align, if the width field is missing, this option has no
    /// effect.
    /// - 's': ignored
    /// - 'c': ignored
    /// - 'b': Inserts 0 to the right of sign and # and to the left of b
    /// - 'B': Inserts 0 to the right of sign and # and to the left of B
    /// - 'd': Inserts 0 to the right of sign and to the left of d
    /// - 'x': Inserts 0 to the right of sign and # and to the left of x
    /// - 'X': Inserts 0 to the right of sign and # and to the left of X
    ///
    /// @include fmt/example_fmt_sign_aware.hpp
    ///
    /// Results in the following output:
    /// @code
    ///   0b101010
    ///       0x2A
    /// 0b00101010
    /// 0x0000002A
    /// @endcode
    ///
    /// <b>Rules for Optional Field [width]:</b><br>
    /// Unlike std::format, negative numbers are not supported. The width field
    /// determines the total length of the resulting output, with all options
    /// included. In addition, the bsl::fmt library supports dynamic width as
    /// well. If the dynamic width is provided, this field is ignored and the
    /// dynamic width is used instead.
    ///
    /// @include fmt/example_fmt_width.hpp
    ///
    /// Results in the following output:
    /// @code
    /// 42
    ///         42
    ///     42
    /// 0b00101010
    /// 0x0000002A
    /// 0b00101010
    /// 0x0000002A
    /// @endcode
    ///
    /// <b>type rules [bool]:</b><br>
    /// If bsl::fmt{} is given a boolean, the type field indicates the
    /// following:
    /// - none, 's': outputs "true" or "false"
    /// - 'b', 'B', 'c', 'd', 'x', 'X': outputs "1" or "0"
    ///
    /// @include fmt/example_fmt_bool.hpp
    ///
    /// Results in the following output:
    /// @code
    /// true
    /// false
    /// 1
    /// 0
    /// @endcode
    ///
    /// <b>type rules [bsl::char_type]:</b><br>
    /// If bsl::fmt{} is given a bsl::char_type, the type field indicates the
    /// following:
    /// - none, 's', 'c': outputs the ascii representation of the character
    /// - 'b', 'B', 'd', 'x', 'X': uses static_cast<bsl::uint8>() to convert
    ///   the character type and then uses the integral rules defined below.
    ///
    /// @include fmt/example_fmt_char_type.hpp
    ///
    /// Results in the following output:
    /// @code
    /// *
    /// 101010
    /// 42
    /// 2A
    /// @endcode
    ///
    /// <b>type rules [bsl::cstr_type]:</b><br>
    /// If bsl::fmt{} is given a bsl::cstr_type, the type field indicates the
    /// following:
    /// - none, 's': outputs string.
    ///
    /// @include fmt/example_fmt_cstr_type.hpp
    ///
    /// Results in the following output:
    /// @code
    /// success
    /// @endcode
    ///
    /// <b>type rules [integral]:</b><br>
    /// If bsl::fmt{} is given an integral type, the type field indicates the
    /// following:
    /// - none, 'd': the number is outputted as a decimal.
    /// - 'c': uses static_cast<bsl::char_type>() to convert the integral type
    ///   and then uses the bsl::char_type rules defined above.
    /// - 'b': the number is outputted as a binary.
    /// - 'B': the number is outputted as a binary.
    /// - 'x': the number is outputted as a hexidecimal.
    /// - 'X': the number is outputted as a hexidecimal.
    ///
    /// @include fmt/example_fmt_integral.hpp
    ///
    /// Results in the following output:
    /// @code
    /// 42
    /// 101010
    /// *
    /// 2A
    ///
    /// 0b101010
    /// 0x2A
    ///
    /// 0b101010
    /// 0x00002A
    ///
    /// +42
    /// -42
    ///
    /// 42
    /// -42
    /// @endcode
    ///
    /// For all other types, the BSL provides the "<<" syntax, but the use
    /// of bsl::fmt is not supported.
    ///
    /// If you wish to implement support for your own types, you can do
    /// so why overloading the following function in the "bsl" namespace
    /// @code
    /// template<typename OUT>
    /// constexpr void
    /// fmt_impl(OUT &&o, fmt_options const &ops, <type> const &val) noexcept
    /// {
    ///     ...
    /// }
    /// @endcode
    ///
    /// You can also overload the following if you wish to provide output
    /// support but do not wish to provide bsl::fmt{} support (this option
    /// will result in more efficient code):
    /// @code
    /// template<typename T>
    /// [[maybe_unused]] constexpr out<T>
    /// operator<<(out<T> const o, <type> const &val) noexcept
    /// {
    ///     if constexpr (o.empty()) {
    ///         return o;
    ///     }
    ///
    ///     ...
    /// }
    /// @endcode
    ///
    /// <!-- template parameters -->
    ///   @tparam V the type of value being formatted for output
    ///
    template<typename V>
    class fmt final
    {
        /// @brief stores the fmt options for this bsl::fmt
        fmt_options m_ops;
        /// @brief stores a reference to the provided val.
        V const &m_val;

    public:
        /// <!-- description -->
        ///   @brief Creates a bsl::fmt, which when passed to an outputter
        ///     will output the provided value given the provided format
        ///     string.
        ///   @include fmt/example_fmt_constructor_f_val.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param ops the format options used to format the output of val
        ///   @param val the value to output given the provided format string
        ///
        constexpr fmt(fmt_options const &ops, V const &val) noexcept    // --
            : m_ops{ops}, m_val{val}
        {}

        /// <!-- description -->
        ///   @brief Creates a bsl::fmt, which when passed to an outputter
        ///     will output the provided value given the provided format
        ///     string. Note that this version also accepts a dynamic width,
        ///     meaning the width can be determined at runtime. If the width
        ///     is provided, the width in the format string is ignored.
        ///   @include fmt/example_fmt_constructor_f_val_width.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param ops the format options used to format the output of val
        ///   @param val the value to output given the provided format string
        ///   @param width a dynamic width which overrides the width field
        ///     in the format string (used to set the width field at runtime).
        ///
        constexpr fmt(fmt_options const &ops, V const &val, bsl::uintmax width) noexcept
            : m_ops{ops}, m_val{val}
        {
            constexpr bsl::uintmax max_width{1000U};
            if (width > max_width) {
                width = max_width - 1U;
            }

            m_ops.set_width(width);
        }

        /// <!-- description -->
        ///   @brief Creates a bsl::fmt, which when passed to an outputter
        ///     will output the provided value given the provided format
        ///     string.
        ///   @include fmt/example_fmt_constructor_f_val.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param str the format options used to format the output of val
        ///   @param val the value to output given the provided format string
        ///
        constexpr fmt(cstr_type const str, V const &val) noexcept    // --
            : fmt{fmt_options{str}, val}
        {}

        /// <!-- description -->
        ///   @brief Creates a bsl::fmt, which when passed to an outputter
        ///     will output the provided value given the provided format
        ///     string. Note that this version also accepts a dynamic width,
        ///     meaning the width can be determined at runtime. If the width
        ///     is provided, the width in the format string is ignored.
        ///   @include fmt/example_fmt_constructor_f_val_width.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param str the format options used to format the output of val
        ///   @param val the value to output given the provided format string
        ///   @param width a dynamic width which overrides the width field
        ///     in the format string (used to set the width field at runtime).
        ///
        constexpr fmt(cstr_type const str, V const &val, bsl::uintmax const width) noexcept
            : fmt{fmt_options{str}, val, width}
        {}

        /// <!-- description -->
        ///   @brief Outputs the provided formatted argument to the provided
        ///     output type.
        ///   @related bsl::fmt
        ///
        /// <!-- notes -->
        ///   @note We make this a friend of bsl::fmt as there is no way
        ///     to define a stream operator as a member function. As a result,
        ///     this would require the use of a public member function that
        ///     would expose the const&, potentially leading to UB.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T the type of outputter provided
        ///   @tparam U the type of value being ouputter using bsl::fmt
        ///   @param o the instance of the outputter used to output the value.
        ///   @param arg a bsl::fmt that contains the value being outputted as
        ///     well as any format instructions.
        ///   @return return o
        ///
        template<typename T, typename U>
        friend constexpr out<T>
        operator<<(out<T> const o, fmt<U> &&arg) noexcept;    // PRQA S 2107 // NOLINT
    };

    /// <!-- description -->
    ///   @brief Outputs the provided formatted argument to the provided
    ///     output type. If you want to provide your own custom outputter,
    ///     DO NOT overload this function. Instead, overload the fmt_impl
    ///     function.
    ///   @related bsl::fmt
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of outputter provided
    ///   @tparam U the type of value being ouputter using bsl::fmt
    ///   @param o the instance of the outputter used to output the value.
    ///   @param arg a bsl::fmt that contains the value being outputted as
    ///     well as any format instructions.
    ///   @return return o
    ///
    template<typename T, typename U>
    [[maybe_unused]] constexpr out<T>
    operator<<(out<T> const o, fmt<U> &&arg) noexcept
    {
        if constexpr (o.empty()) {
            return o;
        }

        fmt_impl(o, arg.m_ops, arg.m_val);    // NOLINT
        return o;
    }

    /// <!-- description -->
    ///   @brief Outputs the provided argument to the provided
    ///     output type. If you want to provide your own custom outputter,
    ///     DO NOT overload this function. Instead, overload the fmt_impl
    ///     function.
    ///   @related bsl::fmt
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of outputter provided
    ///   @tparam U the type of value being ouputter using bsl::fmt
    ///   @param o the instance of the outputter used to output the value.
    ///   @param arg the value to output
    ///   @return return o
    ///
    template<
        typename T,
        typename U,
        enable_if_t<!is_bool<U>::value, bool> = true,
        enable_if_t<!is_same<U, char_type>::value, bool> = true,
        enable_if_t<!is_pointer<U>::value, bool> = true,
        enable_if_t<!is_integral<U>::value, bool> = true,
        enable_if_t<!is_null_pointer<U>::value, bool> = true>
    [[maybe_unused]] constexpr out<T>
    operator<<(out<T> const o, U const &arg) noexcept
    {
        if constexpr (o.empty()) {
            return o;
        }

        fmt_impl(o, nullops, arg);    // NOLINT
        return o;
    }
}

#endif
