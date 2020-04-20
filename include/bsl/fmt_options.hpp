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
/// @file fmt_options.hpp
///

#ifndef BSL_FMT_OPTIONS_HPP
#define BSL_FMT_OPTIONS_HPP

#include "char_type.hpp"
#include "convert.hpp"
#include "cstr_type.hpp"
#include "cstdint.hpp"
#include "cstring.hpp"
#include "npos.hpp"
#include "safe_integral.hpp"

// TODO
// - Once Clang/LLVM supports C++20's consteval, we should determine if
//   consteval can be used with this class's constructors, which would
//   ensure that all format strings are parsed at compile-time. We
//   should also add error logic to the parsers as errors can then be
//   detected at compile-time, preventing the possibility of format string
//   errors.
//

namespace bsl
{
    namespace details
    {
        /// @enum bsl::details::fmt_fsm
        ///
        /// <!-- description -->
        ///   @brief Used to define a finite state machine that is used to
        ///     parse the {fmt} style syntax for formatting. Although there
        ///     are many ways to implement a parser, the FSM proved to be
        ///     a really simple approach, even though the FSM in this case
        ///     is overly simplified. What makes this approach so simple is
        ///     each field is accounted for in the FSM, yet each parser is
        ///     optional based on what the user provides, so everything is
        ///     accounted for.
        ///
        enum class fmt_fsm : bsl::uint32
        {
            fmt_fsm_align = 0U,
            fmt_fsm_sign = 1U,
            fmt_fsm_alternate_form = 2U,
            fmt_fsm_sign_aware = 3U,
            fmt_fsm_width = 4U,
            fmt_fsm_type = 5U,
        };
    }

    /// @enum bsl::fmt_align
    ///
    /// <!-- description -->
    ///   @brief Used to determine what the alignment of the output
    ///     should be. If the width is not defined, this field does
    ///     nothing.
    ///
    enum class fmt_align : bsl::uint32
    {
        fmt_align_default = 0U,
        fmt_align_left = 1U,
        fmt_align_right = 2U,
        fmt_align_center = 3U
    };

    /// @enum bsl::fmt_sign
    ///
    /// <!-- description -->
    ///   @brief Used to determine how an integral's sign field is
    ///     handled. This only has an effect on signed types.
    ///
    enum class fmt_sign : bsl::uint32
    {
        fmt_sign_neg_only = 0U,
        fmt_sign_pos_neg = 1U,
        fmt_sign_space_for_pos = 3U,
    };

    /// @enum bsl::fmt_type
    ///
    /// <!-- description -->
    ///   @brief Used to determine how to output an unsigned integer
    ///     type (either as hex or dec). All ofther {fmt} types are
    ///     currently not supported and this has no effect on signed
    ///     integer types.
    ///
    enum class fmt_type : bsl::uint32
    {
        fmt_type_default = 0U,
        fmt_type_b = 1U,
        fmt_type_c = 2U,
        fmt_type_d = 3U,
        fmt_type_s = 4U,
        fmt_type_x = 5U,
    };

    /// @class bsl::fmt_options
    ///
    /// <!-- description -->
    ///   @brief Used by fmt to determine how to format the output
    ///     of an fmt command. See the documentation fo bsl::fmt for
    ///     more information.
    ///
    ///   @var bsl::fmt_options::fill
    ///     defines
    ///   @var bsl::fmt_options::align
    ///     defines the "align" field in the {fmt} syntax
    ///   @var bsl::fmt_options::sign
    ///     defines the "sign" field in the {fmt} syntax
    ///   @var bsl::fmt_options::alternate_form
    ///     defines the "#" field in the {fmt} syntax
    ///   @var bsl::fmt_options::sign_aware
    ///     defines the "0" field in the {fmt} syntax
    ///   @var bsl::fmt_options::width
    ///     defines the "width" field in the {fmt} syntax
    ///   @var bsl::fmt_options::type
    ///     defines the "type" field in the {fmt} syntax
    ///
    class fmt_options final
    {
        /// @brief store the "fill" field in the {fmt} syntax
        char_type m_fill{' '};
        /// @brief store the "align" field in the {fmt} syntax
        fmt_align m_align{};
        /// @brief store the "sign" field in the {fmt} syntax
        fmt_sign m_sign{};
        /// @brief store the "alt form" field in the {fmt} syntax
        bool m_alternate_form{};
        /// @brief store the "sign aware" field in the {fmt} syntax
        bool m_sign_aware{};
        /// @brief store the "width" field in the {fmt} syntax
        bsl::safe_uintmax m_width{};
        /// @brief store the "type" field in the {fmt} syntax
        fmt_type m_type{};

    public:
        /// <!-- description -->
        ///   @brief Creates a bsl::fmt_options given a user provided
        ///     format string. The goal of this class is to pre-process
        ///     as much of the format string that the compiler will
        ///     allow so that at run-time, the program only has to
        ///     parse this struct to determine how to format a specific
        ///     argument.
        ///
        /// <!-- inputs/outputs -->
        ///   @param f the user provided format string.
        ///
        constexpr fmt_options(cstr_type const f) noexcept    // NOLINT
        {
            details::fmt_fsm fsm{};

            bsl::safe_uintmax idx{};
            bsl::safe_uintmax const len{bsl::builtin_strlen(f)};

            while (idx < len) {
                switch (fsm) {
                    case details::fmt_fsm::fmt_fsm_align: {
                        this->fmt_options_impl_align(f, idx, len);
                        fsm = details::fmt_fsm::fmt_fsm_sign;
                        break;
                    }

                    case details::fmt_fsm::fmt_fsm_sign: {
                        this->fmt_options_impl_sign(f, idx);
                        fsm = details::fmt_fsm::fmt_fsm_alternate_form;
                        break;
                    }

                    case details::fmt_fsm::fmt_fsm_alternate_form: {
                        this->fmt_options_impl_alternate_form(f, idx);
                        fsm = details::fmt_fsm::fmt_fsm_sign_aware;
                        break;
                    }

                    case details::fmt_fsm::fmt_fsm_sign_aware: {
                        this->fmt_options_impl_sign_aware(f, idx);
                        fsm = details::fmt_fsm::fmt_fsm_width;
                        break;
                    }

                    case details::fmt_fsm::fmt_fsm_width: {
                        this->fmt_options_impl_width(f, idx, len);
                        fsm = details::fmt_fsm::fmt_fsm_type;
                        break;
                    }

                    case details::fmt_fsm::fmt_fsm_type: {
                        this->fmt_options_impl_type(f, idx);
                        break;
                    }
                }
            }
        }

        /// <!-- description -->
        ///   @brief Returns the "fill" field in the {fmt} syntax based on
        ///     the previously provided format string.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the "fill" field in the {fmt} syntax based on
        ///     the previously provided format string.
        ///
        [[nodiscard]] constexpr char_type
        fill() const noexcept
        {
            return m_fill;
        }

        /// <!-- description -->
        ///   @brief Sets the "fill" field in the {fmt} syntax, overriding
        ///     what the previously provided format string provided.
        ///
        /// <!-- inputs/outputs -->
        ///   @param val the val to set the "fill" field to
        ///
        constexpr void
        set_fill(char_type const val) noexcept
        {
            m_fill = val;
        }

        /// <!-- description -->
        ///   @brief Returns the "align" field in the {fmt} syntax based on
        ///     the previously provided format string.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the "align" field in the {fmt} syntax based on
        ///     the previously provided format string.
        ///
        [[nodiscard]] constexpr fmt_align
        align() const noexcept
        {
            return m_align;
        }

        /// <!-- description -->
        ///   @brief Sets the "align" field in the {fmt} syntax, overriding
        ///     what the previously provided format string provided.
        ///
        /// <!-- inputs/outputs -->
        ///   @param val the val to set the "align" field to
        ///
        constexpr void
        set_align(fmt_align const val) noexcept
        {
            m_align = val;
        }

        /// <!-- description -->
        ///   @brief Returns the "sign" field in the {fmt} syntax based on
        ///     the previously provided format string.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the "sign" field in the {fmt} syntax based on
        ///     the previously provided format string.
        ///
        [[nodiscard]] constexpr fmt_sign
        sign() const noexcept
        {
            return m_sign;
        }

        /// <!-- description -->
        ///   @brief Sets the "sign" field in the {fmt} syntax, overriding
        ///     what the previously provided format string provided.
        ///
        /// <!-- inputs/outputs -->
        ///   @param val the val to set the "sign" field to
        ///
        constexpr void
        set_sign(fmt_sign const val) noexcept
        {
            m_sign = val;
        }

        /// <!-- description -->
        ///   @brief Returns the "alt form" field in the {fmt} syntax based on
        ///     the previously provided format string.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the "alt form" field in the {fmt} syntax based on
        ///     the previously provided format string.
        ///
        [[nodiscard]] constexpr bool
        alternate_form() const noexcept
        {
            return m_alternate_form;
        }

        /// <!-- description -->
        ///   @brief Sets the "alt form" field in the {fmt} syntax, overriding
        ///     what the previously provided format string provided.
        ///
        /// <!-- inputs/outputs -->
        ///   @param val the val to set the "alt form" field to
        ///
        constexpr void
        set_alternate_form(bool const val) noexcept
        {
            m_alternate_form = val;
        }

        /// <!-- description -->
        ///   @brief Returns the "sign aware" field in the {fmt} syntax based
        ///     on the previously provided format string.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the "sign aware" field in the {fmt} syntax based
        ///     on the previously provided format string.
        ///
        [[nodiscard]] constexpr bool
        sign_aware() const noexcept
        {
            return m_sign_aware;
        }

        /// <!-- description -->
        ///   @brief Sets the "sign aware" field in the {fmt} syntax, overriding
        ///     what the previously provided format string provided.
        ///
        /// <!-- inputs/outputs -->
        ///   @param val the val to set the "sign aware" field to
        ///
        constexpr void
        set_sign_aware(bool const val) noexcept
        {
            m_sign_aware = val;
        }

        /// <!-- description -->
        ///   @brief Returns the "width" field in the {fmt} syntax based on
        ///     the previously provided format string.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the "width" field in the {fmt} syntax based on
        ///     the previously provided format string.
        ///
        [[nodiscard]] constexpr bsl::safe_uintmax
        width() const noexcept
        {
            return m_width;
        }

        /// <!-- description -->
        ///   @brief Sets the "width" field in the {fmt} syntax, overriding
        ///     what the previously provided format string provided.
        ///
        /// <!-- inputs/outputs -->
        ///   @param val the val to set the "width" field to
        ///
        constexpr void
        set_width(bsl::safe_uintmax const val) noexcept
        {
            m_width = val;
        }

        /// <!-- description -->
        ///   @brief Returns the "type" field in the {fmt} syntax based on
        ///     the previously provided format string.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the "type" field in the {fmt} syntax based on
        ///     the previously provided format string.
        ///
        [[nodiscard]] constexpr fmt_type
        type() const noexcept
        {
            return m_type;
        }

        /// <!-- description -->
        ///   @brief Sets the "type" field in the {fmt} syntax, overriding
        ///     what the previously provided format string provided.
        ///
        /// <!-- inputs/outputs -->
        ///   @param val the val to set the "type" field to
        ///
        constexpr void
        set_type(fmt_type const val) noexcept
        {
            m_type = val;
        }

    private:
        /// <!-- description -->
        ///   @brief This function is responsible for parsing the align
        ///     and fill {fmt} fields and filling out the fmt_options as needed.
        ///     Also note that _if_ we find a valid field, we consume the
        ///     field from the format string for the next parser in the fsm.
        ///     Of all of the {fmt} fields, this one is the hardest as it
        ///     has to account for fill, which is optional, and can be any
        ///     character type except for '\0', which includes the alignment
        ///     characters themselves. To handle this, we need to get the first
        ///     2 characters from the format string (if they exist), and then
        ///     we first assume that the second character is the align field
        ///     and if it is not, we then look to the fill character which
        ///     might have been the align parameter the whole time.
        ///
        /// <!-- inputs/outputs -->
        ///   @param f the provided format string to parse
        ///
        constexpr void
        fmt_options_impl_align(
            cstr_type const f, bsl::safe_uintmax &idx, bsl::safe_uintmax const len) noexcept
        {
            char_type f_fill{' '};
            char_type f_align{};
            bsl::safe_uintmax idx_inc{bsl::to_umax(1)};

            if ((idx + bsl::to_umax(1)) < len) {
                f_fill = f[idx.get()];
                f_align = f[(idx + bsl::to_umax(1)).get()];
                idx_inc = bsl::to_umax(2);
            }
            else {
                f_align = f[idx.get()];
            }

            switch (f_align) {
                case '<': {
                    m_fill = f_fill;
                    m_align = fmt_align::fmt_align_left;
                    idx += idx_inc;
                    break;
                }

                case '>': {
                    m_fill = f_fill;
                    m_align = fmt_align::fmt_align_right;
                    idx += idx_inc;
                    break;
                }

                case '^': {
                    m_fill = f_fill;
                    m_align = fmt_align::fmt_align_center;
                    idx += idx_inc;
                    break;
                }

                default: {
                    break;
                }
            }

            if (fmt_align::fmt_align_default == m_align) {
                switch (f_fill) {
                    case '<': {
                        m_align = fmt_align::fmt_align_left;
                        ++idx;
                        break;
                    }

                    case '>': {
                        m_align = fmt_align::fmt_align_right;
                        ++idx;
                        break;
                    }

                    case '^': {
                        m_align = fmt_align::fmt_align_center;
                        ++idx;
                        break;
                    }

                    default: {
                        break;
                    }
                }
            }
        }

        /// <!-- description -->
        ///   @brief This function is responsible for parsing the sign
        ///     {fmt} field and filling out the fmt_options as needed.
        ///     Also note that _if_ we find a valid field, we consume the
        ///     field from the format string for the next parser in the fsm.
        ///
        /// <!-- inputs/outputs -->
        ///   @param f the provided format string to parse
        ///
        constexpr void
        fmt_options_impl_sign(cstr_type const f, bsl::safe_uintmax &idx) noexcept
        {
            switch (f[idx.get()]) {
                case '+': {
                    m_sign = fmt_sign::fmt_sign_pos_neg;
                    ++idx;
                    break;
                }

                case '-': {
                    m_sign = fmt_sign::fmt_sign_neg_only;
                    ++idx;
                    break;
                }

                case ' ': {
                    m_sign = fmt_sign::fmt_sign_space_for_pos;
                    ++idx;
                    break;
                }

                default: {
                    break;
                }
            }
        }

        /// <!-- description -->
        ///   @brief This function is responsible for parsing the alt form
        ///     {fmt} field and filling out the fmt_options as needed.
        ///     Also note that _if_ we find a valid field, we consume the
        ///     field from the format string for the next parser in the fsm.
        ///
        /// <!-- inputs/outputs -->
        ///   @param f the provided format string to parse
        ///
        constexpr void
        fmt_options_impl_alternate_form(cstr_type const f, bsl::safe_uintmax &idx) noexcept
        {
            if ('#' == f[idx.get()]) {
                m_alternate_form = true;
                ++idx;
            }
        }

        /// <!-- description -->
        ///   @brief This function is responsible for parsing the sign aware
        ///     {fmt} field and filling out the fmt_options as needed.
        ///     Also note that _if_ we find a valid field, we consume the
        ///     field from the format string for the next parser in the fsm.
        ///
        /// <!-- inputs/outputs -->
        ///   @param f the provided format string to parse
        ///
        constexpr void
        fmt_options_impl_sign_aware(cstr_type const f, bsl::safe_uintmax &idx) noexcept
        {
            if ('0' == f[idx.get()]) {
                m_sign_aware = true;
                ++idx;
            }
        }

        /// <!-- description -->
        ///   @brief This function is responsible for parsing the width
        ///     {fmt} field and filling out the fmt_options as needed.
        ///     Also note that _if_ we find a valid field, we consume the
        ///     field from the format string for the next parser in the fsm.
        ///
        /// <!-- inputs/outputs -->
        ///   @param f the provided format string to parse
        ///
        constexpr void
        fmt_options_impl_width(
            cstr_type const f, bsl::safe_uintmax &idx, bsl::safe_uintmax const len) noexcept
        {
            constexpr bsl::safe_uintmax max_num_digits{bsl::to_umax(3)};

            for (bsl::safe_uintmax i{}; (i < max_num_digits) && (idx < len); ++i) {
                char_type const digit{f[idx.get()]};

                if ((digit >= '0') && (digit <= '9')) {
                    m_width *= bsl::to_umax(10);
                    m_width += bsl::to_umax(digit);
                    m_width -= bsl::to_umax('0');
                    ++idx;
                }
            }
        }

        /// <!-- description -->
        ///   @brief This function is responsible for parsing the type
        ///     {fmt} field and filling out the fmt_options as needed.
        ///     Also note that _if_ we find a valid field, we consume the
        ///     field from the format string for the next parser in the fsm.
        ///     Since this is the last state in the fmt, we clear out the
        ///     format string when this function is done to ensure the
        ///     fsm will stop, no matter what is provided.
        ///
        /// <!-- inputs/outputs -->
        ///   @param f the provided format string to parse
        ///
        constexpr void
        fmt_options_impl_type(cstr_type const f, bsl::safe_uintmax &idx) noexcept
        {
            switch (f[idx.get()]) {
                case 'b':
                case 'B': {
                    m_type = fmt_type::fmt_type_b;
                    break;
                }

                case 'c': {
                    m_type = fmt_type::fmt_type_c;
                    break;
                }

                case 'd': {
                    m_type = fmt_type::fmt_type_d;
                    break;
                }

                case 's': {
                    m_type = fmt_type::fmt_type_s;
                    break;
                }

                case 'x':
                case 'X': {
                    m_type = fmt_type::fmt_type_x;
                    break;
                }

                default: {
                    break;
                }
            }

            idx = bsl::npos;
        }
    };

    /// @brief defines no formatting.
    constexpr fmt_options nullops{""};
    /// @brief defines how to format a ptr like type.
    constexpr fmt_options ptrops{(sizeof(bsl::uintptr) == 4) ? "#010x" : "#018x"};    // NOLINT
}

#endif
