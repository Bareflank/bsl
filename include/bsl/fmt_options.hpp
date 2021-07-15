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
#include "cstdint.hpp"
#include "cstr_type.hpp"
#include "cstring.hpp"
#include "details/fmt_fsm.hpp"
#include "fmt_align.hpp"
#include "fmt_sign.hpp"
#include "fmt_type.hpp"
#include "likely.hpp"
#include "npos.hpp"
#include "safe_integral.hpp"
#include "touch.hpp"
#include "unlikely.hpp"

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
        safe_uintmax m_width{};
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
        explicit constexpr fmt_options(cstr_type const f) noexcept
        {
            details::fmt_fsm mut_fsm{};

            safe_uintmax mut_idx{};
            safe_uintmax const len{bsl::builtin_strlen(f)};

            while (mut_idx < len) {
                switch (mut_fsm) {
                    case details::fmt_fsm::fmt_fsm_align: {
                        this->fmt_options_impl_align(f, mut_idx, len);
                        mut_fsm = details::fmt_fsm::fmt_fsm_sign;
                        break;
                    }

                    case details::fmt_fsm::fmt_fsm_sign: {
                        this->fmt_options_impl_sign(f, mut_idx);
                        mut_fsm = details::fmt_fsm::fmt_fsm_alternate_form;
                        break;
                    }

                    case details::fmt_fsm::fmt_fsm_alternate_form: {
                        this->fmt_options_impl_alternate_form(f, mut_idx);
                        mut_fsm = details::fmt_fsm::fmt_fsm_sign_aware;
                        break;
                    }

                    case details::fmt_fsm::fmt_fsm_sign_aware: {
                        this->fmt_options_impl_sign_aware(f, mut_idx);
                        mut_fsm = details::fmt_fsm::fmt_fsm_width;
                        break;
                    }

                    case details::fmt_fsm::fmt_fsm_width: {
                        this->fmt_options_impl_width(f, mut_idx, len);
                        mut_fsm = details::fmt_fsm::fmt_fsm_type;
                        break;
                    }

                    case details::fmt_fsm::fmt_fsm_type: {
                        this->fmt_options_impl_type(f, mut_idx);
                        break;
                    }
                }
            }
        }

        /// <!-- description -->
        ///   @brief Destroyes a previously created bsl::fmt_options
        ///
        constexpr ~fmt_options() noexcept = default;

        /// <!-- description -->
        ///   @brief copy constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///
        constexpr fmt_options(fmt_options const &o) noexcept = default;

        /// <!-- description -->
        ///   @brief move constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_o the object being moved
        ///
        constexpr fmt_options(fmt_options &&mut_o) noexcept = default;

        /// <!-- description -->
        ///   @brief copy assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr auto operator=(fmt_options const &o) &noexcept
            -> fmt_options & = default;

        /// <!-- description -->
        ///   @brief move assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_o the object being moved
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr auto operator=(fmt_options &&mut_o) &noexcept
            -> fmt_options & = default;

        /// <!-- description -->
        ///   @brief This constructor allows for single argument constructors
        ///     without the need to mark them as explicit as it will absorb
        ///     any incoming potential implicit conversion and prevent it.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam O the type that could be implicitly converted
        ///   @param mut_val the value that could be implicitly converted
        ///
        template<typename O>
        constexpr fmt_options(O mut_val) noexcept = delete;

        /// <!-- description -->
        ///   @brief Returns the "fill" field in the {fmt} syntax based on
        ///     the previously provided format string.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the "fill" field in the {fmt} syntax based on
        ///     the previously provided format string.
        ///
        [[nodiscard]] constexpr auto
        fill() const noexcept -> char_type
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
        [[nodiscard]] constexpr auto
        align() const noexcept -> fmt_align
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
        [[nodiscard]] constexpr auto
        sign() const noexcept -> fmt_sign
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
        [[nodiscard]] constexpr auto
        alternate_form() const noexcept -> bool
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
        [[nodiscard]] constexpr auto
        sign_aware() const noexcept -> bool
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
        [[nodiscard]] constexpr auto
        width() const noexcept -> bsl::safe_uintmax
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
        set_width(safe_uintmax const &val) noexcept
        {
            constexpr safe_uintmax max_width{static_cast<bsl::uintmax>(999)};

            if (unlikely(!val)) {
                unlikely_invalid_argument_failure();
                m_width = max_width;
                return;
            }

            if (val > max_width) {
                unlikely_invalid_argument_failure();
                m_width = max_width;
                return;
            }

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
        [[nodiscard]] constexpr auto
        type() const noexcept -> fmt_type
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
        ///   @brief Returns the fill value for alignment.
        ///
        /// <!-- inputs/outputs -->
        ///   @param f the provided format string to parse
        ///   @param idx the index in the fmt options string to start from
        ///   @param len the total number of characters in the fmt options
        ///     string being parsed.
        ///   @return Returns the fill value for alignment.
        ///
        [[nodiscard]] static constexpr auto
        fmt_options_impl_align_get_fill(
            cstr_type const f, safe_uintmax const &idx, safe_uintmax const &len) noexcept
            -> char_type
        {
            constexpr safe_uintmax one{static_cast<bsl::uintmax>(1)};

            if ((idx + one) < len) {
                return f[idx.get()];
            }

            return ' ';
        }

        /// <!-- description -->
        ///   @brief Returns the alignment command for alignment.
        ///
        /// <!-- inputs/outputs -->
        ///   @param f the provided format string to parse
        ///   @param idx the index in the fmt options string to start from
        ///   @param len the total number of characters in the fmt options
        ///     string being parsed.
        ///   @return Returns the alignment command for alignment.
        ///
        [[nodiscard]] static constexpr auto
        fmt_options_impl_align_get_align(
            cstr_type const f, safe_uintmax const &idx, safe_uintmax const &len) noexcept
            -> char_type
        {
            constexpr safe_uintmax one{static_cast<bsl::uintmax>(1)};

            if ((idx + one) < len) {
                return f[(idx + one).get()];
            }

            return f[idx.get()];
        }

        /// <!-- description -->
        ///   @brief Returns the increment amount for alignment.
        ///
        /// <!-- inputs/outputs -->
        ///   @param idx the index in the fmt options string to start from
        ///   @param len the total number of characters in the fmt options
        ///     string being parsed.
        ///   @return Returns the increment amount for alignment.
        ///
        [[nodiscard]] static constexpr auto
        fmt_options_impl_align_get_inc(safe_uintmax const &idx, safe_uintmax const &len) noexcept
            -> safe_uintmax
        {
            constexpr safe_uintmax one{static_cast<bsl::uintmax>(1)};
            constexpr safe_uintmax two{static_cast<bsl::uintmax>(2)};

            if ((idx + one) < len) {
                return two;
            }

            return one;
        }

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
        ///   @param mut_idx the index in the fmt options string to start from
        ///   @param len the total number of characters in the fmt options
        ///     string being parsed.
        ///
        constexpr void
        fmt_options_impl_align(
            cstr_type const f, safe_uintmax &mut_idx, safe_uintmax const &len) noexcept
        {
            char_type const f_fill{fmt_options_impl_align_get_fill(f, mut_idx, len)};
            char_type const f_align{fmt_options_impl_align_get_align(f, mut_idx, len)};
            safe_uintmax const idx_inc{fmt_options_impl_align_get_inc(mut_idx, len)};

            switch (f_align) {
                case '<': {
                    m_fill = f_fill;
                    m_align = fmt_align::fmt_align_left;
                    mut_idx += idx_inc;
                    break;
                }

                case '>': {
                    m_fill = f_fill;
                    m_align = fmt_align::fmt_align_right;
                    mut_idx += idx_inc;
                    break;
                }

                case '^': {
                    m_fill = f_fill;
                    m_align = fmt_align::fmt_align_center;
                    mut_idx += idx_inc;
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
                        ++mut_idx;
                        break;
                    }

                    case '>': {
                        m_align = fmt_align::fmt_align_right;
                        ++mut_idx;
                        break;
                    }

                    case '^': {
                        m_align = fmt_align::fmt_align_center;
                        ++mut_idx;
                        break;
                    }

                    default: {
                        break;
                    }
                }
            }
            else {
                bsl::touch();
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
        ///   @param mut_idx the index in the fmt options string to start from
        ///
        constexpr void
        fmt_options_impl_sign(cstr_type const f, safe_uintmax &mut_idx) noexcept
        {
            switch (f[mut_idx.get()]) {
                case '+': {
                    m_sign = fmt_sign::fmt_sign_pos_neg;
                    ++mut_idx;
                    break;
                }

                case '-': {
                    m_sign = fmt_sign::fmt_sign_neg_only;
                    ++mut_idx;
                    break;
                }

                case ' ': {
                    m_sign = fmt_sign::fmt_sign_space_for_pos;
                    ++mut_idx;
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
        ///   @param mut_idx the index in the fmt options string to start from
        ///
        constexpr void
        fmt_options_impl_alternate_form(cstr_type const f, safe_uintmax &mut_idx) noexcept
        {
            if ('#' == f[mut_idx.get()]) {
                m_alternate_form = true;
                ++mut_idx;
            }
            else {
                bsl::touch();
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
        ///   @param mut_idx the index in the fmt options string to start from
        ///
        constexpr void
        fmt_options_impl_sign_aware(cstr_type const f, safe_uintmax &mut_idx) noexcept
        {
            if ('0' == f[mut_idx.get()]) {
                m_sign_aware = true;
                ++mut_idx;
            }
            else {
                bsl::touch();
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
        ///   @param mut_idx the index in the fmt options string to start from
        ///   @param len the total number of characters in the fmt options
        ///     string being parsed.
        ///
        constexpr void
        fmt_options_impl_width(
            cstr_type const f, safe_uintmax &mut_idx, safe_uintmax const &len) noexcept
        {
            constexpr safe_uintmax max_num_width_digits{static_cast<bsl::uintmax>(3)};
            constexpr safe_uintmax base10{static_cast<bsl::uintmax>(10)};

            for (safe_uintmax mut_i{}; mut_idx < len; ++mut_i) {
                if (unlikely(mut_i == max_num_width_digits)) {
                    unlikely_invalid_argument_failure();
                    break;
                }

                char_type const digit{f[mut_idx.get()]};
                if (digit < '0') {
                    break;
                }

                if (digit > '9') {
                    break;
                }

                m_width *= base10;
                m_width += static_cast<bsl::uintmax>(digit);
                m_width -= static_cast<bsl::uintmax>('0');
                ++mut_idx;
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
        ///   @param mut_idx the index in the fmt options string to start from
        ///
        constexpr void
        fmt_options_impl_type(cstr_type const f, safe_uintmax &mut_idx) noexcept
        {
            switch (f[mut_idx.get()]) {
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

            mut_idx += (bsl::npos - mut_idx);
        }
    };

    namespace details
    {
        /// <!-- description -->
        ///   @brief Returns the fmt options for a pointer depending on the
        ///     the size of a pointer.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the fmt options for a pointer depending on the
        ///     the size of a pointer.
        ///
        [[nodiscard]] constexpr auto
        get_ptrops() noexcept -> fmt_options
        {
            if (sizeof(bsl::uintptr) == sizeof(bsl::uint32)) {
                return fmt_options{"#010x"};
            }

            return fmt_options{"#018x"};
        }
    }

    /// @brief defines no formatting.
    constexpr fmt_options nullops{""};
    /// @brief defines how to format a ptr like type.
    constexpr fmt_options ptrops{details::get_ptrops()};
}

#endif
