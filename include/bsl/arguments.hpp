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
/// @file arguments.hpp
///

#ifndef BSL_ARGUMENTS_HPP
#define BSL_ARGUMENTS_HPP

#include "details/arguments_impl.hpp"

#include "convert.hpp"
#include "cstdint.hpp"
#include "cstr_type.hpp"
#include "debug.hpp"
#include "from_chars.hpp"
#include "safe_integral.hpp"
#include "span.hpp"
#include "string_view.hpp"

namespace bsl
{
    /// @class bsl::arguments
    ///
    /// <!-- description -->
    ///   @brief Encapsulates the argc, argv arguments that are passed to
    ///     traditional C applications using a bsl::span, and provides
    ///     accessors for getting position and optional arguments. Unlike
    ///     other argument parsers, the bsl::arguments does not use dynamic
    ///     memory. The has the benefit of reduced complexity and memory
    ///     usage, at the expense of slower argument processing as each
    ///     argument that you get must be processed independently. For this
    ///     reason, care should be taken not to only get each argument once.
    ///
    /// <b>Positional Arguments:</b><br>
    /// Positional arguments are arguments that you request at a specific
    /// position on the command line, when all of the optional arguments
    /// are removed (i.e., any argument that starts with '-').
    ///
    /// @include arguments/example_arguments_pos.hpp
    ///
    /// Results in the following output:
    /// @code
    /// bool test: true
    /// bool test: false
    /// bool test: true
    /// bool test: false
    /// integral test: 42
    /// integral test: -42
    /// integral test: 42
    /// integral test: [error]
    /// string test: hello
    /// string test: world
    /// mixed test [pos1]: pos1
    /// mixed test [pos2]: pos2
    /// mixed test [pos3]:
    /// mixed test [opt1]: true
    /// mixed test [opt2]: 42
    /// mixed test [opt3]: false
    /// @endcode
    ///
    /// <b>Optional Arguments:</b><br>
    /// Optional arguments are any argument that starts with a "-".
    /// Optional arguments are not required to be provided by the user
    /// of the command line, they can show up in any position on the
    /// command line, and they are processed in reverse order, meaning
    /// they can override each other if needed. Optional arguments
    /// also work a little differently than positional arguments with
    /// respect to getting the value of an optional argument. If you
    /// are looking for a bool, the presence of the optional argument
    /// results in true, while the lack of an optional argument results
    /// in false. For strings and integrals, the user must use the
    /// "=" syntax, with the optional argument name on the left and
    /// the value on the right. Note that the optional argument must
    /// also be one complete string when given to the parser, which
    /// typically means that on the command line, if spaces and other
    /// esoteric characters are needed, quotes must be used to ensure
    /// the application is given the argument as a single string and
    /// not a collections of strings.
    ///
    /// @include arguments/example_arguments_opt.hpp
    ///
    /// Results in the following output:
    /// @code
    /// bool test: true
    /// bool test: false
    /// integral test: 42
    /// integral test: -42
    /// integral test: 42
    /// integral test: [error]
    /// integral test: [error]
    /// string test: hello world
    /// string test:
    /// type test: true
    /// type test: true
    /// override test: 42
    /// mixed test [pos1]: pos1
    /// mixed test [pos2]: pos2
    /// mixed test [pos3]:
    /// mixed test [opt1]: true
    /// mixed test [opt2]: 42
    /// mixed test [opt3]: false
    /// @endcode
    ///
    class arguments final
    {
    public:
        /// @brief alias for: cstr_type const
        using value_type = cstr_type const;
        /// @brief alias for: safe_uintmax
        using size_type = safe_uintmax;
        /// @brief alias for: safe_uintmax
        using difference_type = safe_uintmax;
        /// @brief alias for: cstr_type const &
        using reference_type = cstr_type const &;
        /// @brief alias for: cstr_type const &
        using const_reference_type = cstr_type const &;
        /// @brief alias for: cstr_type const *
        using pointer_type = cstr_type const *;
        /// @brief alias for: cstr_type const *
        using const_pointer_type = cstr_type const *;
        /// @brief alias for: contiguous_iterator<cstr_type const>
        using iterator_type = contiguous_iterator<cstr_type const>;
        /// @brief alias for: contiguous_iterator<cstr_type const>
        using const_iterator_type = contiguous_iterator<cstr_type const>;
        /// @brief alias for: reverse_iterator<iterator>
        using reverse_iterator_type = reverse_iterator<iterator_type>;
        /// @brief alias for: reverse_iterator<const_iterator>
        using const_reverse_iterator_type = reverse_iterator<const_iterator_type>;

        /// <!-- description -->
        ///   @brief Creates a bsl::arguments object given a provided argc
        ///     and argv.
        ///
        /// <!-- inputs/outputs -->
        ///   @param argc the total number of arguments passed to the
        ///     application
        ///   @param argv the arguments passed to the application
        ///
        constexpr arguments(size_type const &argc, value_type *const argv) noexcept
            : m_args{argv, argc}
        {}

        /// <!-- description -->
        ///   @brief Creates a bsl::arguments object given a provided argc
        ///     and argv.
        ///
        /// <!-- inputs/outputs -->
        ///   @param argc the total number of arguments passed to the
        ///     application
        ///   @param argv the arguments passed to the application
        ///
        constexpr arguments(bsl::int32 const argc, value_type *const argv) noexcept
            : arguments{to_umax(argc), argv}
        {}

        /// <!-- description -->
        ///   @brief Returns the provided argc, argv parameters as a span
        ///     that can be parsed manually.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the provided argc, argv parameters as a span
        ///     that can be parsed manually.
        ///
        [[nodiscard]] constexpr span<cstr_type const> const &
        args() const noexcept
        {
            return m_args;
        }

        /// <!-- description -->
        ///   @brief Returns the positional argument at position "pos"
        ///     converted to "T". If the positional argument "pos" does not
        ///     exist, the result depends on "T". For a bsl::safe_integral,
        ///     the result is bsl::safe_integral<T>{0, true}, meaning the
        ///     integral has it's error flag set. All other types return T{}.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T either bsl::safe_integral, bsl::string_view or bool
        ///   @param pos the position of the positional argument to get.
        ///   @return Returns the positional argument at position "pos"
        ///     converted to "T". If the positional argument "pos" does not
        ///     exist, the result depends on "T". For a bsl::safe_integral,
        ///     the result is bsl::safe_integral<T>{0, true}, meaning the
        ///     integral has it's error flag set. All other types return T{}.
        ///
        template<typename T, bsl::int32 B = 10>
        [[nodiscard]] constexpr T
        get(size_type const &pos) const noexcept
        {
            return details::arguments_impl<T, B>::get(m_args, pos);
        }

        /// <!-- description -->
        ///   @brief Returns the requested optional argument. If the optional
        ///     argument "pos" does not exist, the result depends on "T".
        ///     For a bsl::safe_integral, the result is
        ///     bsl::safe_integral<T>{0, true}, meaning the integral has it's
        ///     error flag set. All other types return T{}.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T either bsl::safe_integral, bsl::string_view or bool
        ///   @param opt the optional argument to get.
        ///   @return Returns the requested optional argument. If the optional
        ///     argument "pos" does not exist, the result depends on "T".
        ///     For a bsl::safe_integral, the result is
        ///     bsl::safe_integral<T>{0, true}, meaning the integral has it's
        ///     error flag set. All other types return T{}.
        ///
        template<typename T, bsl::int32 B = 10>
        [[nodiscard]] constexpr T
        get(string_view const &opt) const noexcept
        {
            return details::arguments_impl<T, B>::get(m_args, opt);
        }

        /// <!-- description -->
        ///   @brief Same as get<T, B>(pos)
        ///   @include arguments/example_arguments_at.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T either bsl::safe_integral, bsl::string_view or bool
        ///   @param pos the position of the positional argument to get.
        ///   @return Returns the positional argument at position "pos"
        ///     converted to "T". If the positional argument "pos" does not
        ///     exist, the result depends on "T". For a bsl::safe_integral,
        ///     the result is bsl::safe_integral<T>{0, true}, meaning the
        ///     integral has it's error flag set. All other types return T{}.
        ///
        template<typename T, bsl::int32 B = 10>
        [[nodiscard]] constexpr T
        at(size_type const &pos) const noexcept
        {
            return this->get<T, B>(pos);
        }

        /// <!-- description -->
        ///   @brief Same as get<T, B>(to_umax(0))
        ///   @include arguments/example_arguments_front.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T either bsl::safe_integral, bsl::string_view or bool
        ///   @return Returns the positional argument at position "0"
        ///     converted to "T". If the positional argument "0" does not
        ///     exist, the result depends on "T". For a bsl::safe_integral,
        ///     the result is bsl::safe_integral<T>{0, true}, meaning the
        ///     integral has it's error flag set. All other types return T{}.
        ///
        template<typename T, bsl::int32 B = 10>
        [[nodiscard]] constexpr T
        front() const noexcept
        {
            return this->get<T, B>(to_umax(0));
        }

        /// <!-- description -->
        ///   @brief Same as get<T, B>(size().is_pos() ? (size() - to_umax(1)) : to_umax(0))
        ///   @include arguments/example_arguments_back.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T either bsl::safe_integral, bsl::string_view or bool
        ///   @return Returns the positional argument at position "size() - 1"
        ///     converted to "T". If the positional argument "size() - 1" does
        ///     not exist, the result depends on "T". For a bsl::safe_integral,
        ///     the result is bsl::safe_integral<T>{0, true}, meaning the
        ///     integral has it's error flag set. All other types return T{}.
        ///
        template<typename T, bsl::int32 B = 10>
        [[nodiscard]] constexpr T
        back() const noexcept
        {
            size_type s{this->size()};
            return this->get<T, B>(s.is_pos() ? (s - to_umax(1)) : to_umax(0));
        }

        /// <!-- description -->
        ///   @brief Returns size().is_zero()
        ///   @include arguments/example_arguments_empty.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns size().is_zero()
        ///
        [[nodiscard]] constexpr bool
        empty() const noexcept
        {
            return this->size().is_zero();
        }

        /// <!-- description -->
        ///   @brief Returns true if the arguments contains a valid span
        ///     of arguments.
        ///   @include arguments/example_arguments_operator_bool.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if the arguments contains a valid span
        ///     of arguments.
        ///
        [[nodiscard]] constexpr explicit operator bool() const noexcept
        {
            return !!m_args;
        }

        /// <!-- description -->
        ///   @brief Returns the number of positional arguments being viewed.
        ///     Optional arguments are ignored and are not included in the
        ///     resulting size. Note that this function is slow.
        ///   @include arguments/example_arguments_size.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the number of positional arguments being viewed.
        ///     Optional arguments are ignored and are not included in the
        ///     resulting size.
        ///
        [[nodiscard]] constexpr size_type
        size() const noexcept
        {
            size_type ret{};

            for (safe_uintmax i{}; i < m_args.size(); ++i) {
                string_view const arg{*m_args.at_if(i)};

                if (arg.starts_with('-')) {
                    continue;
                }

                ++ret;
            }

            return ret;
        }

        /// <!-- description -->
        ///   @brief Increments argument list. This is the same as creating a
        ///     new bsl::arguments with the pointer advanced and count
        ///     decremented. Note that only positional arguments are accounted
        ///     for. Optional arguments are ignored.
        ///   @include arguments/example_arguments_increment.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return returns *this
        ///
        [[maybe_unused]] constexpr arguments &
        operator++() noexcept
        {
            for (safe_uintmax i{to_umax(1)}; i < m_args.size(); ++i) {
                string_view const arg{*m_args.at_if(i)};

                if (arg.starts_with('-')) {
                    continue;
                }

                *this = arguments{m_args.size() - i, m_args.at_if(i)};
                return *this;
            }

            *this = arguments{0, nullptr};
            return *this;
        }

    private:
        /// @brief stores the argc/argv arguments.
        span<value_type> m_args;
    };

    /// <!-- description -->
    ///   @brief Outputs the provided bsl::arguments to the provided
    ///     output type.
    ///   @related bsl::arguments
    ///   @include arguments/example_arguments_ostream.hpp
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of outputter provided
    ///   @param o the instance of the outputter used to output the value.
    ///   @param a the bsl::arguments to output
    ///   @return return o
    ///
    template<typename T>
    [[maybe_unused]] constexpr out<T>
    operator<<(out<T> const o, arguments const &a) noexcept
    {
        if constexpr (!o) {
            return o;
        }

        return o << a.args();
    }
}

#endif
