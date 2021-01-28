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

#include "convert.hpp"
#include "cstdint.hpp"
#include "cstr_type.hpp"
#include "debug.hpp"
#include "details/arguments_impl.hpp"
#include "details/out.hpp"
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
            : m_args{argv, argc}, m_index{}
        {}

        /// <!-- description -->
        ///   @brief Returns the provided argc, argv parameters as a span
        ///     that can be parsed manually.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the provided argc, argv parameters as a span
        ///     that can be parsed manually.
        ///
        [[nodiscard]] constexpr auto
        args() const &noexcept -> span<cstr_type const> const &
        {
            return m_args;
        }

        /// <!-- description -->
        ///   @brief Returns the current index
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the current index
        ///
        [[nodiscard]] constexpr auto
        index() const &noexcept -> bsl::safe_uintmax const &
        {
            return m_index;
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
        ///   @tparam B the base to convert the argument to
        ///   @param pos the position of the positional argument to get.
        ///   @return Returns the positional argument at position "pos"
        ///     converted to "T". If the positional argument "pos" does not
        ///     exist, the result depends on "T". For a bsl::safe_integral,
        ///     the result is bsl::safe_integral<T>{0, true}, meaning the
        ///     integral has it's error flag set. All other types return T{}.
        ///
        template<typename T, bsl::int32 B = details::ARGUMENTS_DEFAULT_BASE.get()>
        [[nodiscard]] constexpr auto
        get(size_type const &pos) const noexcept -> T
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
        ///   @tparam B the base to convert the argument to
        ///   @param opt the optional argument to get.
        ///   @return Returns the requested optional argument. If the optional
        ///     argument "pos" does not exist, the result depends on "T".
        ///     For a bsl::safe_integral, the result is
        ///     bsl::safe_integral<T>{0, true}, meaning the integral has it's
        ///     error flag set. All other types return T{}.
        ///
        template<typename T, bsl::int32 B = details::ARGUMENTS_DEFAULT_BASE.get()>
        [[nodiscard]] constexpr auto
        get(string_view const &opt) const noexcept -> T
        {
            return details::arguments_impl<T, B>::get(m_args, opt);
        }

        /// <!-- description -->
        ///   @brief Returns this->get<T, B>(pos + current_index), where the
        ///     current_index starts at 0 when the arguments are constructed,
        ///     and can be incremented using the ++ operator.
        ///   @include arguments/example_arguments_at.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T either bsl::safe_integral, bsl::string_view or bool
        ///   @tparam B the base to convert the argument to
        ///   @param pos the position of the positional argument to get.
        ///   @return Returns this->get<T, B>(pos + current_index), where the
        ///     current_index starts at 0 when the arguments are constructed,
        ///     and can be incremented using the ++ operator.
        ///
        template<typename T, bsl::int32 B = details::ARGUMENTS_DEFAULT_BASE.get()>
        [[nodiscard]] constexpr auto
        at(size_type const &pos) const noexcept -> T
        {
            return this->get<T, B>(pos + m_index);
        }

        /// <!-- description -->
        ///   @brief Returns this->at<T, B>(size_type::zero()).
        ///   @include arguments/example_arguments_front.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T either bsl::safe_integral, bsl::string_view or bool
        ///   @tparam B the base to convert the argument to
        ///   @return Returns this->at<T, B>(size_type::zero()).
        ///
        template<typename T, bsl::int32 B = details::ARGUMENTS_DEFAULT_BASE.get()>
        [[nodiscard]] constexpr auto
        front() const noexcept -> T
        {
            return this->at<T, B>(size_type::zero());
        }

        /// <!-- description -->
        ///   @brief Returns remaining().is_zero()
        ///   @include arguments/example_arguments_empty.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns remaining().is_zero()
        ///
        [[nodiscard]] constexpr auto
        empty() const noexcept -> bool
        {
            return this->remaining().is_zero();
        }

        /// <!-- description -->
        ///   @brief Returns !this->empty()
        ///   @include arguments/example_arguments_operator_bool.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns !this->empty()
        ///
        [[nodiscard]] constexpr explicit operator bool() const noexcept
        {
            return !this->empty();
        }

        /// <!-- description -->
        ///   @brief Returns the number of positional arguments.
        ///     Optional arguments are ignored and are not included in the
        ///     resulting size. Note that this function is slow.
        ///   @include arguments/example_arguments_size.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the number of positional arguments.
        ///     Optional arguments are ignored and are not included in the
        ///     resulting size.
        ///
        [[nodiscard]] constexpr auto
        size() const noexcept -> size_type
        {
            size_type ret{};

            for (safe_uintmax i{}; i < m_args.size(); ++i) {
                if (!bsl::string_view{*m_args.at_if(i)}.starts_with('-')) {
                    ++ret;
                }
                else {
                    bsl::touch();
                }
            }

            return ret;
        }

        /// <!-- description -->
        ///   @brief Returns this->size() - this->index()
        ///   @include arguments/example_arguments_size.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns this->size() - this->index()
        ///
        [[nodiscard]] constexpr auto
        remaining() const noexcept -> size_type
        {
            return this->size() - this->index();
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
        [[maybe_unused]] constexpr auto
        operator++() noexcept -> arguments &
        {
            if (m_index < this->size()) {
                ++m_index;
            }
            else {
                bsl::touch();
            }

            return *this;
        }

    private:
        /// @brief stores the argc/argv arguments.
        span<value_type> m_args;
        /// @brief stores the current index into the arguments.
        bsl::safe_uintmax m_index;
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
    [[maybe_unused]] constexpr auto
    operator<<(out<T> const o, arguments const &a) noexcept -> out<T>
    {
        if constexpr (!o) {
            return o;
        }

        return o << a.args() << ", " << a.index();
    }
}

#endif
