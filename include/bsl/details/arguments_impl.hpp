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

#ifndef BSL_DETAILS_ARGUMENTS_IMPL_HPP
#define BSL_DETAILS_ARGUMENTS_IMPL_HPP

#include "../convert.hpp"
#include "../cstdint.hpp"
#include "../cstr_type.hpp"
#include "../debug.hpp"
#include "../from_chars.hpp"
#include "../safe_integral.hpp"
#include "../span.hpp"
#include "../string_view.hpp"

namespace bsl
{
    namespace details
    {
        /// @class bsl::details::arguments_impl
        ///
        /// <!-- description -->
        ///   @brief Provides the base implementation for the bsl::arguments
        ///     get() function. This specific version handles the case when
        ///     the provided type is not supported.
        ///
        /// <!-- template parameters -->
        ///   @tparam T the type to get from the provided command line
        ///     arguments.
        ///   @tparam B the base of the number to get. This defaults to 10
        ///     and is ignored for all types except bsl::safe_integral types.
        ///
        template<typename T, bsl::int32 B = 10>
        class arguments_impl final
        {
            static_assert(
                sizeof(T) != sizeof(T),    // NOLINT
                "unsupported type provided to bsl::arguments");
        };

        /// @class bsl::details::arguments_impl
        ///
        /// <!-- description -->
        ///   @brief Provides the base implementation for the bsl::arguments
        ///     get() function. This specific version handles the
        ///     bsl::string_view case.
        ///
        /// <!-- template parameters -->
        ///   @tparam B the base of the number to get. This defaults to 10
        ///     and is ignored for all types except bsl::safe_integral types.
        ///
        template<bsl::int32 B>
        class arguments_impl<string_view, B> final
        {
        public:
            /// <!-- description -->
            ///   @brief Returns the requested positional argument as a
            ///     bsl::string_view. If the provided "pos" is invalid,
            ///     this function will return an empty bsl::string_view.
            ///
            /// <!-- inputs/outputs -->
            ///   @param pos the position of the positional argument to get.
            ///   @return Returns the requested positional argument as a
            ///     bsl::string_view. If the provided "pos" is invalid,
            ///     this function will return an empty bsl::string_view.
            ///
            [[nodiscard]] static constexpr string_view
            get(span<cstr_type const> const &args, safe_uintmax const &pos) noexcept
            {
                if (!pos) {
                    bsl::error() << "invalid positional argument index: " << pos << bsl::endl;
                    return {};
                }

                safe_uintmax idx{};
                for (safe_uintmax i{}; i < args.size(); ++i) {
                    string_view const arg{*args.at_if(i)};

                    if (arg.starts_with('-')) {
                        continue;
                    }

                    if (idx < pos) {
                        ++idx;
                        continue;
                    }

                    return arg;
                }

                return {};
            }

            /// <!-- description -->
            ///   @brief Returns the requested optional argument as a
            ///     bsl::string_view. If the provided "opt" is invalid,
            ///     this function will return an empty bsl::string_view.
            ///     Note that arguments are processed in reverse order,
            ///     providing the ability to override arguments on the
            ///     command line.
            ///
            /// <!-- inputs/outputs -->
            ///   @param opt the optional argument to get.
            ///   @return Returns the requested optional argument as a
            ///     bsl::string_view. If the provided "opt" is invalid,
            ///     this function will return an empty bsl::string_view
            ///
            [[nodiscard]] static constexpr string_view
            get(span<cstr_type const> const &args, string_view const &opt) noexcept
            {
                if (opt.empty()) {
                    bsl::error() << "cannot request an empty optional argument\n";
                    return {};
                }

                for (safe_uintmax i{args.size()}; i.is_pos(); --i) {
                    string_view arg{*args.at_if(i - safe_uintmax::one())};

                    if (!arg.starts_with(opt)) {
                        continue;
                    }

                    arg.remove_prefix(opt.length());

                    if (!arg.starts_with('=')) {
                        continue;
                    }

                    arg.remove_prefix(safe_uintmax::one());
                    return arg;
                }

                return {};
            }
        };

        /// @class bsl::details::arguments_impl
        ///
        /// <!-- description -->
        ///   @brief Provides the base implementation for the bsl::arguments
        ///     get() function. This specific version handles the bool case.
        ///
        /// <!-- template parameters -->
        ///   @tparam B the base of the number to get. This defaults to 10
        ///     and is ignored for all types except bsl::safe_integral types.
        ///
        template<bsl::int32 B>
        class arguments_impl<bool, B> final
        {
        public:
            /// <!-- description -->
            ///   @brief Returns the requested positional argument as a
            ///     bsl::safe_int8. If the provided "pos" is invalid,
            ///     this function will return an invalid bsl::safe_int8.
            ///
            /// <!-- inputs/outputs -->
            ///   @param pos the position of the positional argument to get.
            ///   @return Returns the requested positional argument as a
            ///     bsl::safe_int8. If the provided "pos" is invalid,
            ///     this function will return an invalid bsl::safe_int8.
            ///
            [[nodiscard]] static constexpr bool
            get(span<cstr_type const> const &args, safe_uintmax const &pos) noexcept
            {
                string_view const arg{arguments_impl<string_view, B>::get(args, pos)};

                if (arg == "true") {
                    return true;
                }

                safe_int32 val{};
                if (from_chars(arg, val) != arg.length()) {
                    return false;
                }

                return (!!val) && (!val.is_zero());
            }

            /// <!-- description -->
            ///   @brief Returns true if the requested optional argument
            ///     is present. Returns false otherwise.
            ///
            /// <!-- inputs/outputs -->
            ///   @param opt the optional argument to get.
            ///   @return Returns true if the requested optional argument
            ///     is present. Returns false otherwise.
            ///
            [[nodiscard]] static constexpr bool
            get(span<cstr_type const> const &args, string_view const &opt) noexcept
            {
                if (opt.empty()) {
                    bsl::error() << "cannot request an empty optional argument\n";
                    return false;
                }

                for (safe_uintmax i{}; i < args.size(); ++i) {
                    string_view const arg{*args.at_if(i)};

                    if (arg == opt) {
                        return true;
                    }
                }

                return false;
            }
        };

        /// @class bsl::details::arguments_impl
        ///
        /// <!-- description -->
        ///   @brief Provides the base implementation for the bsl::arguments
        ///     get() function. This specific version handles the
        ///     bsl::safe_integral case.
        ///
        /// <!-- template parameters -->
        ///   @tparam T the type of bsl::safe_integral to get from the
        ///     provided command line arguments.
        ///   @tparam B the base of the number to get. This defaults to 10
        ///     and is ignored for all types except bsl::safe_integral types.
        ///
        template<typename T, bsl::int32 B>
        class arguments_impl<safe_integral<T>, B> final
        {
        public:
            /// <!-- description -->
            ///   @brief Returns the requested positional argument as a
            ///     bsl::safe_int8. If the provided "pos" is invalid,
            ///     this function will return an invalid bsl::safe_int8.
            ///
            /// <!-- inputs/outputs -->
            ///   @param pos the position of the positional argument to get.
            ///   @return Returns the requested positional argument as a
            ///     bsl::safe_int8. If the provided "pos" is invalid,
            ///     this function will return an invalid bsl::safe_int8.
            ///
            [[nodiscard]] static constexpr safe_integral<T>
            get(span<cstr_type const> const &args, safe_uintmax const &pos) noexcept
            {
                safe_integral<T> val{};
                string_view const arg{arguments_impl<string_view, B>::get(args, pos)};

                if (from_chars(arg, val, to_i32(B)) != arg.length()) {
                    return safe_integral<T>::zero(true);
                }

                return val;
            }

            /// <!-- description -->
            ///   @brief Returns the requested optional argument as a
            ///     bsl::safe_int64. If the provided "opt" is invalid,
            ///     this function will return an invalid bsl::safe_int64.
            ///     Note that arguments are processed in reverse order,
            ///     providing the ability to override arguments on the
            ///     command line..
            ///
            /// <!-- inputs/outputs -->
            ///   @param opt the optional argument to get.
            ///   @return Returns the requested optional argument as a
            ///     bsl::safe_int64. If the provided "opt" is invalid,
            ///     this function will return an invalid bsl::safe_int64
            ///
            [[nodiscard]] static constexpr safe_integral<T>
            get(span<cstr_type const> const &args, string_view const &opt) noexcept
            {
                safe_integral<T> val{};
                string_view const arg{arguments_impl<string_view, B>::get(args, opt)};

                if (from_chars(arg, val, to_i32(B)) != arg.length()) {
                    return safe_integral<T>::zero(true);
                }

                return val;
            }
        };
    }
}

#endif
