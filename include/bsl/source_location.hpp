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
/// @file source_location.hpp
///

#ifndef BSL_SOURCE_LOCATION_HPP
#define BSL_SOURCE_LOCATION_HPP

#include "cstdint.hpp"
#include "cstr_type.hpp"

namespace bsl
{
    namespace details
    {
        /// @brief defines an invalid file.
        constexpr bsl::cstr_type INVALID_FILE{"unknown"};
        /// @brief defines an invalid function.
        constexpr bsl::cstr_type INVALID_FUNC{"unknown"};
        /// @brief defines an invalid line number.
        constexpr decltype(__builtin_LINE()) INVALID_LINE{
            static_cast<decltype(__builtin_LINE())>(-1)};
    }

    /// <!-- description -->
    ///   @brief This class implements the source_location specification that
    ///     will eventually be included in C++20. We make some changes to the
    ///     specification to support AUTOSAR, but these changes should not
    ///     change how the code is compiled or used, with the exception that
    ///     we do not include the column() as this does not seem to be
    ///     implemented by any compilers yet.
    ///   @include example_source_location_overview.hpp
    ///
    class source_location final
    {
    public:
        /// @brief defines the source location's file name type
        using file_type = bsl::cstr_type;
        /// @brief defines the source location's function name type
        using func_type = bsl::cstr_type;
        /// @brief defines the source location's line location type
        using line_type = decltype(__builtin_LINE());

    private:
        /// <!-- description -->
        ///   @brief constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param current_file the file name of the source
        ///   @param current_func the function name of the source
        ///   @param current_line the line location of the source
        ///
        constexpr source_location(                    // --
            file_type const current_file,             // --
            func_type const current_func,             // --
            line_type const current_line) noexcept    // --
            : m_file{current_file}                    // --
            , m_func{current_func}                    // --
            , m_line{current_line}
        {}

    public:
        /// <!-- description -->
        ///   @brief Creates a default constructed source location. By default,
        ///     a source location's file name is "unknown", the function name
        ///     is "unknown" and the line location is "-1".
        ///   @include source_location/example_source_location_default_constructor.hpp
        ///
        constexpr source_location() noexcept    // --
            : m_file{details::INVALID_FILE}     // --
            , m_func{details::INVALID_FUNC}     // --
            , m_line{details::INVALID_LINE}
        {}

        /// <!-- description -->
        ///   @brief Destroyes a previously created bsl::source_location
        ///
        constexpr ~source_location() noexcept = default;

        /// <!-- description -->
        ///   @brief copy constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///
        constexpr source_location(source_location const &o) noexcept = default;

        /// <!-- description -->
        ///   @brief move constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_o the object being moved
        ///
        constexpr source_location(source_location &&mut_o) noexcept = default;

        /// <!-- description -->
        ///   @brief copy assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr auto operator=(source_location const &o) &noexcept
            -> source_location & = default;

        /// <!-- description -->
        ///   @brief move assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_o the object being moved
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr auto operator=(source_location &&mut_o) &noexcept
            -> source_location & = default;

        /// <!-- description -->
        ///   @brief Constructs a new source_location object corresponding to
        ///     the location of the call site.
        ///   @include source_location/example_source_location_current.hpp
        ///
        /// <!-- notes -->
        ///   @note You should not set the parameters manually. Instead,
        ///     use the default parameters which will contain the location
        ///     information provided by the compiler.
        ///   @note We DO NOT ensure by contract that the source location
        ///     contains valid pointers for the file name and function name
        ///     which means the resulting source_location could return
        ///     a nullptr for both the file name and function name. Care should
        ///     be taken to ensure the proper checks are made as needed.
        ///   @note Instead of using bsl::source_location::current() to get
        ///     the current source_location, use bsl::here() which provides a
        ///     function with less verbosity.
        ///
        /// <!-- inputs/outputs -->
        ///   @param current_file defaults to the current file name
        ///   @param current_func defaults to the current function name
        ///   @param current_line defaults to the current line location
        ///   @return returns a new source_location object corresponding to
        ///     the location of the call site of current().
        ///
        [[nodiscard]] static constexpr auto
        current(
            file_type const current_file = __builtin_FILE(),
            func_type const current_func = __builtin_FUNCTION(),
            line_type const current_line = __builtin_LINE()) noexcept -> source_location
        {
            return {current_file, current_func, current_line};
        }

        /// <!-- description -->
        ///   @brief Returns the file name associated with the
        ///     bsl::source_location
        ///   @include source_location/example_source_location_file_name.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return returns the file name associated with the
        ///
        [[nodiscard]] constexpr auto
        file_name() const noexcept -> file_type
        {
            return m_file;
        }

        /// <!-- description -->
        ///   @brief Returns the function name associated with the
        ///     bsl::source_location
        ///   @include source_location/example_source_location_function_name.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return returns the function name associated with the
        ///
        [[nodiscard]] constexpr auto
        function_name() const noexcept -> func_type
        {
            return m_func;
        }

        /// <!-- description -->
        ///   @brief Returns the line location associated with the
        ///     bsl::source_location
        ///   @include source_location/example_source_location_line.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return returns the line location associated with the
        ///
        [[nodiscard]] constexpr auto
        line() const noexcept -> line_type
        {
            return m_line;
        }

    private:
        /// @brief stores the file name of the bsl::source_location
        file_type m_file;
        /// @brief stores the function name of the bsl::source_location
        func_type m_func;
        /// @brief stores the line location of the bsl::source_location
        line_type m_line;
    };
}

#endif
