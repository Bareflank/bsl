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
/// @file ut.hpp
///

#ifndef BSL_UT_HPP
#define BSL_UT_HPP

#include "color.hpp"
#include "debug.hpp"
#include "discard.hpp"
#include "exit_code.hpp"
#include "main.hpp"
#include "source_location.hpp"
#include "string_view.hpp"

#include <stdlib.h>    // NOLINT

#pragma clang diagnostic ignored "-Wunused-member-function"
#pragma clang diagnostic ignored "-Wunneeded-member-function"
#pragma clang diagnostic ignored "-Wunneeded-internal-declaration"
#pragma clang diagnostic ignored "-Wmissing-braces"
#pragma clang diagnostic ignored "-Wglobal-constructors"
#pragma clang diagnostic ignored "-Wexit-time-destructors"

namespace bsl
{
    namespace details
    {
        /// <!-- description -->
        ///   @brief Prints the current source location to the console.
        ///
        /// <!-- inputs/outputs -->
        ///   @param sloc the current source location to print
        ///
        inline void
        ut_print_here(sloc_type const &sloc) noexcept
        {
            bsl::print() << sloc;
        }
    }

    /// @class bsl::ut_scenario
    ///
    /// <!-- description -->
    ///   @brief Defines a unit test scenario. A scenario defines a user
    ///     story, describing the "scenario" being tested. A scenario
    ///     should be paired with ut_given, ut_when and ut_then to define
    ///     the scenario in english.
    ///
    class ut_scenario final
    {
    public:
        /// <!-- description -->
        ///   @brief Constructs a scenario
        ///
        /// <!-- inputs/outputs -->
        ///   @param name the name of the scenario (i.e., test case)
        ///
        explicit constexpr ut_scenario(string_view const &name) noexcept
        {
            bsl::discard(name);
        }

        /// <!-- description -->
        ///   @brief Executes a lambda function as the body of the
        ///     scenario.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam FUNC the type of lambda being executed
        ///   @param func the lambda being executed
        ///   @return Returns a reference to the scenario.
        ///
        template<typename FUNC>
        [[maybe_unused]] constexpr ut_scenario &
        operator=(FUNC &&func) noexcept
        {
            func();
            return *this;
        }
    };

    /// @class bsl::ut_given
    ///
    /// <!-- description -->
    ///   @brief Defines the initial state of a unit test scenario including
    ///     the creation of any objects that might participate in the
    ///     unit test.
    ///
    class ut_given final
    {
    public:
        /// <!-- description -->
        ///   @brief Executes a lambda function as the body of the
        ///     "given" portion of the scenario.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam FUNC the type of lambda being executed
        ///   @param func the lambda being executed
        ///   @return Returns a reference to the ut_given.
        ///
        template<typename FUNC>
        [[maybe_unused]] constexpr ut_given &
        operator=(FUNC &&func) noexcept
        {
            func();
            return *this;
        }
    };

    /// @class bsl::ut_when
    ///
    /// <!-- description -->
    ///   @brief Defines the "action" of a unit test scenario
    ///
    class ut_when final
    {
    public:
        /// <!-- description -->
        ///   @brief Executes a lambda function as the body of the
        ///     "when" portion of the scenario.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam FUNC the type of lambda being executed
        ///   @param func the lambda being executed
        ///   @return Returns a reference to the ut_when.
        ///
        template<typename FUNC>
        [[maybe_unused]] constexpr ut_when &
        operator=(FUNC &&func) noexcept
        {
            func();
            return *this;
        }
    };

    /// @class bsl::ut_then
    ///
    /// <!-- description -->
    ///   @brief Defines the expected "result" of a unit test scenario.
    ///
    class ut_then final
    {
    public:
        /// <!-- description -->
        ///   @brief Executes a lambda function as the body of the
        ///     "then" portion of the scenario.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam FUNC the type of lambda being executed
        ///   @param func the lambda being executed
        ///   @return Returns a reference to the ut_then.
        ///
        template<typename FUNC>
        [[maybe_unused]] constexpr ut_then &
        operator=(FUNC &&func) noexcept
        {
            func();
            return *this;
        }
    };

    /// <!-- description -->
    ///   @brief Outputs a message and returns bsl::exit_success
    ///
    /// <!-- inputs/outputs -->
    ///   @return returns bsl::exit_success
    ///
    constexpr bsl::exit_code
    ut_success() noexcept
    {
        bsl::print() << bsl::green << "All tests passed" << bsl::reset_color << bsl::endl;
        return bsl::exit_success;
    }

    /// <!-- description -->
    ///   @brief This is a non-constexpr function that can be used to detect
    ///     when a unit test check fails. If this function is called at
    ///     compile-time, it will not compile, resulting in a human readable
    ///     error message.
    ///
    inline void
    ut_check_failed() noexcept
    {}

    /// <!-- description -->
    ///   @brief Checks to see if "test" is true. If test is false, this
    ///     function will exit fast with a failure code.
    ///
    /// <!-- inputs/outputs -->
    ///   @param test if test is true, this function returns true. If test is
    ///     false, this function will exit fast with a failure code.
    ///   @param sloc used to identify the location in the unit test that a
    ///     check failed.
    ///   @return returns test
    ///
    [[maybe_unused]] constexpr bool
    ut_check(bool const test, sloc_type const &sloc = here()) noexcept
    {
        if (!test) {
            bsl::error() << bsl::magenta << "[CHECK FAILED]" << bsl::reset_color << bsl::endl;
            bsl::error() << sloc;

            ut_check_failed();
            exit(1);
        }

        return test;
    }
}

#endif
