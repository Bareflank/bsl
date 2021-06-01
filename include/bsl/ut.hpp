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
#include "cstdlib.hpp"
#include "debug.hpp"
#include "dontcare_t.hpp"
#include "exit_code.hpp"
#include "source_location.hpp"
#include "touch.hpp"
#include "ut_given.hpp"
#include "ut_given_at_runtime.hpp"
#include "ut_scenario.hpp"
#include "ut_then.hpp"
#include "ut_when.hpp"

#include <bsl/enable_color.hpp>

#pragma clang diagnostic ignored "-Wunused-member-function"
#pragma clang diagnostic ignored "-Wunneeded-member-function"
#pragma clang diagnostic ignored "-Wunneeded-internal-declaration"
#pragma clang diagnostic ignored "-Wmissing-braces"
#pragma clang diagnostic ignored "-Wglobal-constructors"
#pragma clang diagnostic ignored "-Wexit-time-destructors"

namespace bsl
{
    /// <!-- description -->
    ///   @brief Outputs a message and returns bsl::exit_success
    ///
    /// <!-- inputs/outputs -->
    ///   @return returns bsl::exit_success
    ///
    [[nodiscard]] constexpr auto
    ut_success() noexcept -> bsl::exit_code
    {
        bsl::print() << bsl::green << "All tests passed" << bsl::reset_color << bsl::endl;
        return bsl::exit_success;
    }

    /// <!-- description -->
    ///   @brief This is a non-constexpr function that can be used to detect
    ///     when a unit test required step fails. If this function is called at
    ///     compile-time, it will not compile, resulting in a human readable
    ///     error message.
    ///
    inline void
    ut_required_step_failed() noexcept
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
    [[maybe_unused]] constexpr auto
    ut_required_step(bool const test, source_location const &sloc = here()) noexcept -> bool
    {
        if (!test) {
            bsl::error() << bsl::magenta << "[REQUIRED STEP FAILED]" << bsl::reset_color
                         << bsl::endl;
            bsl::error() << sloc;

            ut_required_step_failed();
            exit(1);
        }
        else {
            bsl::touch();
        }

        return test;
    }

    /// <!-- description -->
    ///   @brief Checks to see if "test" is bsl::errc_success. If test is
    ///     false, this function will exit fast with a failure code.
    ///
    /// <!-- inputs/outputs -->
    ///   @param ec if ec is bsl::errc_success, this function returns true.
    ///     If ec is bsl::errc_failure, this function will exit fast with a
    ///     failure code.
    ///   @param sloc used to identify the location in the unit test that a
    ///     check failed.
    ///   @return returns test
    ///
    [[maybe_unused]] constexpr auto
    ut_required_step(bsl::errc_type const ec, source_location const &sloc = here()) noexcept -> bool
    {
        return ut_required_step(ec.success(), sloc);
    }

    /// <!-- description -->
    ///   @brief Checks to see if "test" is bsl::errc_success. If test is
    ///     false, this function will exit fast with a failure code.
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam FIELD_TYPE the type of integer being checked
    ///   @param val if val does not contain an error, this function returns
    ///     true. If val contains an error, this function will exit fast with a
    ///     failure code.
    ///   @param sloc used to identify the location in the unit test that a
    ///     check failed.
    ///   @return returns test
    ///
    template<typename FIELD_TYPE>
    [[maybe_unused]] constexpr auto
    ut_required_step(
        bsl::safe_integral<FIELD_TYPE> const val, source_location const &sloc = here()) noexcept
        -> bool
    {
        return ut_required_step(!!val, sloc);
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
    [[maybe_unused]] constexpr auto
    ut_check(bool const test, source_location const &sloc = here()) noexcept -> bool
    {
        if (!test) {
            bsl::error() << bsl::magenta << "[CHECK FAILED]" << bsl::reset_color << bsl::endl;
            bsl::error() << sloc;

            ut_check_failed();
            exit(1);
        }
        else {
            bsl::touch();
        }

        return test;
    }

    /// <!-- description -->
    ///   @brief Checks to see if "test" is bsl::errc_success. If test is
    ///     false, this function will exit fast with a failure code.
    ///
    /// <!-- inputs/outputs -->
    ///   @param ec if ec is bsl::errc_success, this function returns true.
    ///     If ec is bsl::errc_failure, this function will exit fast with a
    ///     failure code.
    ///   @param sloc used to identify the location in the unit test that a
    ///     check failed.
    ///   @return returns test
    ///
    [[maybe_unused]] constexpr auto
    ut_check(bsl::errc_type const ec, source_location const &sloc = here()) noexcept -> bool
    {
        return ut_check(ec.success(), sloc);
    }

    /// <!-- description -->
    ///   @brief Checks to see if "test" is bsl::errc_success. If test is
    ///     false, this function will exit fast with a failure code.
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam FIELD_TYPE the type of integer being checked
    ///   @param val if val does not contain an error, this function returns
    ///     true. If val contains an error, this function will exit fast with a
    ///     failure code.
    ///   @param sloc used to identify the location in the unit test that a
    ///     check failed.
    ///   @return returns test
    ///
    template<typename FIELD_TYPE>
    [[maybe_unused]] constexpr auto
    ut_check(
        bsl::safe_integral<FIELD_TYPE> const val, source_location const &sloc = here()) noexcept
        -> bool
    {
        return ut_check(!!val, sloc);
    }
}

#endif
