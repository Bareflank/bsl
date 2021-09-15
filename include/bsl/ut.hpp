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

#include "bsl/cstr_type.hpp"
#include "bsl/debug.hpp"    // IWYU pragma: export
#include "bsl/errc_type.hpp"
#include "bsl/exit_code.hpp"    // IWYU pragma: export
#include "bsl/safe_integral.hpp"
#include "bsl/string_view.hpp"
#include "bsl/touch.hpp"
#include "bsl/unlikely.hpp"
#include "bsl/ut_cleanup.hpp"               // IWYU pragma: export
#include "bsl/ut_cleanup_at_runtime.hpp"    // IWYU pragma: export
#include "bsl/ut_given.hpp"                 // IWYU pragma: export
#include "bsl/ut_given_at_runtime.hpp"      // IWYU pragma: export
#include "bsl/ut_scenario.hpp"              // IWYU pragma: export
#include "bsl/ut_then.hpp"                  // IWYU pragma: export
#include "bsl/ut_then_at_runtime.hpp"       // IWYU pragma: export
#include "bsl/ut_when.hpp"                  // IWYU pragma: export

// NOLINTNEXTLINE(hicpp-deprecated-headers, modernize-deprecated-headers)
#include <stdio.h>

#include <bsl/cstdlib.hpp>
#include <bsl/enable_color.hpp>    // IWYU pragma: export

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
        bsl::print() << bsl::grn << "All tests passed" << bsl::rst << bsl::endl;
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
    ///   @param sloc used to identify the location in the unit test where a
    ///     check failed.
    ///   @return returns test
    ///
    [[maybe_unused]] constexpr auto
    ut_required_step(bool const test, source_location const &sloc = here()) noexcept -> bool
    {
        if (unlikely(!test)) {                               // GRCOV_EXCLUDE_BR // NOLINT
            bsl::details::line_type const l{sloc.line()};    // GRCOV_EXCLUDE // NOLINT
            bsl::cstr_type const f{sloc.file_name()};        // GRCOV_EXCLUDE // NOLINT
            bsl::cstr_type const m{bsl::mag.data()};         // GRCOV_EXCLUDE // NOLINT
            bsl::cstr_type const y{bsl::ylw.data()};         // GRCOV_EXCLUDE // NOLINT
            bsl::cstr_type const c{bsl::cyn.data()};         // GRCOV_EXCLUDE // NOLINT
            bsl::cstr_type const r{bsl::rst.data()};         // GRCOV_EXCLUDE // NOLINT

            ut_required_step_failed();                                // GRCOV_EXCLUDE // NOLINT
            fprintf(stderr, "%s[REQUIRED STEP FAILED]%s\n", m, r);    // GRCOV_EXCLUDE // NOLINT
            fprintf(
                stderr, "  --> %s%s%s:%s%d%s\n", y, f, r, c, l, r);    // GRCOV_EXCLUDE // NOLINT

            stdlib_fast_fail();    // GRCOV_EXCLUDE // NOLINT
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
    ///   @param sloc used to identify the location in the unit test where a
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
    ///   @param sloc used to identify the location in the unit test where a
    ///     check failed.
    ///   @return returns test
    ///
    template<typename FIELD_TYPE>
    [[maybe_unused]] constexpr auto
    ut_required_step(
        bsl::safe_integral<FIELD_TYPE> const &val, source_location const &sloc = here()) noexcept
        -> bool
    {
        return ut_required_step(val.is_valid_and_checked(), sloc);
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
    ///   @param sloc used to identify the location in the unit test where a
    ///     check failed.
    ///   @return returns test
    ///
    [[maybe_unused]] constexpr auto
    ut_check(bool const test, source_location const &sloc = here()) noexcept -> bool
    {
        if (unlikely(!test)) {                               // GRCOV_EXCLUDE_BR
            bsl::details::line_type const l{sloc.line()};    // GRCOV_EXCLUDE // NOLINT
            bsl::cstr_type const f{sloc.file_name()};        // GRCOV_EXCLUDE // NOLINT
            bsl::cstr_type const m{bsl::mag.data()};         // GRCOV_EXCLUDE // NOLINT
            bsl::cstr_type const y{bsl::ylw.data()};         // GRCOV_EXCLUDE // NOLINT
            bsl::cstr_type const c{bsl::cyn.data()};         // GRCOV_EXCLUDE // NOLINT
            bsl::cstr_type const r{bsl::rst.data()};         // GRCOV_EXCLUDE // NOLINT

            ut_check_failed();                                // GRCOV_EXCLUDE // NOLINT
            fprintf(stderr, "%s[CHECK FAILED]%s\n", m, r);    // GRCOV_EXCLUDE // NOLINT
            fprintf(
                stderr, "  --> %s%s%s:%s%d%s\n", y, f, r, c, l, r);    // GRCOV_EXCLUDE // NOLINT

            stdlib_fast_fail();    // GRCOV_EXCLUDE // NOLINT
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
    ///   @param sloc used to identify the location in the unit test where a
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
    ///   @param sloc used to identify the location in the unit test where a
    ///     check failed.
    ///   @return returns test
    ///
    template<typename FIELD_TYPE>
    [[maybe_unused]] constexpr auto
    ut_check(
        bsl::safe_integral<FIELD_TYPE> const &val, source_location const &sloc = here()) noexcept
        -> bool
    {
        return ut_check(val.is_valid_and_checked(), sloc);
    }
}

#endif
