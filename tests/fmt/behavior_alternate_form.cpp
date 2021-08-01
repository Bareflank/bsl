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

#include "../fmt_test.hpp"

#include <bsl/debug.hpp>
#include <bsl/ut.hpp>

namespace
{
    /// <!-- description -->
    ///   @brief Individual tests for integral types so that we test every
    ///     possible combination.
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of integral to test
    ///
    template<typename T>
    void
    tests_for_integrals() noexcept
    {
        fmt_test::reset();
        bsl::ut_scenario{"all versions of out for integrals"} = [&]() noexcept {
            fmt_test::output_to_all(bsl::fmt_options{"#"}, static_cast<T>(0));
            fmt_test::output_to_all(bsl::fmt_options{"#"}, static_cast<T>(1));
            fmt_test::output_to_all(bsl::fmt_options{"#"}, bsl::safe_integral<T>::magic_1());
            fmt_test::output_to_all(bsl::fmt_options{"#"}, bsl::safe_integral<T>::magic_0());
            fmt_test::output_to_all(bsl::fmt_options{"#"}, bsl::safe_integral<T>::failure());
            fmt_test::output_to_all(bsl::fmt_options{"#b"}, static_cast<T>(0));
            fmt_test::output_to_all(bsl::fmt_options{"#b"}, static_cast<T>(1));
            fmt_test::output_to_all(bsl::fmt_options{"#b"}, bsl::safe_integral<T>::magic_1());
            fmt_test::output_to_all(bsl::fmt_options{"#b"}, bsl::safe_integral<T>::magic_0());
            fmt_test::output_to_all(bsl::fmt_options{"#b"}, bsl::safe_integral<T>::failure());
            fmt_test::output_to_all(bsl::fmt_options{"#c"}, static_cast<T>(0));
            fmt_test::output_to_all(bsl::fmt_options{"#c"}, static_cast<T>(1));
            fmt_test::output_to_all(bsl::fmt_options{"#c"}, bsl::safe_integral<T>::magic_1());
            fmt_test::output_to_all(bsl::fmt_options{"#c"}, bsl::safe_integral<T>::magic_0());
            fmt_test::output_to_all(bsl::fmt_options{"#c"}, bsl::safe_integral<T>::failure());
            fmt_test::output_to_all(bsl::fmt_options{"#d"}, static_cast<T>(0));
            fmt_test::output_to_all(bsl::fmt_options{"#d"}, static_cast<T>(1));
            fmt_test::output_to_all(bsl::fmt_options{"#d"}, bsl::safe_integral<T>::magic_1());
            fmt_test::output_to_all(bsl::fmt_options{"#d"}, bsl::safe_integral<T>::magic_0());
            fmt_test::output_to_all(bsl::fmt_options{"#d"}, bsl::safe_integral<T>::failure());
            fmt_test::output_to_all(bsl::fmt_options{"#x"}, static_cast<T>(0));
            fmt_test::output_to_all(bsl::fmt_options{"#x"}, static_cast<T>(1));
            fmt_test::output_to_all(bsl::fmt_options{"#x"}, bsl::safe_integral<T>::magic_1());
            fmt_test::output_to_all(bsl::fmt_options{"#x"}, bsl::safe_integral<T>::magic_0());
            fmt_test::output_to_all(bsl::fmt_options{"#x"}, bsl::safe_integral<T>::failure());
            fmt_test::output_to_all(bsl::fmt_options{"#s"}, static_cast<T>(0));
            fmt_test::output_to_all(bsl::fmt_options{"#s"}, static_cast<T>(1));
            fmt_test::output_to_all(bsl::fmt_options{"#s"}, bsl::safe_integral<T>::magic_1());
            fmt_test::output_to_all(bsl::fmt_options{"#s"}, bsl::safe_integral<T>::magic_0());
            fmt_test::output_to_all(bsl::fmt_options{"#s"}, bsl::safe_integral<T>::failure());

            if constexpr (bsl::is_signed<T>::value) {
                fmt_test::output_to_all(
                    bsl::fmt_options{"#"}, bsl::safe_integral<T>::magic_neg_1());
                fmt_test::output_to_all(
                    bsl::fmt_options{"#b"}, bsl::safe_integral<T>::magic_neg_1());
                fmt_test::output_to_all(
                    bsl::fmt_options{"#c"}, bsl::safe_integral<T>::magic_neg_1());
                fmt_test::output_to_all(
                    bsl::fmt_options{"#d"}, bsl::safe_integral<T>::magic_neg_1());
                fmt_test::output_to_all(
                    bsl::fmt_options{"#x"}, bsl::safe_integral<T>::magic_neg_1());
                fmt_test::output_to_all(
                    bsl::fmt_options{"#s"}, bsl::safe_integral<T>::magic_neg_1());
            }

            bsl::fmt_options mut_ops{"#"};
            mut_ops.set_type(static_cast<bsl::fmt_type>(42));
            fmt_test::output_to_all(mut_ops, static_cast<T>(0));
            fmt_test::output_to_all(mut_ops, static_cast<T>(1));
            fmt_test::output_to_all(mut_ops, bsl::safe_integral<T>::magic_1());
            fmt_test::output_to_all(mut_ops, bsl::safe_integral<T>::magic_0());
            fmt_test::output_to_all(mut_ops, bsl::safe_integral<T>::failure());

            if constexpr (bsl::is_signed<T>::value) {
                fmt_test::output_to_all(mut_ops, bsl::safe_integral<T>::magic_neg_1());
            }
        };
    }
}

/// <!-- description -->
///   @brief Main function for this unit test. If a call to bsl::ut_check() fails
///     the application will fast fail. If all calls to bsl::ut_check() pass, this
///     function will successfully return with bsl::exit_success.
///
/// <!-- inputs/outputs -->
///   @return Always returns bsl::exit_success.
///
[[nodiscard]] auto
main() noexcept -> bsl::exit_code
{
    tests_for_integrals<bsl::int8>();
    tests_for_integrals<bsl::int16>();
    tests_for_integrals<bsl::int32>();
    tests_for_integrals<bsl::int64>();
    tests_for_integrals<bsl::uint8>();
    tests_for_integrals<bsl::uint16>();
    tests_for_integrals<bsl::uint32>();
    tests_for_integrals<bsl::uint64>();
    tests_for_integrals<bsl::uintmx>();

    bsl::ut_scenario{"all versions of out for bool"} = []() noexcept {
        bool const val1{true};
        bool const val2{false};
        fmt_test::reset();

        fmt_test::output_to_all(bsl::fmt_options{"#"}, val1);
        fmt_test::output_to_all(bsl::fmt_options{"#"}, val2);
        fmt_test::output_to_all(bsl::fmt_options{"#b"}, val1);
        fmt_test::output_to_all(bsl::fmt_options{"#b"}, val2);
        fmt_test::output_to_all(bsl::fmt_options{"#c"}, val1);
        fmt_test::output_to_all(bsl::fmt_options{"#c"}, val2);
        fmt_test::output_to_all(bsl::fmt_options{"#d"}, val1);
        fmt_test::output_to_all(bsl::fmt_options{"#d"}, val2);
        fmt_test::output_to_all(bsl::fmt_options{"#x"}, val1);
        fmt_test::output_to_all(bsl::fmt_options{"#x"}, val2);
        fmt_test::output_to_all(bsl::fmt_options{"#s"}, val1);
        fmt_test::output_to_all(bsl::fmt_options{"#s"}, val2);

        bsl::fmt_options mut_ops{"#"};
        mut_ops.set_type(static_cast<bsl::fmt_type>(42));
        fmt_test::output_to_all(mut_ops, val1);
        fmt_test::output_to_all(mut_ops, val2);
    };

    bsl::ut_scenario{"all versions of out for char_type"} = []() noexcept {
        bsl::char_type const val{'*'};
        fmt_test::reset();

        fmt_test::output_to_all(bsl::fmt_options{"#"}, val);
        fmt_test::output_to_all(bsl::fmt_options{"#b"}, val);
        fmt_test::output_to_all(bsl::fmt_options{"#c"}, val);
        fmt_test::output_to_all(bsl::fmt_options{"#d"}, val);
        fmt_test::output_to_all(bsl::fmt_options{"#x"}, val);
        fmt_test::output_to_all(bsl::fmt_options{"#s"}, val);

        bsl::fmt_options mut_ops{"#"};
        mut_ops.set_type(static_cast<bsl::fmt_type>(42));
        fmt_test::output_to_all(mut_ops, val);
    };

    bsl::ut_scenario{"all versions of out for cstr_type"} = []() noexcept {
        bsl::cstr_type const val1{};
        bsl::cstr_type const val2{"Hello"};
        fmt_test::reset();

        fmt_test::output_to_all(bsl::fmt_options{"#"}, val1);
        fmt_test::output_to_all(bsl::fmt_options{"#"}, val2);
        fmt_test::output_to_all(bsl::fmt_options{"#b"}, val1);
        fmt_test::output_to_all(bsl::fmt_options{"#b"}, val2);
        fmt_test::output_to_all(bsl::fmt_options{"#c"}, val1);
        fmt_test::output_to_all(bsl::fmt_options{"#c"}, val2);
        fmt_test::output_to_all(bsl::fmt_options{"#d"}, val1);
        fmt_test::output_to_all(bsl::fmt_options{"#d"}, val2);
        fmt_test::output_to_all(bsl::fmt_options{"#x"}, val1);
        fmt_test::output_to_all(bsl::fmt_options{"#x"}, val2);
        fmt_test::output_to_all(bsl::fmt_options{"#s"}, val1);
        fmt_test::output_to_all(bsl::fmt_options{"#s"}, val2);

        bsl::fmt_options mut_ops{"#"};
        mut_ops.set_type(static_cast<bsl::fmt_type>(42));
        fmt_test::output_to_all(mut_ops, val1);
        fmt_test::output_to_all(mut_ops, val2);
    };

    bsl::ut_scenario{"all versions of out for string_view"} = []() noexcept {
        bsl::string_view const val1{};
        bsl::string_view const val2{"Hello"};
        fmt_test::reset();

        fmt_test::output_to_all(bsl::fmt_options{"#"}, val1);
        fmt_test::output_to_all(bsl::fmt_options{"#"}, val2);
        fmt_test::output_to_all(bsl::fmt_options{"#b"}, val1);
        fmt_test::output_to_all(bsl::fmt_options{"#b"}, val2);
        fmt_test::output_to_all(bsl::fmt_options{"#c"}, val1);
        fmt_test::output_to_all(bsl::fmt_options{"#c"}, val2);
        fmt_test::output_to_all(bsl::fmt_options{"#d"}, val1);
        fmt_test::output_to_all(bsl::fmt_options{"#d"}, val2);
        fmt_test::output_to_all(bsl::fmt_options{"#x"}, val1);
        fmt_test::output_to_all(bsl::fmt_options{"#x"}, val2);
        fmt_test::output_to_all(bsl::fmt_options{"#s"}, val1);
        fmt_test::output_to_all(bsl::fmt_options{"#s"}, val2);

        bsl::fmt_options mut_ops{"#"};
        mut_ops.set_type(static_cast<bsl::fmt_type>(42));
        fmt_test::output_to_all(mut_ops, val1);
        fmt_test::output_to_all(mut_ops, val2);
    };

    return bsl::ut_success();
}
