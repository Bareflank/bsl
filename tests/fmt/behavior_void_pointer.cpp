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

#pragma clang diagnostic ignored "-Wreserved-id-macro"
#define BAREFLANK

#include <stdio.h>    // NOLINT

#include <bsl/char_type.hpp>
#include <bsl/convert.hpp>
#include <bsl/cstdint.hpp>
#include <bsl/cstring.hpp>
#include <bsl/cstr_type.hpp>
#include <bsl/safe_integral.hpp>

#include <bsl/details/putc_stdout.hpp>
#include <bsl/details/puts_stdout.hpp>
#include <bsl/details/putc_stderr.hpp>
#include <bsl/details/puts_stderr.hpp>

namespace
{
    template<bsl::uintmax N>
    struct test_string_view final
    {
        bsl::char_type data[N]{};    // NOLINT
        bsl::safe_uintmax size{};
    };

    constexpr bsl::safe_uintmax res_size{bsl::to_umax(256)};
    test_string_view<res_size.get()> res{};

    template<bsl::uintmax N>
    bool
    operator==(test_string_view<N> const &lhs, bsl::cstr_type const str) noexcept
    {
        if (bsl::builtin_strlen(str) != lhs.size) {
            return false;
        }

        for (bsl::safe_uintmax i{}; i < lhs.size; ++i) {
            if (lhs.data[i.get()] != str[i.get()]) {    // NOLINT
                return false;
            }
        }

        return true;
    }

    void
    reset() noexcept
    {
        for (auto &e : res.data) {
            e = 0;
        }

        res.size = bsl::to_umax(0);
    }
}

namespace bsl
{
    namespace details
    {
        void
        putc_stdout(bsl::char_type const c) noexcept
        {
            res.data[res.size.get()] = c;    // NOLINT
            ++res.size;
        }

        void
        puts_stdout(bsl::cstr_type const str) noexcept
        {
            for (bsl::safe_uintmax i{}; i < bsl::builtin_strlen(str); ++i) {
                res.data[res.size.get()] = str[i.get()];    // NOLINT
                ++res.size;
            }
        }

        void
        putc_stderr(char_type const c) noexcept
        {
            bsl::discard(fputc(c, stderr));    // NOLINT
        }

        void
        puts_stderr(cstr_type const str) noexcept
        {
            bsl::discard(fputs(str, stderr));    // NOLINT
        }
    }
}

#include <bsl/debug.hpp>
#include <bsl/ut.hpp>

/// <!-- description -->
///   @brief Main function for this unit test. If a call to ut_check() fails
///     the application will fast fail. If all calls to ut_check() pass, this
///     function will successfully return with bsl::exit_success.
///
/// <!-- inputs/outputs -->
///   @return Always returns bsl::exit_success.
///
bsl::exit_code
main() noexcept
{
    bsl::ut_scenario{"void pointer"} = []() {
        bsl::ut_when{} = []() {
            reset();
            void *val{};
            bsl::print() << val;
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "nullptr");
            };
        };

        bsl::ut_when{} = []() {
            reset();
            void *val{reinterpret_cast<void *>(0x0000000000000042)};    // NOLINT
            bsl::print() << val;
            bsl::ut_then{} = []() {
                bsl::ut_check(res == "0x0000000000000042");
            };
        };
    };

    return bsl::ut_success();
}
