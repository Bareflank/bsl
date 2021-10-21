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

#include <bsl/arguments.hpp>
#include <bsl/array.hpp>
#include <bsl/convert.hpp>
#include <bsl/cstr_type.hpp>
#include <bsl/debug.hpp>
#include <bsl/exit_code.hpp>
#include <bsl/safe_idx.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/unlikely.hpp>

namespace bsl
{
    /// <!-- description -->
    ///   @brief Provides the example's main function (for the readme)
    ///
    /// <!-- inputs/outputs -->
    ///   @param argc the total number of arguments given to main
    ///   @param argv the arguments given to main
    ///   @return Returns bsl::exit_success on success, bsl::exit_failure
    ///     on failure.
    ///
    [[nodiscard]] constexpr auto
    example_main(bsl::int32 const argc, bsl::cstr_type const *const argv) noexcept -> bsl::exit_code
    {
        constexpr auto num_expected_args{2_umx};
        bsl::arguments const args{argc, argv};

        if (args.size() < num_expected_args) {
            bsl::error() << "Invalid number of args" << bsl::endl << bsl::here();
            return bsl::exit_failure;
        }

        constexpr auto index_of_arg{1_umx};
        auto const val{args.at<bsl::safe_i32>(index_of_arg)};

        if (bsl::unlikely(val.is_invalid())) {
            bsl::error() << "Invalid arg" << bsl::endl << bsl::here();
            return bsl::exit_failure;
        }

        constexpr auto size_of_arr{42_umx};
        bsl::array<bsl::safe_i32, size_of_arr.get()> mut_arr{};

        for (auto &mut_elem : mut_arr) {
            mut_elem = val;
        }

        for (bsl::safe_idx mut_i{}; mut_i < mut_arr.size(); ++mut_i) {
            bsl::print() << " elem["                                    // --
                         << mut_i                                       // --
                         << "] == "                                     // --
                         << bsl::fmt{"#010x", *mut_arr.at_if(mut_i)}    // --
                         << bsl::endl;                                  // --
        }

        return bsl::exit_success;
    }
}
