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
#include <bsl/debug.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/string_view.hpp>

namespace bsl
{
    /// <!-- description -->
    ///   @brief Provides the example's main function
    ///
    inline void
    example_arguments_pos() noexcept
    {
        constexpr auto hex_test{16_umx};
        constexpr auto arg0{0_umx};
        constexpr auto arg1{1_umx};
        constexpr auto arg2{2_umx};
        constexpr auto arg3{3_umx};

        constexpr bsl::array argv1{"true", "false", "1", "0"};
        bsl::arguments const args1{argv1.size(), argv1.data()};

        bsl::print() << "bool test: "                          // --
                     << args1.get<bool>(arg0) << bsl::endl;    // --
        bsl::print() << "bool test: "                          // --
                     << args1.get<bool>(arg1) << bsl::endl;    // --
        bsl::print() << "bool test: "                          // --
                     << args1.get<bool>(arg2) << bsl::endl;    // --
        bsl::print() << "bool test: "                          // --
                     << args1.get<bool>(arg3) << bsl::endl;    // --

        constexpr bsl::array argv2{"42", " -42", "2A", "not a number"};
        bsl::arguments const args2{argv2.size(), argv2.data()};

        bsl::print() << "integral test: "                                               // --
                     << args2.get<bsl::safe_i32>(arg0) << bsl::endl;                    // --
        bsl::print() << "integral test: "                                               // --
                     << args2.get<bsl::safe_i32>(arg1) << bsl::endl;                    // --
        bsl::print() << "integral test: "                                               // --
                     << args2.get<bsl::safe_u32, hex_test.get()>(arg2) << bsl::endl;    // --
        bsl::print() << "integral test: "                                               // --
                     << args2.get<bsl::safe_u32>(arg3) << bsl::endl;                    // --

        constexpr bsl::array argv3{"hello", "world"};
        bsl::arguments const args3{argv3.size(), argv3.data()};

        bsl::print() << "string test: "                                    // --
                     << args3.get<bsl::string_view>(arg0) << bsl::endl;    // --
        bsl::print() << "string test: "                                    // --
                     << args3.get<bsl::string_view>(arg1) << bsl::endl;    // --

        constexpr bsl::array argv4{"app", "pos1", "-opt1", "pos2", "-opt2=23", "-opt2=42"};
        bsl::arguments const args4{argv4.size(), argv4.data()};

        bsl::print() << "mixed test [pos1]: "                                 // --
                     << args4.get<bsl::string_view>(arg1) << bsl::endl;       // --
        bsl::print() << "mixed test [pos2]: "                                 // --
                     << args4.get<bsl::string_view>(arg2) << bsl::endl;       // --
        bsl::print() << "mixed test [pos3]: "                                 // --
                     << args4.get<bsl::string_view>(arg3) << bsl::endl;       // --
        bsl::print() << "mixed test [opt1]: "                                 // --
                     << args4.get<bool>("-opt1") << bsl::endl;                // --
        bsl::print() << "mixed test [opt2]: "                                 // --
                     << args4.get<bsl::string_view>("-opt2") << bsl::endl;    // --
        bsl::print() << "mixed test [opt3]: "                                 // --
                     << args4.get<bool>("-opt3") << bsl::endl;                // --
    }
}
