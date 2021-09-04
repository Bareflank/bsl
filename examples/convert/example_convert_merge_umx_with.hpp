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

#include <bsl/convert.hpp>
#include <bsl/debug.hpp>
#include <bsl/safe_integral.hpp>

namespace bsl
{
    /// <!-- description -->
    ///   @brief Provides the example's main function
    ///
    inline void
    example_convert_merge_umx_with() noexcept
    {
        constexpr auto uppermx{0x1234567890ABCDEF_umx};
        constexpr auto lower08{0xFF_u8};
        constexpr auto lower16{0xFFFF_u16};
        constexpr auto lower32{0xFFFFFFFF_u32};

        bsl::print() << "success [8bit]: "                                    // --
                     << bsl::hex(bsl::merge_umx_with_u8(uppermx, lower08))    // --
                     << bsl::endl;                                            // --

        bsl::print() << "success [16bit]: "                                    // --
                     << bsl::hex(bsl::merge_umx_with_u16(uppermx, lower16))    // --
                     << bsl::endl;                                             // --

        bsl::print() << "success [32bit]: "                                    // --
                     << bsl::hex(bsl::merge_umx_with_u32(uppermx, lower32))    // --
                     << bsl::endl;                                             // --
    }
}
