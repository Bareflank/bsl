// @copyright
// Copyright (C) 2020 Assured Information Security, Inc.
//
// @copyright
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// @copyright
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// @copyright
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// NOTE:
// - The Rust manual states that a C style char type will "always" be a
//   i8 or u8, which is absolutely not true.
//   https://doc.rust-lang.org/std/os/raw/type.c_char.html
//
// - These types are not exposed to the core library either. The BSL requires
//   that an unsigned char is a u8 (even though it doesn't have to be, and
//   on some really weird systems, bytes are not 8 bits), but in our case,
//   it is safe to assume that u8 will work for C compatibility as we will
//   always be linking against LLVM style C and C++, which will set a char
//   to u8 on the systems and operating systems we care about.
//

/// @brief Defines a C-style string type
pub type CStrT = u8;

// -----------------------------------------------------------------------------
// Unit Tests
// -----------------------------------------------------------------------------

// TODO
// - Need to implement something for this type. In Rust this is not easy
//   because there is no such thing.
//
