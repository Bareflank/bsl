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
// - For now, if you want to run the tests, you will need to comment this
//   out. Just make sure to put it back before checking in any changes.
//   Not really sure how to set this up so that we have std for tests only,
//   and no_std for regular use.
//
#![no_std]

#[macro_use]
extern crate static_assertions;

#[cfg(not(feature = "custom_print_thread_id"))]
#[allow(unused_macros)]
#[doc(hidden)]
macro_rules! print_thread_id {
    ($($arg:tt)*) => {};
}

#[path = "include/bsl/touch.rs"]
#[doc(hidden)]
pub mod touch;
pub use touch::touch;
#[path = "include/bsl/discard.rs"]
#[doc(hidden)]
pub mod discard;
pub use discard::discard;

#[path = "include/bsl/char_type.rs"]
#[doc(hidden)]
pub mod char_type;
pub use char_type::CharT;
#[path = "include/bsl/cstr_type.rs"]
#[doc(hidden)]
pub mod cstr_type;
pub use cstr_type::CStrT;
#[path = "include/bsl/cptr_type.rs"]
#[doc(hidden)]
pub mod cptr_type;
pub use cptr_type::CPtrT;

#[path = "include/bsl/source_location.rs"]
#[doc(hidden)]
pub mod source_location;
pub use source_location::here;
pub use source_location::SourceLocation;

#[path = "include/bsl/integer.rs"]
#[doc(hidden)]
pub mod integer;
pub use integer::Integer;
pub use integer::SignedInteger;
pub use integer::UnsignedInteger;

#[path = "include/bsl/color.rs"]
#[doc(hidden)]
pub mod color;
pub use color::blk;
pub use color::blu;
pub use color::bold_blk;
pub use color::bold_blu;
pub use color::bold_cyn;
pub use color::bold_grn;
pub use color::bold_mag;
pub use color::bold_red;
pub use color::bold_wht;
pub use color::bold_ylw;
pub use color::cyn;
pub use color::grn;
pub use color::mag;
pub use color::red;
pub use color::rst;
pub use color::wht;
pub use color::ylw;

#[macro_use]
#[path = "include/bsl/debug.rs"]
#[doc(hidden)]
pub mod debug;

#[macro_use]
#[path = "include/bsl/debug_levels.rs"]
#[doc(hidden)]
pub mod debug_levels;
pub use debug_levels::debug_level_is_at_least_v;
pub use debug_levels::debug_level_is_at_least_vv;
pub use debug_levels::debug_level_is_at_least_vvv;
pub use debug_levels::debug_level_is_critical_only;

#[path = "include/bsl/exit_code.rs"]
#[doc(hidden)]
pub mod exit_code;
pub use exit_code::exit_failure;
pub use exit_code::exit_success;
pub use exit_code::ExitCode;

#[path = "include/bsl/basic_errc_type.rs"]
#[doc(hidden)]
pub mod basic_errc_type;
pub use basic_errc_type::BasicErrcType;
#[path = "include/bsl/errc_type.rs"]
#[doc(hidden)]
pub mod errc_type;
pub use errc_type::errc_already_exists;
pub use errc_type::errc_assetion;
pub use errc_type::errc_busy;
pub use errc_type::errc_divide_by_zero;
pub use errc_type::errc_failure;
pub use errc_type::errc_index_out_of_bounds;
pub use errc_type::errc_invalid_argument;
pub use errc_type::errc_narrow_overflow;
pub use errc_type::errc_nullptr_dereference;
pub use errc_type::errc_postcondition;
pub use errc_type::errc_precondition;
pub use errc_type::errc_signed_overflow;
pub use errc_type::errc_success;
pub use errc_type::errc_unsigned_wrap;
pub use errc_type::errc_unsupported;
pub use errc_type::ErrcType;

#[path = "include/bsl/into_bool.rs"]
#[doc(hidden)]
pub mod into_bool;
pub use into_bool::IntoBool;

#[macro_use]
#[path = "include/bsl/assert.rs"]
#[doc(hidden)]
pub mod assert;
pub use assert::assert;
#[path = "include/bsl/expects.rs"]
#[doc(hidden)]
pub mod expects;
pub use expects::expects;
#[path = "include/bsl/ensures.rs"]
#[doc(hidden)]
pub mod ensures;
pub use ensures::ensures;

#[path = "include/bsl/finally.rs"]
#[doc(hidden)]
pub mod finally;
pub use finally::Finally;

#[path = "include/bsl/safe_integral.rs"]
#[doc(hidden)]
pub mod safe_integral;
pub use safe_integral::make_safe;
pub use safe_integral::SafeI16;
pub use safe_integral::SafeI32;
pub use safe_integral::SafeI64;
pub use safe_integral::SafeI8;
pub use safe_integral::SafeIntegral;
pub use safe_integral::SafeU16;
pub use safe_integral::SafeU32;
pub use safe_integral::SafeU64;
pub use safe_integral::SafeU8;
pub use safe_integral::SafeUMx;
#[path = "include/bsl/safe_idx.rs"]
#[doc(hidden)]
pub mod safe_idx;
pub use safe_idx::SafeIdx;

#[path = "include/bsl/into_safe_integral.rs"]
#[doc(hidden)]
pub mod into_safe_integral;
pub use into_safe_integral::IntoSafeIntegral;

#[path = "include/bsl/convert.rs"]
#[doc(hidden)]
pub mod convert;
pub use convert::merge_umx_with_u16;
pub use convert::merge_umx_with_u32;
pub use convert::merge_umx_with_u8;
pub use convert::to_i16;
pub use convert::to_i32;
pub use convert::to_i64;
pub use convert::to_i8;
pub use convert::to_idx;
pub use convert::to_u16;
pub use convert::to_u16_unsafe;
pub use convert::to_u32;
pub use convert::to_u32_unsafe;
pub use convert::to_u64;
pub use convert::to_u64_unsafe;
pub use convert::to_u8;
pub use convert::to_u8_unsafe;
pub use convert::to_umx;
pub use convert::to_umx_unsafe;
