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

// TODO:
// - Currently in Rust we don't have a print_thread_id() function. In C++,
//   this is done using some CMake magic, which is hard to do in Rust. Will
//   need to sort out a method to allow a user of this library to override
//   that function.
//

use core::fmt;
use core::fmt::Write;

// -----------------------------------------------------------------------------
// Extern C Functions
// -----------------------------------------------------------------------------

extern "C" {
    pub fn putchar(c: i32);
}

// -----------------------------------------------------------------------------
// Format Writers
// -----------------------------------------------------------------------------

pub struct Writer;
pub struct WriterForce;

impl fmt::Write for Writer {
    #[cfg(not(test))]
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for byte in s.bytes() {
            unsafe {
                putchar(byte as i32);
            }
        }

        return Ok(());
    }

    #[cfg(test)]
    fn write_str(&mut self, _s: &str) -> fmt::Result {
        return Ok(());
    }
}

impl fmt::Write for WriterForce {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for byte in s.bytes() {
            unsafe {
                putchar(byte as i32);
            }
        }

        return Ok(());
    }
}

pub fn print_fmt(args: core::fmt::Arguments) {
    Writer.write_fmt(args).unwrap();
}

pub fn print_force_fmt(args: core::fmt::Arguments) {
    WriterForce.write_fmt(args).unwrap();
}

// -----------------------------------------------------------------------------
// Print Macros
// -----------------------------------------------------------------------------

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {
        $crate::debug::print_fmt(format_args!($($arg)*))
    };
}

#[cfg(feature = "debug_level_v")]
#[macro_export]
macro_rules! print_v {
    ($($arg:tt)*) => { $crate::print!("{}", format_args!($($arg)*)) };
}

#[cfg(feature = "debug_level_vv")]
#[macro_export]
macro_rules! print_vv {
    ($($arg:tt)*) => { $crate::print!("{}", format_args!($($arg)*)) };
}

#[cfg(feature = "debug_level_vvv")]
#[macro_export]
macro_rules! print_vvv {
    ($($arg:tt)*) => { $crate::print!("{}", format_args!($($arg)*)) };
}

#[cfg(not(feature = "debug_level_v"))]
#[macro_export]
macro_rules! print_v {
    ($($arg:tt)*) => {};
}

#[cfg(not(feature = "debug_level_vv"))]
#[macro_export]
macro_rules! print_vv {
    ($($arg:tt)*) => {};
}

#[cfg(not(feature = "debug_level_vvv"))]
#[macro_export]
macro_rules! print_vvv {
    ($($arg:tt)*) => {};
}

// -----------------------------------------------------------------------------
// Debug Macros
// -----------------------------------------------------------------------------

#[cfg(feature = "disable_color")]
#[macro_export]
macro_rules! debug {
    ($($arg:tt)*) => {
        $crate::print!("DEBUG");
        print_thread_id!();
        $crate::print!(": {}", format_args!($($arg)*));
    };
}

#[cfg(not(feature = "disable_color"))]
#[macro_export]
macro_rules! debug {
    ($($arg:tt)*) => {
        $crate::print!("{}DEBUG{}", "\x1B[1;92m", "\x1B[0m");
        print_thread_id!();
        $crate::print!(": {}", format_args!($($arg)*));
    };
}

#[cfg(feature = "debug_level_v")]
#[macro_export]
macro_rules! debug_v {
    ($($arg:tt)*) => { $crate::debug!("{}", format_args!($($arg)*)) };
}

#[cfg(feature = "debug_level_vv")]
#[macro_export]
macro_rules! debug_vv {
    ($($arg:tt)*) => { $crate::debug!("{}", format_args!($($arg)*)) };
}

#[cfg(feature = "debug_level_vvv")]
#[macro_export]
macro_rules! debug_vvv {
    ($($arg:tt)*) => { $crate::debug!("{}", format_args!($($arg)*)) };
}

#[cfg(not(feature = "debug_level_v"))]
#[macro_export]
macro_rules! debug_v {
    ($($arg:tt)*) => {};
}

#[cfg(not(feature = "debug_level_vv"))]
#[macro_export]
macro_rules! debug_vv {
    ($($arg:tt)*) => {};
}

#[cfg(not(feature = "debug_level_vvv"))]
#[macro_export]
macro_rules! debug_vvv {
    ($($arg:tt)*) => {};
}

// -----------------------------------------------------------------------------
// Alert Macros
// -----------------------------------------------------------------------------

#[cfg(feature = "disable_color")]
#[macro_export]
macro_rules! alert {
    ($($arg:tt)*) => {
        $crate::print!("ALERT");
        print_thread_id!();
        $crate::print!(": {}", format_args!($($arg)*));
    };
}

#[cfg(not(feature = "disable_color"))]
#[macro_export]
macro_rules! alert {
    ($($arg:tt)*) => {
        $crate::print!("{}ALERT{}", "\x1B[1;93m", "\x1B[0m");
        print_thread_id!();
        $crate::print!(": {}", format_args!($($arg)*));
    };
}

#[cfg(feature = "debug_level_v")]
#[macro_export]
macro_rules! alert_v {
    ($($arg:tt)*) => { $crate::alert!("{}", format_args!($($arg)*)) };
}

#[cfg(feature = "debug_level_vv")]
#[macro_export]
macro_rules! alert_vv {
    ($($arg:tt)*) => { $crate::alert!("{}", format_args!($($arg)*)) };
}

#[cfg(feature = "debug_level_vvv")]
#[macro_export]
macro_rules! alert_vvv {
    ($($arg:tt)*) => { $crate::alert!("{}", format_args!($($arg)*)) };
}

#[cfg(not(feature = "debug_level_v"))]
#[macro_export]
macro_rules! alert_v {
    ($($arg:tt)*) => {};
}

#[cfg(not(feature = "debug_level_vv"))]
#[macro_export]
macro_rules! alert_vv {
    ($($arg:tt)*) => {};
}

#[cfg(not(feature = "debug_level_vvv"))]
#[macro_export]
macro_rules! alert_vvv {
    ($($arg:tt)*) => {};
}

// -----------------------------------------------------------------------------
// Error Macros
// -----------------------------------------------------------------------------

#[cfg(feature = "disable_color")]
#[macro_export]
macro_rules! error {
    ($($arg:tt)*) => {
        $crate::print!("ERROR");
        print_thread_id!();
        $crate::print!(": {}", format_args!($($arg)*));
    };
}

#[cfg(not(feature = "disable_color"))]
#[macro_export]
macro_rules! error {
    ($($arg:tt)*) => {
        $crate::print!("{}ERROR{}", "\x1B[1;91m", "\x1B[0m");
        print_thread_id!();
        $crate::print!(": {}", format_args!($($arg)*));
    };
}

// -----------------------------------------------------------------------------
// Print (Visible During Unit Testing)
// -----------------------------------------------------------------------------

#[macro_export]
macro_rules! print_test {
    ($($arg:tt)*) => {
        $crate::debug::print_force_fmt(format_args!($($arg)*))
    };
}

// -----------------------------------------------------------------------------
// Unit Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod test_debug {
    #[test]
    fn debug_general() {
        print!("this is print statement: {}\n", 42);
        debug!("this is debug statement: {}\n", 42);
        debug_v!("this is debug statement: {}\n", 42);
        debug_vv!("this is debug statement: {}\n", 42);
        debug_vvv!("this is debug statement: {}\n", 42);
        alert!("this is alert statement: {}\n", 42);
        alert_v!("this is alert statement: {}\n", 42);
        alert_vv!("this is alert statement: {}\n", 42);
        alert_vvv!("this is alert statement: {}\n", 42);
        error!("this is error statement: {}\n", 42);
        print_test!("this is print_test statement: {}\n", 42);
    }
}
