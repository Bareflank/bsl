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

/// <!-- description -->
///   @brief Returns true if the debug level was set to critical only
///
/// <!-- inputs/outputs -->
///   @return Returns true if the debug level was set to critical only
///
pub fn debug_level_is_critical_only() -> bool {
    if cfg!(feature = "debug_level_v") {
        return false;
    }

    if cfg!(feature = "debug_level_vv") {
        return false;
    }

    if cfg!(feature = "debug_level_vvv") {
        return false;
    }

    return true;
}

/// <!-- description -->
///   @brief Returns true if the debug level was set to at least V or
///     higher.
///
/// <!-- inputs/outputs -->
///   @return Returns true if the debug level was set to at least V or
///     higher.
///
pub fn debug_level_is_at_least_v() -> bool {
    if cfg!(feature = "debug_level_v") {
        return true;
    }

    if cfg!(feature = "debug_level_vv") {
        return true;
    }

    if cfg!(feature = "debug_level_vvv") {
        return true;
    }

    return false;
}

/// <!-- description -->
///   @brief Returns true if the debug level was set to at least V or
///     higher.
///
/// <!-- inputs/outputs -->
///   @return Returns true if the debug level was set to at least V or
///     higher.
///
pub fn debug_level_is_at_least_vv() -> bool {
    if cfg!(feature = "debug_level_v") {
        return false;
    }

    if cfg!(feature = "debug_level_vv") {
        return true;
    }

    if cfg!(feature = "debug_level_vvv") {
        return true;
    }

    return false;
}

/// <!-- description -->
///   @brief Returns true if the debug level was set to at least V or
///     higher.
///
/// <!-- inputs/outputs -->
///   @return Returns true if the debug level was set to at least V or
///     higher.
///
pub fn debug_level_is_at_least_vvv() -> bool {
    if cfg!(feature = "debug_level_v") {
        return false;
    }

    if cfg!(feature = "debug_level_vv") {
        return false;
    }

    if cfg!(feature = "debug_level_vvv") {
        return true;
    }

    return false;
}
