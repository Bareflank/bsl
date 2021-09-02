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
/// @file cstring.hpp
///

#ifndef BSL_CSTRING_HPP
#define BSL_CSTRING_HPP

#include "bsl/char_type.hpp"
#include "bsl/cstr_type.hpp"
#include "bsl/discard.hpp"
#include "bsl/expects.hpp"
#include "bsl/is_constant_evaluated.hpp"
#include "bsl/is_trivial.hpp"
#include "bsl/safe_idx.hpp"
#include "bsl/safe_integral.hpp"
#include "bsl/unlikely.hpp"

// Notes: --
// - In general, you should not use these functions as they are not
//   Core Guideline or AUTOSAR compliant. We leverage them internally
//   within the BSL as this is the only way to ensure some of the BSL's
//   APIs have the proper optimizations.
// - We only implement the functions that we need here. Once again, do
//   not rely on this header.
// - The APIs of these functions have been modified to remove the need
//   for conversions as well as ensure sizes are provided (where possible).
//   This means that some of the APIs are our own to ensure there are not
//   issues with name collisions.
// - Each of these functions has safety added to them to ensure crashing is
//   not possible.
// - All function arguments are sent to bsl::discard to ensure you can replace
//   the builtins with static values without getting unused argument errors.
//

namespace bsl
{
    /// <!-- description -->
    ///   @brief Returns the same result as std::strlen with the exception
    ///     that any undefined behavior will return safe_i32::failure().
    ///
    /// <!-- inputs/outputs -->
    ///   @param str a pointer to a string to get the length of
    ///   @return Returns the same result as std::strlen with the exception
    ///     that any undefined behavior will return safe_i32::failure().
    ///
    [[nodiscard]] constexpr auto
    builtin_strlen(cstr_type const str) noexcept -> safe_umx
    {
        expects(nullptr != str);

        bsl::safe_idx mut_len{};
        while ('\0' != str[mut_len.get()]) {
            ++mut_len;
        }

        return safe_umx{mut_len.get()};
    }

    /// <!-- description -->
    ///   @brief Same as std::memset with parameter checks. If dst or count
    ///     is 0, this function returns nullptr.
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of dst to set
    ///   @param pmut_dst a pointer to the memory to set
    ///   @param ch the value to set the memory to
    ///   @param count the total number of bytes to set
    ///   @return Returns the same result as std::memset.
    ///
    template<typename T>
    [[maybe_unused]] constexpr auto
    builtin_memset(T *const pmut_dst, char_type const ch, safe_umx const &count) noexcept -> T *
    {
        static_assert(is_trivial<T>::value);

        expects(nullptr != pmut_dst);
        expects(count.is_valid_and_checked());

        if (unlikely(count.is_zero())) {
            return pmut_dst;
        }

        /// NOTE:
        /// - For now, with a constexpr version of this function, we only
        ///   support using memset to clear an array. During runtime, this
        ///   will get forwarded to a memset function which either the compiler
        ///   will provide, or the user will have to provide, which in most
        ///   cases should be arch specific as optimizations are critical
        ///   here.
        ///

        if (is_constant_evaluated()) {
            expects('\0' == ch);

            /// NOTE:
            /// - The input has already been verified. All we need to check
            ///   for is divide by 0 and this does not occur for both the
            ///   divide and the modulo, so we mark the results as checked.
            ///

            if ((count % sizeof(T)).checked().is_pos()) {
                unlikely_invalid_argument_failure();
                return nullptr;
            }

            auto const size{(count / sizeof(T)).checked()};
            for (safe_idx mut_i{}; mut_i < size; ++mut_i) {
                // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
                pmut_dst[mut_i.get()] = {};
            }

            return pmut_dst;
        }

        bsl::discard(__builtin_memset(pmut_dst, ch, count.get()));
        return pmut_dst;
    }

    /// <!-- description -->
    ///   @brief Same as std::memcpy with parameter checks. If dst, src are a
    ///     nullptr, or count is 0, this function returns nullptr.
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of src/dst to copy
    ///   @param pmut_dst a pointer to the memory to copy to
    ///   @param src a pointer to the memory to copy from
    ///   @param count the total number of bytes to copy
    ///   @return Returns the same result as std::memcpy.
    ///
    template<typename T>
    [[maybe_unused]] constexpr auto
    builtin_memcpy(T *const pmut_dst, T const *const src, safe_umx const &count) noexcept -> T *
    {
        static_assert(is_trivial<T>::value);

        expects(nullptr != pmut_dst);
        expects(nullptr != src);
        expects(count.is_valid_and_checked());

        if (unlikely(count.is_zero())) {
            return pmut_dst;
        }

        if (is_constant_evaluated()) {
            /// NOTE:
            /// - The input has already been verified. All we need to check
            ///   for is divide by 0 and this does not occur for both the
            ///   divide and the modulo, so we mark the results as checked.
            ///

            if ((count % sizeof(T)).checked().is_pos()) {
                unlikely_invalid_argument_failure();
                return nullptr;
            }

            auto const size{(count / sizeof(T)).checked()};
            for (safe_idx mut_i{}; mut_i < size; ++mut_i) {
                // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic, cppcoreguidelines-avoid-c-arrays, hicpp-avoid-c-arrays, modernize-avoid-c-arrays)
                pmut_dst[mut_i.get()] = src[mut_i.get()];
            }

            return pmut_dst;
        }

        bsl::discard(__builtin_memcpy(pmut_dst, src, count.get()));
        return pmut_dst;
    }
}

#endif
