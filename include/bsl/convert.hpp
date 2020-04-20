//
// Copyright (C) 2019 Assured Information Security, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#ifndef BSL_CONVERT_HPP
#define BSL_CONVERT_HPP

#include "enable_if.hpp"
#include "is_constant_evaluated.hpp"
#include "is_pointer.hpp"
#include "is_same.hpp"
#include "is_same_signedness.hpp"
#include "is_signed.hpp"
#include "numeric_limits.hpp"
#include "safe_integral.hpp"

namespace bsl
{
    /// <!-- description -->
    ///   @brief Used to signal to the user during compile-time that a
    ///     conversion error occurred that would result in the loss of
    ///     data.
    inline void
    conversion_failure__narrowing_results_in_loss_of_data() noexcept
    {}

    /// <!-- description -->
    ///   @brief Converts from a bsl::safe_integral of type F to type T.
    ///     This function will perform both widdening and narrowing
    ///     conversions so there is no need to distinguish between the
    ///     two. If the bsl::safe_integer that is provided has experienced
    ///     and error, this function will return 0 with the error flag set.
    ///     If a widdening conversion is taking place, this function will
    ///     be optimized out (assuming the signedness between F and T are
    ///     the same). As a result, when initializing a type, its best to
    ///     keep the signedness the same.
    ///   @include example_convert_overview.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam F the integral type to convert from
    ///   @tparam T the integral type to convert to
    ///   @param f the integral to convert from F to T
    ///   @return Returns f converted from F to T
    ///
    template<typename T, typename F>
    [[nodiscard]] constexpr safe_integral<T>
    convert(F const &f) noexcept
    {
        using t_limits = numeric_limits<T>;
        using f_limits = numeric_limits<F>;

        if constexpr (is_same<F, T>::value) {
            return safe_integral<T>{static_cast<T>(f)};
        }

        if constexpr (is_signed<F>::value) {
            if constexpr (is_signed<T>::value) {
                if constexpr (f_limits::max() <= t_limits::max()) {
                    return safe_integral<T>{static_cast<T>(f)};
                }
                else {
                    if ((f > t_limits::max()) || (f < t_limits::min())) {
                        conversion_failure__narrowing_results_in_loss_of_data();
                        return safe_integral<T>{static_cast<T>(0), true};
                    }

                    return safe_integral<T>{static_cast<T>(f)};
                }
            }
            else {
                if (f < 0) {
                    conversion_failure__narrowing_results_in_loss_of_data();
                    return safe_integral<T>{static_cast<T>(0), true};
                }

                if constexpr (static_cast<bsl::uintmax>(f_limits::max()) <= t_limits::max()) {
                    return safe_integral<T>{static_cast<T>(f)};
                }
                else {
                    if (static_cast<bsl::uintmax>(f) > t_limits::max()) {
                        conversion_failure__narrowing_results_in_loss_of_data();
                        return safe_integral<T>{static_cast<T>(0), true};
                    }

                    return safe_integral<T>{static_cast<T>(f)};
                }
            }
        }
        else {
            if constexpr (is_signed<T>::value) {
                if constexpr (f_limits::max() <= static_cast<bsl::uintmax>(t_limits::max())) {
                    return safe_integral<T>{static_cast<T>(f)};
                }
                else {
                    if (f > static_cast<bsl::uintmax>(t_limits::max())) {
                        conversion_failure__narrowing_results_in_loss_of_data();
                        return safe_integral<T>{static_cast<T>(0), true};
                    }

                    return safe_integral<T>{static_cast<T>(f)};
                }
            }
            else {
                if constexpr (f_limits::max() <= t_limits::max()) {
                    return safe_integral<T>{static_cast<T>(f)};
                }
                else {
                    if ((f > t_limits::max())) {
                        conversion_failure__narrowing_results_in_loss_of_data();
                        return safe_integral<T>{static_cast<T>(0), true};
                    }

                    return safe_integral<T>{static_cast<T>(f)};
                }
            }
        }
    }

    /// <!-- description -->
    ///   @brief Converts from a bsl::safe_integral of type F to type T.
    ///     This function will perform both widdening and narrowing
    ///     conversions so there is no need to distinguish between the
    ///     two. If the bsl::safe_integer that is provided has experienced
    ///     and error, this function will return 0 with the error flag set.
    ///     If a widdening conversion is taking place, this function will
    ///     be optimized out (assuming the signedness between F and T are
    ///     the same). As a result, when initializing a type, its best to
    ///     keep the signedness the same.
    ///   @include example_convert_overview.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam F the integral type to convert from
    ///   @tparam T the integral type to convert to
    ///   @param f the integral to convert from F to T
    ///   @return Returns f converted from F to T
    ///
    template<typename T, typename F>
    [[nodiscard]] constexpr safe_integral<T>
    convert(safe_integral<F> const &f) noexcept
    {
        if (f.failure()) {
            return safe_integral<T>{static_cast<T>(0), true};
        }

        return convert<T>(f.get());
    }

    /// <!-- description -->
    ///   @brief Returns convert<bsl::int8>(val)
    ///   @include convert/example_convert_to_i8.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of integral to convert
    ///   @param val the integral to convert
    ///   @return Returns convert<bsl::int8>(val)
    ///
    template<typename T>
    [[nodiscard]] constexpr bsl::safe_int8
    to_i8(safe_integral<T> const &val) noexcept
    {
        return convert<bsl::int8>(val);
    }

    /// <!-- description -->
    ///   @brief Returns convert<bsl::int8>(val)
    ///   @include convert/example_convert_to_i8.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of integral to convert
    ///   @param val the integral to convert
    ///   @return Returns convert<bsl::int8>(val)
    ///
    template<typename T>
    [[nodiscard]] constexpr bsl::safe_int8
    to_i8(T const val) noexcept
    {
        return convert<bsl::int8>(val);
    }

    /// <!-- description -->
    ///   @brief Returns convert<bsl::int16>(val)
    ///   @include convert/example_convert_to_i16.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of integral to convert
    ///   @param val the integral to convert
    ///   @return Returns convert<bsl::int16>(val)
    ///
    template<typename T>
    [[nodiscard]] constexpr bsl::safe_int16
    to_i16(safe_integral<T> const &val) noexcept
    {
        return convert<bsl::int16>(val);
    }

    /// <!-- description -->
    ///   @brief Returns convert<bsl::int16>(val)
    ///   @include convert/example_convert_to_i16.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of integral to convert
    ///   @param val the integral to convert
    ///   @return Returns convert<bsl::int16>(val)
    ///
    template<typename T>
    [[nodiscard]] constexpr bsl::safe_int16
    to_i16(T const val) noexcept
    {
        return convert<bsl::int16>(val);
    }

    /// <!-- description -->
    ///   @brief Returns convert<bsl::int32>(val)
    ///   @include convert/example_convert_to_i32.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of integral to convert
    ///   @param val the integral to convert
    ///   @return Returns convert<bsl::int32>(val)
    ///
    template<typename T>
    [[nodiscard]] constexpr bsl::safe_int32
    to_i32(safe_integral<T> const &val) noexcept
    {
        return convert<bsl::int32>(val);
    }

    /// <!-- description -->
    ///   @brief Returns convert<bsl::int32>(val)
    ///   @include convert/example_convert_to_i32.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of integral to convert
    ///   @param val the integral to convert
    ///   @return Returns convert<bsl::int32>(val)
    ///
    template<typename T>
    [[nodiscard]] constexpr bsl::safe_int32
    to_i32(T const val) noexcept
    {
        return convert<bsl::int32>(val);
    }

    /// <!-- description -->
    ///   @brief Returns convert<bsl::int64>(val)
    ///   @include convert/example_convert_to_i64.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of integral to convert
    ///   @param val the integral to convert
    ///   @return Returns convert<bsl::int64>(val)
    ///
    template<typename T>
    [[nodiscard]] constexpr bsl::safe_int64
    to_i64(safe_integral<T> const &val) noexcept
    {
        return convert<bsl::int64>(val);
    }

    /// <!-- description -->
    ///   @brief Returns convert<bsl::int64>(val)
    ///   @include convert/example_convert_to_i64.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of integral to convert
    ///   @param val the integral to convert
    ///   @return Returns convert<bsl::int64>(val)
    ///
    template<typename T>
    [[nodiscard]] constexpr bsl::safe_int64
    to_i64(T const val) noexcept
    {
        return convert<bsl::int64>(val);
    }

    /// <!-- description -->
    ///   @brief Returns convert<bsl::intmax>(val)
    ///   @include convert/example_convert_to_imax.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of integral to convert
    ///   @param val the integral to convert
    ///   @return Returns convert<bsl::intmax>(val)
    ///
    template<typename T>
    [[nodiscard]] constexpr bsl::safe_intmax
    to_imax(safe_integral<T> const &val) noexcept
    {
        return convert<bsl::intmax>(val);
    }

    /// <!-- description -->
    ///   @brief Returns convert<bsl::intmax>(val)
    ///   @include convert/example_convert_to_imax.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of integral to convert
    ///   @param val the integral to convert
    ///   @return Returns convert<bsl::intmax>(val)
    ///
    template<typename T>
    [[nodiscard]] constexpr bsl::safe_intmax
    to_imax(T const val) noexcept
    {
        return convert<bsl::intmax>(val);
    }

    /// <!-- description -->
    ///   @brief Returns convert<bsl::uint8>(val)
    ///   @include convert/example_convert_to_u8.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of integral to convert
    ///   @param val the integral to convert
    ///   @return Returns convert<bsl::uint8>(val)
    ///
    template<typename T>
    [[nodiscard]] constexpr bsl::safe_uint8
    to_u8(safe_integral<T> const &val) noexcept
    {
        return convert<bsl::uint8>(val);
    }

    /// <!-- description -->
    ///   @brief Returns convert<bsl::uint8>(val)
    ///   @include convert/example_convert_to_u8.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of integral to convert
    ///   @param val the integral to convert
    ///   @return Returns convert<bsl::uint8>(val)
    ///
    template<typename T>
    [[nodiscard]] constexpr bsl::safe_uint8
    to_u8(T const val) noexcept
    {
        return convert<bsl::uint8>(val);
    }

    /// <!-- description -->
    ///   @brief Returns convert<bsl::uint16>(val)
    ///   @include convert/example_convert_to_u16.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of integral to convert
    ///   @param val the integral to convert
    ///   @return Returns convert<bsl::uint16>(val)
    ///
    template<typename T>
    [[nodiscard]] constexpr bsl::safe_uint16
    to_u16(safe_integral<T> const &val) noexcept
    {
        return convert<bsl::uint16>(val);
    }

    /// <!-- description -->
    ///   @brief Returns convert<bsl::uint16>(val)
    ///   @include convert/example_convert_to_u16.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of integral to convert
    ///   @param val the integral to convert
    ///   @return Returns convert<bsl::uint16>(val)
    ///
    template<typename T>
    [[nodiscard]] constexpr bsl::safe_uint16
    to_u16(T const val) noexcept
    {
        return convert<bsl::uint16>(val);
    }

    /// <!-- description -->
    ///   @brief Returns convert<bsl::uint32>(val)
    ///   @include convert/example_convert_to_u32.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of integral to convert
    ///   @param val the integral to convert
    ///   @return Returns convert<bsl::uint32>(val)
    ///
    template<typename T>
    [[nodiscard]] constexpr bsl::safe_uint32
    to_u32(safe_integral<T> const &val) noexcept
    {
        return convert<bsl::uint32>(val);
    }

    /// <!-- description -->
    ///   @brief Returns convert<bsl::uint32>(val)
    ///   @include convert/example_convert_to_u32.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of integral to convert
    ///   @param val the integral to convert
    ///   @return Returns convert<bsl::uint32>(val)
    ///
    template<typename T>
    [[nodiscard]] constexpr bsl::safe_uint32
    to_u32(T const val) noexcept
    {
        return convert<bsl::uint32>(val);
    }

    /// <!-- description -->
    ///   @brief Returns convert<bsl::uint64>(val)
    ///   @include convert/example_convert_to_u64.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of integral to convert
    ///   @param val the integral to convert
    ///   @return Returns convert<bsl::uint64>(val)
    ///
    template<typename T>
    [[nodiscard]] constexpr bsl::safe_uint64
    to_u64(safe_integral<T> const &val) noexcept
    {
        return convert<bsl::uint64>(val);
    }

    /// <!-- description -->
    ///   @brief Returns convert<bsl::uint64>(val)
    ///   @include convert/example_convert_to_u64.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of integral to convert
    ///   @param val the integral to convert
    ///   @return Returns convert<bsl::uint64>(val)
    ///
    template<typename T>
    [[nodiscard]] constexpr bsl::safe_uint64
    to_u64(T const val) noexcept
    {
        return convert<bsl::uint64>(val);
    }

    /// <!-- description -->
    ///   @brief Returns convert<bsl::uintmax>(val)
    ///   @include convert/example_convert_to_umax.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of integral to convert
    ///   @param val the integral to convert
    ///   @return Returns convert<bsl::uintmax>(val)
    ///
    template<typename T>
    [[nodiscard]] constexpr bsl::safe_uintmax
    to_umax(safe_integral<T> const &val) noexcept
    {
        return convert<bsl::uintmax>(val);
    }

    /// <!-- description -->
    ///   @brief Returns convert<bsl::uintmax>(val)
    ///   @include convert/example_convert_to_umax.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of integral to convert
    ///   @param val the integral to convert
    ///   @return Returns convert<bsl::uintmax>(val)
    ///
    template<typename T>
    [[nodiscard]] constexpr bsl::safe_uintmax
    to_umax(T const val) noexcept
    {
        return convert<bsl::uintmax>(val);
    }

    /// <!-- description -->
    ///   @brief Returns convert<bsl::uintptr>(val)
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @param val the integral to convert
    ///   @return Returns convert<bsl::uintptr>(val)
    ///
    [[nodiscard]] constexpr bsl::safe_uintptr
    to_uptr(void const *const val) noexcept
    {
        if (is_constant_evaluated()) {
            return bsl::safe_uintptr{};
        }

        return convert<bsl::uintptr>(
            reinterpret_cast<bsl::uintptr>(val));    // NOLINT // PRQA S 1-10000
    }

    /// <!-- description -->
    ///   @brief Returns convert<bsl::uintptr>(val)
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of integral to convert
    ///   @param val the integral to convert
    ///   @return Returns convert<bsl::uintptr>(val)
    ///
    template<typename T>
    [[nodiscard]] constexpr bsl::safe_uintptr
    to_uptr(safe_integral<T> const &val) noexcept
    {
        return convert<bsl::uintptr>(val);
    }

    /// <!-- description -->
    ///   @brief Returns convert<bsl::uintptr>(val)
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of integral to convert
    ///   @param val the integral to convert
    ///   @return Returns convert<bsl::uintptr>(val)
    ///
    template<typename T, enable_if_t<!is_pointer<T>::value, bool> = true>
    [[nodiscard]] constexpr bsl::safe_uintptr
    to_uptr(T const val) noexcept
    {
        return convert<bsl::uintptr>(val);
    }
}

#endif
