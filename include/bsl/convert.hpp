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

#include "bsl/cstr_type.hpp"
#include "bsl/enable_if.hpp"
#include "bsl/ensures.hpp"
#include "bsl/from_chars.hpp"
#include "bsl/is_integral.hpp"
#include "bsl/is_same.hpp"
#include "bsl/is_signed.hpp"
#include "bsl/numeric_limits.hpp"
#include "bsl/safe_idx.hpp"
#include "bsl/safe_integral.hpp"
#include "bsl/string_view.hpp"
#include "bsl/touch.hpp"
#include "bsl/unlikely.hpp"

#include <bsl/assert.hpp>

namespace bsl
{
    /// <!-- description -->
    ///   @brief Used to signal to the user during compile-time that a
    ///     conversion error occurred when attempting to execute a
    ///     user-defined literal.
    ///
    inline void
    invalid_literal_tokens() noexcept
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
    ///   @param other the integral to convert from F to T
    ///   @return Returns f converted from F to T
    ///
    template<typename T, typename F>
    [[nodiscard]] constexpr auto
    convert_raw(F const &other) noexcept -> safe_integral<T>
    {
        using t_limits = numeric_limits<T>;
        using f_limits = numeric_limits<F>;

        if constexpr (is_same<F, T>::value) {
            return safe_integral<T>{static_cast<T>(other)};
        }

        if constexpr (is_signed<F>::value) {
            if constexpr (is_signed<T>::value) {
                constexpr bsl::int64 t_max{static_cast<bsl::int64>(t_limits::max_value())};
                constexpr bsl::int64 t_min{static_cast<bsl::int64>(t_limits::min_value())};
                constexpr bsl::int64 f_max{static_cast<bsl::int64>(f_limits::max_value())};

                if constexpr (f_max < t_max) {
                    return safe_integral<T>{static_cast<T>(other)};
                }
                else if constexpr (f_max == t_max) {
                    return safe_integral<T>{static_cast<T>(other)};
                }
                else {
                    if (unlikely(static_cast<bsl::int64>(other) > t_max)) {
                        return safe_integral<T>::failure();
                    }

                    if (unlikely(static_cast<bsl::int64>(other) < t_min)) {
                        return safe_integral<T>::failure();
                    }

                    return safe_integral<T>{static_cast<T>(other)};
                }
            }
            else {
                constexpr bsl::uintmx t_max{static_cast<bsl::uintmx>(t_limits::max_value())};
                constexpr bsl::uintmx f_max{static_cast<bsl::uintmx>(f_limits::max_value())};

                if (unlikely(static_cast<bsl::int64>(other) < static_cast<bsl::int64>(0))) {
                    return safe_integral<T>::failure();
                }

                if constexpr (f_max < t_max) {
                    return safe_integral<T>{static_cast<T>(other)};
                }
                else if constexpr (f_max == t_max) {
                    return safe_integral<T>{static_cast<T>(other)};
                }
                else {
                    if (unlikely(static_cast<bsl::uintmx>(other) > t_max)) {
                        return safe_integral<T>::failure();
                    }

                    return safe_integral<T>{static_cast<T>(other)};
                }
            }
        }
        else {
            if constexpr (is_signed<T>::value) {
                constexpr bsl::uintmx t_max{static_cast<bsl::uintmx>(t_limits::max_value())};
                constexpr bsl::uintmx f_max{static_cast<bsl::uintmx>(f_limits::max_value())};

                if constexpr (f_max < t_max) {
                    return safe_integral<T>{static_cast<T>(other)};
                }
                else if constexpr (f_max == t_max) {
                    return safe_integral<T>{static_cast<T>(other)};
                }
                else {
                    if (unlikely(static_cast<bsl::uintmx>(other) > t_max)) {
                        return safe_integral<T>::failure();
                    }

                    return safe_integral<T>{static_cast<T>(other)};
                }
            }
            else {
                constexpr bsl::uintmx t_max{static_cast<bsl::uintmx>(t_limits::max_value())};
                constexpr bsl::uintmx f_max{static_cast<bsl::uintmx>(f_limits::max_value())};

                if constexpr (f_max < t_max) {
                    return safe_integral<T>{static_cast<T>(other)};
                }
                else if constexpr (f_max == t_max) {
                    return safe_integral<T>{static_cast<T>(other)};
                }
                else {
                    if (unlikely(static_cast<bsl::uintmx>(other) > t_max)) {
                        return safe_integral<T>::failure();
                    }

                    return safe_integral<T>{static_cast<T>(other)};
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
    ///   @param other the integral to convert from F to T
    ///   @return Returns f converted from F to T
    ///
    template<typename T, typename F>
    [[nodiscard]] constexpr auto
    convert_sfe(safe_integral<F> const &other) noexcept -> safe_integral<T>
    {
        return safe_integral<T>{convert_raw<T>(other.cdata_as_ref()), other};
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
    ///   @tparam T the integral type to convert to
    ///   @param other the integral to convert from F to T
    ///   @return Returns f converted from F to T
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    convert_sfe(safe_idx const &other) noexcept -> safe_integral<T>
    {
        if (other.is_invalid()) {
            return safe_integral<T>::failure();
        }

        return safe_integral<T>{convert_raw<T>(other.cdata_as_ref())};
    }

    // -------------------------------------------------------------------------
    // predefined conversion functions
    // -------------------------------------------------------------------------

    /// <!-- description -->
    ///   @brief Returns convert_sfe<bsl::int8>(other)
    ///   @include convert/example_convert_to_i8.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of integral to convert
    ///   @param other the integral to convert
    ///   @return Returns convert_sfe<bsl::int8>(other)
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    to_i8(safe_integral<T> const &other) noexcept -> safe_i8
    {
        return convert_sfe<bsl::int8>(other);
    }

    /// <!-- description -->
    ///   @brief Returns convert_sfe<bsl::int8>(other)
    ///   @include convert/example_convert_to_i8.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @param other the integral to convert
    ///   @return Returns convert_sfe<bsl::int8>(other)
    ///
    [[nodiscard]] constexpr auto
    to_i8(safe_idx const &other) noexcept -> safe_i8
    {
        return convert_sfe<bsl::int8>(other);
    }

    /// <!-- description -->
    ///   @brief Returns convert_sfe<bsl::int8>(other)
    ///   @include convert/example_convert_to_i8.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of integral to convert
    ///   @param other the integral to convert
    ///   @return Returns convert_sfe<bsl::int8>(other)
    ///
    template<typename T, enable_if_t<is_integral<T>::value, bool> = true>
    [[nodiscard]] constexpr auto
    to_i8(T const other) noexcept -> safe_i8
    {
        return convert_raw<bsl::int8>(other);
    }

    /// <!-- description -->
    ///   @brief Returns convert_sfe<bsl::int16>(other)
    ///   @include convert/example_convert_to_i16.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of integral to convert
    ///   @param other the integral to convert
    ///   @return Returns convert_sfe<bsl::int16>(other)
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    to_i16(safe_integral<T> const &other) noexcept -> safe_i16
    {
        return convert_sfe<bsl::int16>(other);
    }

    /// <!-- description -->
    ///   @brief Returns convert_sfe<bsl::int16>(other)
    ///   @include convert/example_convert_to_i16.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @param other the integral to convert
    ///   @return Returns convert_sfe<bsl::int16>(other)
    ///
    [[nodiscard]] constexpr auto
    to_i16(safe_idx const &other) noexcept -> safe_i16
    {
        return convert_sfe<bsl::int16>(other);
    }

    /// <!-- description -->
    ///   @brief Returns convert_sfe<bsl::int16>(other)
    ///   @include convert/example_convert_to_i16.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of integral to convert
    ///   @param other the integral to convert
    ///   @return Returns convert_sfe<bsl::int16>(other)
    ///
    template<typename T, enable_if_t<is_integral<T>::value, bool> = true>
    [[nodiscard]] constexpr auto
    to_i16(T const other) noexcept -> safe_i16
    {
        return convert_raw<bsl::int16>(other);
    }

    /// <!-- description -->
    ///   @brief Returns convert_sfe<bsl::int32>(other)
    ///   @include convert/example_convert_to_i32.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of integral to convert
    ///   @param other the integral to convert
    ///   @return Returns convert_sfe<bsl::int32>(other)
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    to_i32(safe_integral<T> const &other) noexcept -> safe_i32
    {
        return convert_sfe<bsl::int32>(other);
    }

    /// <!-- description -->
    ///   @brief Returns convert_sfe<bsl::int32>(other)
    ///   @include convert/example_convert_to_i32.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @param other the integral to convert
    ///   @return Returns convert_sfe<bsl::int32>(other)
    ///
    [[nodiscard]] constexpr auto
    to_i32(safe_idx const &other) noexcept -> safe_i32
    {
        return convert_sfe<bsl::int32>(other);
    }

    /// <!-- description -->
    ///   @brief Returns convert_sfe<bsl::int32>(other)
    ///   @include convert/example_convert_to_i32.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of integral to convert
    ///   @param other the integral to convert
    ///   @return Returns convert_sfe<bsl::int32>(other)
    ///
    template<typename T, enable_if_t<is_integral<T>::value, bool> = true>
    [[nodiscard]] constexpr auto
    to_i32(T const other) noexcept -> safe_i32
    {
        return convert_raw<bsl::int32>(other);
    }

    /// <!-- description -->
    ///   @brief Returns convert_sfe<bsl::int64>(other)
    ///   @include convert/example_convert_to_i64.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of integral to convert
    ///   @param other the integral to convert
    ///   @return Returns convert_sfe<bsl::int64>(other)
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    to_i64(safe_integral<T> const &other) noexcept -> safe_i64
    {
        return convert_sfe<bsl::int64>(other);
    }

    /// <!-- description -->
    ///   @brief Returns convert_sfe<bsl::int64>(other)
    ///   @include convert/example_convert_to_i64.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @param other the integral to convert
    ///   @return Returns convert_sfe<bsl::int64>(other)
    ///
    [[nodiscard]] constexpr auto
    to_i64(safe_idx const &other) noexcept -> safe_i64
    {
        return convert_sfe<bsl::int64>(other);
    }

    /// <!-- description -->
    ///   @brief Returns convert_sfe<bsl::int64>(other)
    ///   @include convert/example_convert_to_i64.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of integral to convert
    ///   @param other the integral to convert
    ///   @return Returns convert_sfe<bsl::int64>(other)
    ///
    template<typename T, enable_if_t<is_integral<T>::value, bool> = true>
    [[nodiscard]] constexpr auto
    to_i64(T const other) noexcept -> safe_i64
    {
        return convert_raw<bsl::int64>(other);
    }

    /// <!-- description -->
    ///   @brief Returns convert_sfe<bsl::uint8>(other)
    ///   @include convert/example_convert_to_u8.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of integral to convert
    ///   @param other the integral to convert
    ///   @return Returns convert_sfe<bsl::uint8>(other)
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    to_u8(safe_integral<T> const &other) noexcept -> safe_u8
    {
        return convert_sfe<bsl::uint8>(other);
    }

    /// <!-- description -->
    ///   @brief Returns convert_sfe<bsl::uint8>(other)
    ///   @include convert/example_convert_to_u8.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @param other the integral to convert
    ///   @return Returns convert_sfe<bsl::uint8>(other)
    ///
    [[nodiscard]] constexpr auto
    to_u8(safe_idx const &other) noexcept -> safe_u8
    {
        return convert_sfe<bsl::uint8>(other);
    }

    /// <!-- description -->
    ///   @brief Returns convert_sfe<bsl::uint8>(other)
    ///   @include convert/example_convert_to_u8.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of integral to convert
    ///   @param other the integral to convert
    ///   @return Returns convert_sfe<bsl::uint8>(other)
    ///
    template<typename T, enable_if_t<is_integral<T>::value, bool> = true>
    [[nodiscard]] constexpr auto
    to_u8(T const other) noexcept -> safe_u8
    {
        return convert_raw<bsl::uint8>(other);
    }

    /// <!-- description -->
    ///   @brief Returns static_cast<bsl::uint8>(other.get())
    ///   @include convert/example_convert_to_u8_unsafe.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of integral to convert
    ///   @param other the integral to convert
    ///   @return Returns static_cast<bsl::uint8>(other.get())
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    to_u8_unsafe(safe_integral<T> const &other) noexcept -> safe_u8
    {
        return safe_u8{static_cast<bsl::uint8>(other.get()), other};
    }

    /// <!-- description -->
    ///   @brief Returns static_cast<bsl::uint8>(other);
    ///   @include convert/example_convert_to_u8_unsafe.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of integral to convert
    ///   @param other the integral to convert
    ///   @return Returns static_cast<bsl::uint8>(other);
    ///
    template<typename T, enable_if_t<is_integral<T>::value, bool> = true>
    [[nodiscard]] constexpr auto
    to_u8_unsafe(T const other) noexcept -> safe_u8
    {
        return safe_u8{static_cast<bsl::uint8>(other)};
    }

    /// <!-- description -->
    ///   @brief Returns convert_sfe<bsl::uint16>(other)
    ///   @include convert/example_convert_to_u16.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of integral to convert
    ///   @param other the integral to convert
    ///   @return Returns convert_sfe<bsl::uint16>(other)
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    to_u16(safe_integral<T> const &other) noexcept -> safe_u16
    {
        return convert_sfe<bsl::uint16>(other);
    }

    /// <!-- description -->
    ///   @brief Returns convert_sfe<bsl::uint16>(other)
    ///   @include convert/example_convert_to_u16.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @param other the integral to convert
    ///   @return Returns convert_sfe<bsl::uint16>(other)
    ///
    [[nodiscard]] constexpr auto
    to_u16(safe_idx const &other) noexcept -> safe_u16
    {
        return convert_sfe<bsl::uint16>(other);
    }

    /// <!-- description -->
    ///   @brief Returns convert_sfe<bsl::uint16>(other)
    ///   @include convert/example_convert_to_u16.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of integral to convert
    ///   @param other the integral to convert
    ///   @return Returns convert_sfe<bsl::uint16>(other)
    ///
    template<typename T, enable_if_t<is_integral<T>::value, bool> = true>
    [[nodiscard]] constexpr auto
    to_u16(T const other) noexcept -> safe_u16
    {
        return convert_raw<bsl::uint16>(other);
    }

    /// <!-- description -->
    ///   @brief Returns static_cast<bsl::uint16>(other.get())
    ///   @include convert/example_convert_to_u16_unsafe.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of integral to convert
    ///   @param other the integral to convert
    ///   @return Returns static_cast<bsl::uint16>(other.get())
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    to_u16_unsafe(safe_integral<T> const &other) noexcept -> safe_u16
    {
        return safe_u16{static_cast<bsl::uint16>(other.get()), other};
    }

    /// <!-- description -->
    ///   @brief Returns static_cast<bsl::uint16>(other);
    ///   @include convert/example_convert_to_u16_unsafe.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of integral to convert
    ///   @param other the integral to convert
    ///   @return Returns static_cast<bsl::uint16>(other);
    ///
    template<typename T, enable_if_t<is_integral<T>::value, bool> = true>
    [[nodiscard]] constexpr auto
    to_u16_unsafe(T const other) noexcept -> safe_u16
    {
        return safe_u16{static_cast<bsl::uint16>(other)};
    }

    /// <!-- description -->
    ///   @brief Returns convert_sfe<bsl::uint32>(other)
    ///   @include convert/example_convert_to_u32.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of integral to convert
    ///   @param other the integral to convert
    ///   @return Returns convert_sfe<bsl::uint32>(other)
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    to_u32(safe_integral<T> const &other) noexcept -> safe_u32
    {
        return convert_sfe<bsl::uint32>(other);
    }

    /// <!-- description -->
    ///   @brief Returns convert_sfe<bsl::uint32>(other)
    ///   @include convert/example_convert_to_u32.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @param other the integral to convert
    ///   @return Returns convert_sfe<bsl::uint32>(other)
    ///
    [[nodiscard]] constexpr auto
    to_u32(safe_idx const &other) noexcept -> safe_u32
    {
        return convert_sfe<bsl::uint32>(other);
    }

    /// <!-- description -->
    ///   @brief Returns convert_sfe<bsl::uint32>(other)
    ///   @include convert/example_convert_to_u32.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of integral to convert
    ///   @param other the integral to convert
    ///   @return Returns convert_sfe<bsl::uint32>(other)
    ///
    template<typename T, enable_if_t<is_integral<T>::value, bool> = true>
    [[nodiscard]] constexpr auto
    to_u32(T const other) noexcept -> safe_u32
    {
        return convert_raw<bsl::uint32>(other);
    }

    /// <!-- description -->
    ///   @brief Returns static_cast<bsl::uint32>(other.get())
    ///   @include convert/example_convert_to_u32_unsafe.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of integral to convert
    ///   @param other the integral to convert
    ///   @return Returns static_cast<bsl::uint32>(other.get())
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    to_u32_unsafe(safe_integral<T> const &other) noexcept -> safe_u32
    {
        return safe_u32{static_cast<bsl::uint32>(other.get()), other};
    }

    /// <!-- description -->
    ///   @brief Returns static_cast<bsl::uint32>(other);
    ///   @include convert/example_convert_to_u32_unsafe.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of integral to convert
    ///   @param other the integral to convert
    ///   @return Returns static_cast<bsl::uint32>(other);
    ///
    template<typename T, enable_if_t<is_integral<T>::value, bool> = true>
    [[nodiscard]] constexpr auto
    to_u32_unsafe(T const other) noexcept -> safe_u32
    {
        return safe_u32{static_cast<bsl::uint32>(other)};
    }

    /// <!-- description -->
    ///   @brief Returns convert_sfe<bsl::uint64>(other)
    ///   @include convert/example_convert_to_u64.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of integral to convert
    ///   @param other the integral to convert
    ///   @return Returns convert_sfe<bsl::uint64>(other)
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    to_u64(safe_integral<T> const &other) noexcept -> safe_u64
    {
        return convert_sfe<bsl::uint64>(other);
    }

    /// <!-- description -->
    ///   @brief Returns convert_sfe<bsl::uint64>(other)
    ///   @include convert/example_convert_to_u64.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @param other the integral to convert
    ///   @return Returns convert_sfe<bsl::uint64>(other)
    ///
    [[nodiscard]] constexpr auto
    to_u64(safe_idx const &other) noexcept -> safe_u64
    {
        return convert_sfe<bsl::uint64>(other);
    }

    /// <!-- description -->
    ///   @brief Returns convert_sfe<bsl::uint64>(other)
    ///   @include convert/example_convert_to_u64.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of integral to convert
    ///   @param other the integral to convert
    ///   @return Returns convert_sfe<bsl::uint64>(other)
    ///
    template<typename T, enable_if_t<is_integral<T>::value, bool> = true>
    [[nodiscard]] constexpr auto
    to_u64(T const other) noexcept -> safe_u64
    {
        return convert_raw<bsl::uint64>(other);
    }

    /// <!-- description -->
    ///   @brief Returns static_cast<bsl::uint64>(other.get())
    ///   @include convert/example_convert_to_u64_unsafe.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of integral to convert
    ///   @param other the integral to convert
    ///   @return Returns static_cast<bsl::uint64>(other.get())
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    to_u64_unsafe(safe_integral<T> const &other) noexcept -> safe_u64
    {
        return safe_u64{static_cast<bsl::uint64>(other.get()), other};
    }

    /// <!-- description -->
    ///   @brief Returns static_cast<bsl::uint64>(other);
    ///   @include convert/example_convert_to_u64_unsafe.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of integral to convert
    ///   @param other the integral to convert
    ///   @return Returns static_cast<bsl::uint64>(other);
    ///
    template<typename T, enable_if_t<is_integral<T>::value, bool> = true>
    [[nodiscard]] constexpr auto
    to_u64_unsafe(T const other) noexcept -> safe_u64
    {
        return safe_u64{static_cast<bsl::uint64>(other)};
    }

    /// <!-- description -->
    ///   @brief Returns convert_sfe<bsl::uintmx>(other)
    ///   @include convert/example_convert_to_umx.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @param other the integral to convert
    ///   @return Returns convert_sfe<bsl::uintmx>(other)
    ///
    [[nodiscard]] constexpr auto
    to_umx(safe_idx const &other) noexcept -> safe_umx
    {
        return convert_sfe<bsl::uintmx>(other);
    }

    /// <!-- description -->
    ///   @brief Returns convert_sfe<bsl::uintmx>(other)
    ///   @include convert/example_convert_to_umx.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of integral to convert
    ///   @param other the integral to convert
    ///   @return Returns convert_sfe<bsl::uintmx>(other)
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    to_umx(safe_integral<T> const &other) noexcept -> safe_umx
    {
        return convert_sfe<bsl::uintmx>(other);
    }

    /// <!-- description -->
    ///   @brief Returns convert_sfe<bsl::uintmx>(other)
    ///   @include convert/example_convert_to_umx.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of integral to convert
    ///   @param other the integral to convert
    ///   @return Returns convert_sfe<bsl::uintmx>(other)
    ///
    template<typename T, enable_if_t<is_integral<T>::value, bool> = true>
    [[nodiscard]] constexpr auto
    to_umx(T const other) noexcept -> safe_umx
    {
        return convert_raw<bsl::uintmx>(other);
    }

    /// <!-- description -->
    ///   @brief Returns static_cast<bsl::uintmx>(other.get())
    ///   @include convert/example_convert_to_umx_unsafe.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of integral to convert
    ///   @param other the integral to convert
    ///   @return Returns static_cast<bsl::uintmx>(other.get())
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    to_umx_unsafe(safe_integral<T> const &other) noexcept -> safe_umx
    {
        return safe_umx{static_cast<bsl::uintmx>(other.get()), other};
    }

    /// <!-- description -->
    ///   @brief Returns static_cast<bsl::uintmx>(other);
    ///   @include convert/example_convert_to_umx_unsafe.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of integral to convert
    ///   @param other the integral to convert
    ///   @return Returns static_cast<bsl::uintmx>(other);
    ///
    template<typename T, enable_if_t<is_integral<T>::value, bool> = true>
    [[nodiscard]] constexpr auto
    to_umx_unsafe(T const other) noexcept -> safe_umx
    {
        return safe_umx{static_cast<bsl::uintmx>(other)};
    }

    /// <!-- description -->
    ///   @brief Returns safe_idx{bsl::to_umx(val).get()}. If the conversion
    ///     produces an invalid safe_integral, npos is returned.
    ///   @include convert/example_convert_to_idx.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of integral to convert
    ///   @param other the integral to convert
    ///   @param sloc the location of the call site
    ///   @return Returns safe_idx{bsl::to_umx(val).get()}
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    to_idx(safe_integral<T> const &other, source_location const &sloc = here()) noexcept -> safe_idx
    {
        return safe_idx{to_umx(other), sloc};
    }

    /// <!-- description -->
    ///   @brief Returns safe_idx{bsl::to_umx(val).get()}. If the conversion
    ///     produces an invalid safe_integral, npos is returned.
    ///   @include convert/example_convert_to_idx.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @param other the integral to convert
    ///   @return Returns safe_idx{bsl::to_umx(val).get()}
    ///
    [[nodiscard]] constexpr auto
    to_idx(safe_idx const &other) noexcept -> safe_idx
    {
        return other;
    }

    /// <!-- description -->
    ///   @brief Returns safe_idx{bsl::to_umx(val).get()}. If the conversion
    ///     produces an invalid safe_integral, npos is returned.
    ///   @include convert/example_convert_to_idx.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of integral to convert
    ///   @param other the integral to convert
    ///   @param sloc the location of the call site
    ///   @return Returns safe_idx{bsl::to_umx(val).get()}
    ///
    template<typename T, enable_if_t<is_integral<T>::value, bool> = true>
    [[nodiscard]] constexpr auto
    to_idx(T const other, source_location const &sloc = here()) noexcept -> safe_idx
    {
        return safe_idx{to_umx(other), sloc};
    }

    /// <!-- description -->
    ///   @brief Returns (upper & 0xFFFFFFFFFFFFFF00) | to_umx(lower)
    ///   @include convert/example_convert_merge_umx_with.hpp
    ///
    /// <!-- inputs/outputs -->
    ///   @param upper the integral to merge with lower
    ///   @param lower the integral to merge with upper
    ///   @return Returns (upper & 0xFFFFFFFFFFFFFF00) | to_umx(lower)
    ///
    [[nodiscard]] constexpr auto
    merge_umx_with_u8(safe_umx const &upper, safe_u8 const &lower) noexcept -> safe_umx
    {
        constexpr auto mask{to_umx(0xFFFFFFFFFFFFFF00U)};
        return (upper & mask) | to_umx(lower);
    }

    /// <!-- description -->
    ///   @brief Returns (upper & 0xFFFFFFFFFFFFFF00) | to_umx(lower)
    ///   @include convert/example_convert_merge_umx_with.hpp
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam U Used to ensure the provided integer is the same as
    ///     T, effectively preventing implicit conversions from being
    ///     allowed.
    ///   @param upper the integral to merge with lower
    ///   @param lower the integral to merge with upper
    ///   @return Returns (upper & 0xFFFFFFFFFFFFFF00) | to_umx(lower)
    ///
    template<typename U, enable_if_t<is_same<bsl::uintmx, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    merge_umx_with_u8(U const upper, safe_u8 const &lower) noexcept -> safe_umx
    {
        constexpr auto mask{to_umx(0xFFFFFFFFFFFFFF00U)};
        return (upper & mask) | to_umx(lower);
    }

    /// <!-- description -->
    ///   @brief Returns (upper & 0xFFFFFFFFFFFF0000) | to_umx(lower)
    ///   @include convert/example_convert_merge_umx_with.hpp
    ///
    /// <!-- inputs/outputs -->
    ///   @param upper the integral to merge with lower
    ///   @param lower the integral to merge with upper
    ///   @return Returns (upper & 0xFFFFFFFFFFFF0000) | to_umx(lower)
    ///
    [[nodiscard]] constexpr auto
    merge_umx_with_u16(safe_umx const &upper, safe_u16 const &lower) noexcept -> safe_umx
    {
        constexpr auto mask{to_umx(0xFFFFFFFFFFFF0000U)};
        return (upper & mask) | to_umx(lower);
    }

    /// <!-- description -->
    ///   @brief Returns (upper & 0xFFFFFFFFFFFF0000) | to_umx(lower)
    ///   @include convert/example_convert_merge_umx_with.hpp
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam U Used to ensure the provided integer is the same as
    ///     T, effectively preventing implicit conversions from being
    ///     allowed.
    ///   @param upper the integral to merge with lower
    ///   @param lower the integral to merge with upper
    ///   @return Returns (upper & 0xFFFFFFFFFFFF0000) | to_umx(lower)
    ///
    template<typename U, enable_if_t<is_same<bsl::uintmx, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    merge_umx_with_u16(U const upper, safe_u16 const &lower) noexcept -> safe_umx
    {
        constexpr auto mask{to_umx(0xFFFFFFFFFFFF0000U)};
        return (upper & mask) | to_umx(lower);
    }

    /// <!-- description -->
    ///   @brief Returns (upper & 0xFFFFFFFF00000000) | to_umx(lower)
    ///   @include convert/example_convert_merge_umx_with.hpp
    ///
    /// <!-- inputs/outputs -->
    ///   @param upper the integral to merge with lower
    ///   @param lower the integral to merge with upper
    ///   @return Returns (upper & 0xFFFFFFFF00000000) | to_umx(lower)
    ///
    [[nodiscard]] constexpr auto
    merge_umx_with_u32(safe_umx const &upper, safe_u32 const &lower) noexcept -> safe_umx
    {
        constexpr auto mask{to_umx(0xFFFFFFFF00000000U)};
        return (upper & mask) | to_umx(lower);
    }

    /// <!-- description -->
    ///   @brief Returns (upper & 0xFFFFFFFF00000000) | to_umx(lower)
    ///   @include convert/example_convert_merge_umx_with.hpp
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam U Used to ensure the provided integer is the same as
    ///     T, effectively preventing implicit conversions from being
    ///     allowed.
    ///   @param upper the integral to merge with lower
    ///   @param lower the integral to merge with upper
    ///   @return Returns (upper & 0xFFFFFFFF00000000) | to_umx(lower)
    ///
    template<typename U, enable_if_t<is_same<bsl::uintmx, U>::value, bool> = true>
    [[nodiscard]] constexpr auto
    merge_umx_with_u32(U const upper, safe_u32 const &lower) noexcept -> safe_umx
    {
        constexpr auto mask{to_umx(0xFFFFFFFF00000000U)};
        return (upper & mask) | to_umx(lower);
    }
}

// -------------------------------------------------------------------------
// user defined literals
// -------------------------------------------------------------------------

/// NOTE:
/// - Rule A13-1-1 of the AUTOSAR spec specifically prohibits the use
///   of user-defined literals because "A programmer has limited control on
///   the types of parameters passed to user-defined conversion operators.
///   Also, it is implementation-defined whether fixed-size types from
///   <cstdint> header are compatible with the types allowed by user-defined
///   literals."
///
///   The problem with this rule is it is total nonsense (due to how raw
///   literals work, vs. cooked literals which is what the rule focuses on).
///   This rule is also dangerous, specifically because of how these types
///   are handled:
///   https://en.cppreference.com/w/cpp/language/integer_literal
///
///   As can be seen from the list above, the compiler has to determine which
///   type to return based on the size of the literal. This is even worse
///   for hexidecimal types, where the compiler has to determine whether or
///   not the type is signed or not. Most importantly, the way the compiler
///   converts these types from literal to "int" or "unsigned long long" has
///   no direct comparison to fixed-width types. In otherwords, the following
///   is extremely dangerous:
///
///   uint64_t mask = 0xFFFF00000000FFFF
///
///   Based on the rules above, the compiler is allowed to view these as
///   either a long long int, or an unsigned long long int.
///
///   uint64_t mask = 0xFFFF00000000FFFFU
///
///   The above adds a U. Based on the above reference, the compiler would
///   be forced to convert this to an unsigned long long int. The problem is,
///   most compilers complain about the use of U when you should be using UL
///   or ULL (depending on your compiler). In most cases, the compile will
///   attempt an implicit cast to make it work. Meaning, U is really reserved
///   for "unsigned", but you cannot use UL or ULL because these have different
///   meanings depending on the compiler you use.
///
///   AUTOSAR itself does not allow you to use the native types specifically
///   because of this issue, but at the same time, it only allows you to use
///   native literal types, forcing implicit casts that could lose data.
///
///   In the example for rule A13-1-1:
///
///   constexpr std::uint64_t operator"" _m(std::uint64_t meters)
///   {
///       return meters;
///   }
///
///   They claim that because you cannot state std::uint64_t, user-defined
///   literals should not be allowed because you don't have control, but then
///   do not provide an alternative on how to handle unsigned, 64bit literals.
///   This example is total non-sense as it is not valid C++. They are making
///   changes to the syntax and then complaining that the compiler cannot
///   make sense of this. Really? Let's look at the following:
///
///   uint64_t mask = static_cast<uint64_t>(0xFFFF00000000FFFF)
///
///   The above code does not tell the compiler that the literal is 64bits.
///   Instead, it says, please take the literal that you have, whatever type
///   it is, and convert it to a uint64_t. This can be seen when asking Clang
///   to dump the contents of it's AST tree, as an explicit cast can be seen
///   in the tree. If you don't include the static cast, you will see an
///   implicit cast instead. The type of the literal is compiler specific,
///   which is then converted into a uint64_t.
///
///   The problem with this rule is that it ignores how literals are processed
///   by the compiler. Literals by the compiler are just a string, that is
///   converted into a type based on the rules provided by C++. User-defined
///   literals tell the compiler how to interpret this string. The reason that
///   the user-defined literal signature only supports unsigned long long is
///   not because it converts the type to an unsigned long long. It tells the
///   compiler, "if you have an intergal type, do this". Meaning, you don't
///   need a std::uint64_t version of a user-defined literal to ensure you get
///   fixed-width types from user-defined literals.
///
///   To further explain this, just look at negative literals. C++ itself
///   states that all decimals are "int" (at least with most compilers).
///   This would suggest that "-42" is then an int that contains "-42". It is
///   not. The literal "-42" is actually "42" as an "int". Then, the compiler
///   will apply the "-" operator to this int, producing a value of "-42". This
///   is why INT_MIN uses math. The value of INT_MIN without the negative is
///   too large to fit into an int, and the compiler must first place the
///   positive version of the number into "int" and then apply the "-"
///   operator. To handle this, INT_MIN is actually -INT_MAX -1. Another way
///   of putting it is, there is no way to define INT_MIN as a literal, it
///   must be calculated (assuming 2's compliment, which we do).
///
///   This rule also doesn't talk about the difference between cooked literals
///   and raw literals.
///   - A raw literal takes the form char const *. It allows the user-defined
///     literal to take any integral or float type and convert it to the
///     type that they care about.
///   - A cooked literal is the rest of the user-defined literal signatures.
///
///   Even if cooked user-defined literals were a problem, surely the raw
///   literal type would be acceptable. Specifically, using the raw literal
///   form, you could take any integral and parse the characters manually,
///   ensuring that you have complete control of the resulting type.
///
///   In otherwords... user-defined literals absolutely give you complete
///   control. In fact, there is no way to give you more control of how to
///   interpret a literal then giving you raw access to character tokens in the
///   literal. What this suggests is that rule A13-1-1 makes no sense, or
///   was not fully evaluated, or simply not evaluated properly.
///
///   So, we will need an exception for this, as not allowing user-defined
///   literals is actually more dangerous in practice due to the fact that C++
///   does not provide a means to initialize fixed-width types in a safe
///   way that doesn't generate implicit casts. The question then becomes, how
///   should we implement user-defined literals to safely initialize our
///   fixed-width types, which is what this rule should actually have done.
///
///   One approach would be to use the cooked versions as described here.
///   http://www.open-std.org/jtc1/sc22/wg21/docs/papers/2019/p1280r2.html
///
///   The problem with this approach is that overflows are allowed. Meaning
///   the compiler will truncate silently any info that is not actually used.
///   For this reason, we use the raw literal approach, and we parse the
///   actual literal tokens by hand. This is all constexpr friendly, but it
///   ensures that it is impossible to make a mistake. We also add tests at
///   the end of the header to prove that these are working properly.
///
///   If this rule is specific to the cooked versions, with complaints about
///   you cannot prevent the detection of overflowed data, the rule should
///   have stated to use raw literals instead of the cooked versions. Simply
///   stating that they are not allowed is dangerous and demonstrates that
///   user-defined literals were never actually looked at properly.
///

/// <!-- description -->
///   @brief Returns bsl::to_u8(str) using bsl::from_chars. Attempting to use
///     this literal outside of a constexpr is undefined. If a conversion error
///     occurs during constexpr evaluation, a compile error will occur. This
///     literal ensures that the returned safe_integral is both valid and
///     checked.
///
/// <!-- inputs/outputs -->
///   @param str the literal to convert
///   @return Returns bsl::to_u8(str) using bsl::from_chars
///
[[nodiscard]] constexpr auto operator""_u8(bsl::cstr_type const str) noexcept -> bsl::safe_u8
{
    constexpr auto base10{bsl::to_i32(10)};
    constexpr auto base16{bsl::to_i32(16)};

    bsl::safe_u8 mut_val{};
    bsl::string_view const view{str};

    if (view.starts_with("0x")) {
        mut_val = bsl::from_chars<bsl::uint8>(view.substr(bsl::safe_idx::magic_2()).data(), base16);
    }
    else {
        mut_val = bsl::from_chars<bsl::uint8>(view, base10);
    }

    if (bsl::unlikely(mut_val.is_poisoned())) {
        bsl::invalid_literal_tokens();
        bsl::assert("invalid literal tokens", bsl::here());
    }
    else {
        bsl::touch();
    }

    bsl::ensures(mut_val.is_valid_and_checked());
    return mut_val;
}

/// <!-- description -->
///   @brief Returns bsl::to_u16(str) using bsl::from_chars. Attempting to use
///     this literal outside of a constexpr is undefined. If a conversion error
///     occurs during constexpr evaluation, a compile error will occur. This
///     literal ensures that the returned safe_integral is both valid and
///     checked.
///
/// <!-- inputs/outputs -->
///   @param str the literal to convert
///   @return Returns bsl::to_u16(str) using bsl::from_chars
///
[[nodiscard]] constexpr auto operator""_u16(bsl::cstr_type const str) noexcept -> bsl::safe_u16
{
    constexpr auto base10{bsl::to_i32(10)};
    constexpr auto base16{bsl::to_i32(16)};

    bsl::safe_u16 mut_val{};
    bsl::string_view const view{str};

    if (view.starts_with("0x")) {
        mut_val =
            bsl::from_chars<bsl::uint16>(view.substr(bsl::safe_idx::magic_2()).data(), base16);
    }
    else {
        mut_val = bsl::from_chars<bsl::uint16>(view, base10);
    }

    if (bsl::unlikely(mut_val.is_poisoned())) {
        bsl::invalid_literal_tokens();
        bsl::assert("invalid literal tokens", bsl::here());
    }
    else {
        bsl::touch();
    }

    bsl::ensures(mut_val.is_valid_and_checked());
    return mut_val;
}

/// <!-- description -->
///   @brief Returns bsl::to_u32(str) using bsl::from_chars. Attempting to use
///     this literal outside of a constexpr is undefined. If a conversion error
///     occurs during constexpr evaluation, a compile error will occur. This
///     literal ensures that the returned safe_integral is both valid and
///     checked.
///
/// <!-- inputs/outputs -->
///   @param str the literal to convert
///   @return Returns bsl::to_u32(str) using bsl::from_chars
///
[[nodiscard]] constexpr auto operator""_u32(bsl::cstr_type const str) noexcept -> bsl::safe_u32
{
    constexpr auto base10{bsl::to_i32(10)};
    constexpr auto base16{bsl::to_i32(16)};

    bsl::safe_u32 mut_val{};
    bsl::string_view const view{str};

    if (view.starts_with("0x")) {
        mut_val =
            bsl::from_chars<bsl::uint32>(view.substr(bsl::safe_idx::magic_2()).data(), base16);
    }
    else {
        mut_val = bsl::from_chars<bsl::uint32>(view, base10);
    }

    if (bsl::unlikely(mut_val.is_poisoned())) {
        bsl::invalid_literal_tokens();
        bsl::assert("invalid literal tokens", bsl::here());
    }
    else {
        bsl::touch();
    }

    bsl::ensures(mut_val.is_valid_and_checked());
    return mut_val;
}

/// <!-- description -->
///   @brief Returns bsl::to_u64(str) using bsl::from_chars. Attempting to use
///     this literal outside of a constexpr is undefined. If a conversion error
///     occurs during constexpr evaluation, a compile error will occur. This
///     literal ensures that the returned safe_integral is both valid and
///     checked.
///
/// <!-- inputs/outputs -->
///   @param str the literal to convert
///   @return Returns bsl::to_u64(str) using bsl::from_chars
///
[[nodiscard]] constexpr auto operator""_u64(bsl::cstr_type const str) noexcept -> bsl::safe_u64
{
    constexpr auto base10{bsl::to_i32(10)};
    constexpr auto base16{bsl::to_i32(16)};

    bsl::safe_u64 mut_val{};
    bsl::string_view const view{str};

    if (view.starts_with("0x")) {
        mut_val =
            bsl::from_chars<bsl::uint64>(view.substr(bsl::safe_idx::magic_2()).data(), base16);
    }
    else {
        mut_val = bsl::from_chars<bsl::uint64>(view, base10);
    }

    if (bsl::unlikely(mut_val.is_poisoned())) {
        bsl::invalid_literal_tokens();
        bsl::assert("invalid literal tokens", bsl::here());
    }
    else {
        bsl::touch();
    }

    bsl::ensures(mut_val.is_valid_and_checked());
    return mut_val;
}

/// <!-- description -->
///   @brief Returns bsl::to_umx(str) using bsl::from_chars. Attempting to use
///     this literal outside of a constexpr is undefined. If a conversion error
///     occurs during constexpr evaluation, a compile error will occur. This
///     literal ensures that the returned safe_integral is both valid and
///     checked.
///
/// <!-- inputs/outputs -->
///   @param str the literal to convert
///   @return Returns bsl::to_umx(str) using bsl::from_chars
///
[[nodiscard]] constexpr auto operator""_umx(bsl::cstr_type const str) noexcept -> bsl::safe_umx
{
    constexpr auto base10{bsl::to_i32(10)};
    constexpr auto base16{bsl::to_i32(16)};

    bsl::safe_umx mut_val{};
    bsl::string_view const view{str};

    if (view.starts_with("0x")) {
        mut_val =
            bsl::from_chars<bsl::uintmx>(view.substr(bsl::safe_idx::magic_2()).data(), base16);
    }
    else {
        mut_val = bsl::from_chars<bsl::uintmx>(view, base10);
    }

    if (bsl::unlikely(mut_val.is_poisoned())) {
        bsl::invalid_literal_tokens();
        bsl::assert("invalid literal tokens", bsl::here());
    }
    else {
        bsl::touch();
    }

    bsl::ensures(mut_val.is_valid_and_checked());
    return mut_val;
}

/// <!-- description -->
///   @brief Returns bsl::to_idx(str) using bsl::from_chars. Attempting to use
///     this literal outside of a constexpr is undefined. If a conversion error
///     occurs during constexpr evaluation, a compile error will occur. This
///     literal ensures that the returned safe_integral is both valid and
///     checked.
///
/// <!-- inputs/outputs -->
///   @param str the literal to convert
///   @return Returns bsl::to_idx(str) using bsl::from_chars
///
[[nodiscard]] constexpr auto operator""_idx(bsl::cstr_type const str) noexcept -> bsl::safe_idx
{
    constexpr auto base10{bsl::to_i32(10)};
    constexpr auto base16{bsl::to_i32(16)};

    bsl::safe_umx mut_val{};
    bsl::string_view const view{str};

    if (view.starts_with("0x")) {
        mut_val =
            bsl::from_chars<bsl::uintmx>(view.substr(bsl::safe_idx::magic_2()).data(), base16);
    }
    else {
        mut_val = bsl::from_chars<bsl::uintmx>(view, base10);
    }

    if (bsl::unlikely(mut_val.is_poisoned())) {
        bsl::invalid_literal_tokens();
        bsl::assert("invalid literal tokens", bsl::here());
    }
    else {
        bsl::touch();
    }

    bsl::ensures(mut_val.is_valid_and_checked());
    return bsl::safe_idx{mut_val.get()};
}

/// <!-- description -->
///   @brief Returns bsl::to_i8(str) using bsl::from_chars. Attempting to use
///     this literal outside of a constexpr is undefined. If a conversion error
///     occurs during constexpr evaluation, a compile error will occur. This
///     literal ensures that the returned safe_integral is both valid and
///     checked.
///
/// <!-- inputs/outputs -->
///   @param str the literal to convert
///   @return Returns bsl::to_i8(str) using bsl::from_chars
///
[[nodiscard]] constexpr auto operator""_i8(bsl::cstr_type const str) noexcept -> bsl::safe_i8
{
    constexpr auto base10{bsl::to_i32(10)};

    auto mut_val{bsl::from_chars<bsl::int8>(str, base10)};
    if (bsl::unlikely(mut_val.is_poisoned())) {
        bsl::invalid_literal_tokens();
        bsl::assert("invalid literal tokens", bsl::here());
    }
    else {
        bsl::touch();
    }

    bsl::ensures(mut_val.is_valid_and_checked());
    return mut_val;
}

/// <!-- description -->
///   @brief Returns bsl::to_i16(str) using bsl::from_chars. Attempting to use
///     this literal outside of a constexpr is undefined. If a conversion error
///     occurs during constexpr evaluation, a compile error will occur. This
///     literal ensures that the returned safe_integral is both valid and
///     checked.
///
/// <!-- inputs/outputs -->
///   @param str the literal to convert
///   @return Returns bsl::to_i16(str) using bsl::from_chars
///
[[nodiscard]] constexpr auto operator""_i16(bsl::cstr_type const str) noexcept -> bsl::safe_i16
{
    constexpr auto base10{bsl::to_i32(10)};

    auto mut_val{bsl::from_chars<bsl::int16>(str, base10)};
    if (bsl::unlikely(mut_val.is_poisoned())) {
        bsl::invalid_literal_tokens();
        bsl::assert("invalid literal tokens", bsl::here());
    }
    else {
        bsl::touch();
    }

    bsl::ensures(mut_val.is_valid_and_checked());
    return mut_val;
}

/// <!-- description -->
///   @brief Returns bsl::to_i32(str) using bsl::from_chars. Attempting to use
///     this literal outside of a constexpr is undefined. If a conversion error
///     occurs during constexpr evaluation, a compile error will occur. This
///     literal ensures that the returned safe_integral is both valid and
///     checked.
///
/// <!-- inputs/outputs -->
///   @param str the literal to convert
///   @return Returns bsl::to_i32(str) using bsl::from_chars
///
[[nodiscard]] constexpr auto operator""_i32(bsl::cstr_type const str) noexcept -> bsl::safe_i32
{
    constexpr auto base10{bsl::to_i32(10)};

    auto mut_val{bsl::from_chars<bsl::int32>(str, base10)};
    if (bsl::unlikely(mut_val.is_poisoned())) {
        bsl::invalid_literal_tokens();
        bsl::assert("invalid literal tokens", bsl::here());
    }
    else {
        bsl::touch();
    }

    bsl::ensures(mut_val.is_valid_and_checked());
    return mut_val;
}

/// <!-- description -->
///   @brief Returns bsl::to_i64(str) using bsl::from_chars. Attempting to use
///     this literal outside of a constexpr is undefined. If a conversion error
///     occurs during constexpr evaluation, a compile error will occur. This
///     literal ensures that the returned safe_integral is both valid and
///     checked.
///
/// <!-- inputs/outputs -->
///   @param str the literal to convert
///   @return Returns bsl::to_i64(str) using bsl::from_chars
///
[[nodiscard]] constexpr auto operator""_i64(bsl::cstr_type const str) noexcept -> bsl::safe_i64
{
    constexpr auto base10{bsl::to_i32(10)};

    auto mut_val{bsl::from_chars<bsl::int64>(str, base10)};
    if (bsl::unlikely(mut_val.is_poisoned())) {
        bsl::invalid_literal_tokens();
        bsl::assert("invalid literal tokens", bsl::here());
    }
    else {
        bsl::touch();
    }

    bsl::ensures(mut_val.is_valid_and_checked());
    return mut_val;
}

// -------------------------------------------------------------------------
// user defined literal tests
// -------------------------------------------------------------------------

namespace bsl
{
    /// NOTE:
    /// - These tests are here, and not in the unit tests to ensure that
    ///   wherever this header is used, these are verified.
    ///

    static_assert(0_u8 == bsl::safe_u8::min_value());
    static_assert(0_u16 == bsl::safe_u16::min_value());
    static_assert(0_u32 == bsl::safe_u32::min_value());
    static_assert(0_u64 == bsl::safe_u64::min_value());
    static_assert(0_umx == bsl::safe_umx::min_value());

    static_assert(255_u8 == bsl::safe_u8::max_value());
    static_assert(65535_u16 == bsl::safe_u16::max_value());
    static_assert(4294967295_u32 == bsl::safe_u32::max_value());
    static_assert(18446744073709551615_u64 == bsl::safe_u64::max_value());
    static_assert(18446744073709551615_umx == bsl::safe_umx::max_value());

    static_assert(0x0_u8 == bsl::safe_u8::min_value());
    static_assert(0x0_u16 == bsl::safe_u16::min_value());
    static_assert(0x0_u32 == bsl::safe_u32::min_value());
    static_assert(0x0_u64 == bsl::safe_u64::min_value());
    static_assert(0x0_umx == bsl::safe_umx::min_value());

    static_assert(0xFF_u8 == bsl::safe_u8::max_value());
    static_assert(0xFFFF_u16 == bsl::safe_u16::max_value());
    static_assert(0xFFFFFFFF_u32 == bsl::safe_u32::max_value());
    static_assert(0xFFFFFFFFFFFFFFFF_u64 == bsl::safe_u64::max_value());
    static_assert(0xFFFFFFFFFFFFFFFF_umx == bsl::safe_umx::max_value());

    /// NOTE:
    /// - As stated above, it is impossible to have an INT_MIN literal due to
    ///   how literals work. This is not only true for user-defined literals,
    ///   but also for the actual INT_MIN and friend macros that the compiler
    ///   provides.
    /// - These values must be calculated using -INT_MAX - 1. This is because
    ///   there is no such thing as a negative literal. Instead, you get the
    ///   positive portion of the literal, and the compiler then adds the "-"
    ///   operator later.
    ///

    static_assert((-127_i8 - 1_i8).checked() == bsl::safe_i8::min_value());
    static_assert((-32767_i16 - 1_i16).checked() == bsl::safe_i16::min_value());
    static_assert((-2147483647_i32 - 1_i32).checked() == bsl::safe_i32::min_value());
    static_assert((-9223372036854775807_i64 - 1_i64).checked() == bsl::safe_i64::min_value());

    static_assert(127_i8 == bsl::safe_i8::max_value());
    static_assert(32767_i16 == bsl::safe_i16::max_value());
    static_assert(2147483647_i32 == bsl::safe_i32::max_value());
    static_assert(9223372036854775807_i64 == bsl::safe_i64::max_value());
}

#endif
