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

#include "conditional.hpp"
#include "enable_if.hpp"
#include "forward.hpp"
#include "is_constant_evaluated.hpp"
#include "is_pointer.hpp"
#include "is_same.hpp"
#include "is_same_signedness.hpp"
#include "is_signed.hpp"
#include "is_standard_layout.hpp"
#include "numeric_limits.hpp"
#include "safe_integral.hpp"

namespace bsl
{
    /// <!-- description -->
    ///   @brief Used to signal to the user during compile-time that a
    ///     conversion error occurred that would result in the loss of
    ///     data.
    inline void
    conversion_failure_narrowing_results_in_loss_of_data() noexcept
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
    ///   @param val the integral to convert from F to T
    ///   @return Returns f converted from F to T
    ///
    template<typename T, typename F>
    [[nodiscard]] constexpr auto
    convert(F const &val) noexcept -> safe_integral<T>
    {
        using t_limits = numeric_limits<T>;
        using f_limits = numeric_limits<F>;

        if constexpr (is_same<F, T>::value) {
            return safe_integral<T>{static_cast<T>(val)};
        }

        if constexpr (is_signed<F>::value) {
            if constexpr (is_signed<T>::value) {
                constexpr bsl::intmax t_max{static_cast<bsl::intmax>(t_limits::max())};
                constexpr bsl::intmax t_min{static_cast<bsl::intmax>(t_limits::min())};
                constexpr bsl::intmax f_max{static_cast<bsl::intmax>(f_limits::max())};

                if constexpr (f_max < t_max) {
                    return safe_integral<T>{static_cast<T>(val)};
                }
                else if constexpr (f_max == t_max) {
                    return safe_integral<T>{static_cast<T>(val)};
                }
                else {
                    if (static_cast<bsl::intmax>(val) > t_max) {
                        conversion_failure_narrowing_results_in_loss_of_data();
                        return safe_integral<T>::zero(true);
                    }

                    if (static_cast<bsl::intmax>(val) < t_min) {
                        conversion_failure_narrowing_results_in_loss_of_data();
                        return safe_integral<T>::zero(true);
                    }

                    return safe_integral<T>{static_cast<T>(val)};
                }
            }
            else {
                constexpr bsl::uintmax t_max{static_cast<bsl::uintmax>(t_limits::max())};
                constexpr bsl::uintmax f_max{static_cast<bsl::uintmax>(f_limits::max())};

                if (static_cast<bsl::intmax>(val) < static_cast<bsl::intmax>(0)) {
                    conversion_failure_narrowing_results_in_loss_of_data();
                    return safe_integral<T>::zero(true);
                }

                if constexpr (f_max < t_max) {
                    return safe_integral<T>{static_cast<T>(val)};
                }
                else if constexpr (f_max == t_max) {
                    return safe_integral<T>{static_cast<T>(val)};
                }
                else {
                    if (static_cast<bsl::uintmax>(val) > t_max) {
                        conversion_failure_narrowing_results_in_loss_of_data();
                        return safe_integral<T>::zero(true);
                    }

                    return safe_integral<T>{static_cast<T>(val)};
                }
            }
        }
        else {
            if constexpr (is_signed<T>::value) {
                constexpr bsl::uintmax t_max{static_cast<bsl::uintmax>(t_limits::max())};
                constexpr bsl::uintmax f_max{static_cast<bsl::uintmax>(f_limits::max())};

                if constexpr (f_max < t_max) {
                    return safe_integral<T>{static_cast<T>(val)};
                }
                else if constexpr (f_max == t_max) {
                    return safe_integral<T>{static_cast<T>(val)};
                }
                else {
                    if (static_cast<bsl::uintmax>(val) > t_max) {
                        conversion_failure_narrowing_results_in_loss_of_data();
                        return safe_integral<T>::zero(true);
                    }

                    return safe_integral<T>{static_cast<T>(val)};
                }
            }
            else {
                constexpr bsl::uintmax t_max{static_cast<bsl::uintmax>(t_limits::max())};
                constexpr bsl::uintmax f_max{static_cast<bsl::uintmax>(f_limits::max())};

                if constexpr (f_max < t_max) {
                    return safe_integral<T>{static_cast<T>(val)};
                }
                else if constexpr (f_max == t_max) {
                    return safe_integral<T>{static_cast<T>(val)};
                }
                else {
                    if (static_cast<bsl::uintmax>(val) > t_max) {
                        conversion_failure_narrowing_results_in_loss_of_data();
                        return safe_integral<T>::zero(true);
                    }

                    return safe_integral<T>{static_cast<T>(val)};
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
    ///   @param val the integral to convert from F to T
    ///   @return Returns f converted from F to T
    ///
    template<typename T, typename F>
    [[nodiscard]] constexpr auto
    convert(safe_integral<F> const &val) noexcept -> safe_integral<T>
    {
        if (val.failure()) {
            return safe_integral<T>::zero(true);
        }

        return convert<T>(val.get());
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
    [[nodiscard]] constexpr auto
    to_i8(safe_integral<T> const &val) noexcept -> bsl::safe_int8
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
    [[nodiscard]] constexpr auto
    to_i8(T const val) noexcept -> bsl::safe_int8
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
    [[nodiscard]] constexpr auto
    to_i16(safe_integral<T> const &val) noexcept -> bsl::safe_int16
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
    [[nodiscard]] constexpr auto
    to_i16(T const val) noexcept -> bsl::safe_int16
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
    [[nodiscard]] constexpr auto
    to_i32(safe_integral<T> const &val) noexcept -> bsl::safe_int32
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
    [[nodiscard]] constexpr auto
    to_i32(T const val) noexcept -> bsl::safe_int32
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
    [[nodiscard]] constexpr auto
    to_i64(safe_integral<T> const &val) noexcept -> bsl::safe_int64
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
    [[nodiscard]] constexpr auto
    to_i64(T const val) noexcept -> bsl::safe_int64
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
    [[nodiscard]] constexpr auto
    to_imax(safe_integral<T> const &val) noexcept -> bsl::safe_intmax
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
    [[nodiscard]] constexpr auto
    to_imax(T const val) noexcept -> bsl::safe_intmax
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
    [[nodiscard]] constexpr auto
    to_u8(safe_integral<T> const &val) noexcept -> bsl::safe_uint8
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
    [[nodiscard]] constexpr auto
    to_u8(T const val) noexcept -> bsl::safe_uint8
    {
        return convert<bsl::uint8>(val);
    }

    /// <!-- description -->
    ///   @brief Returns static_cast<bsl::uint8>(val.get())
    ///   @include convert/example_convert_to_u8_unsafe.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of integral to convert
    ///   @param val the integral to convert
    ///   @return Returns static_cast<bsl::uint8>(val.get())
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    to_u8_unsafe(safe_integral<T> const &val) noexcept -> bsl::safe_uint8
    {
        return static_cast<bsl::uint8>(val.get());
    }

    /// <!-- description -->
    ///   @brief Returns static_cast<bsl::uint8>(val);
    ///   @include convert/example_convert_to_u8_unsafe.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of integral to convert
    ///   @param val the integral to convert
    ///   @return Returns static_cast<bsl::uint8>(val);
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    to_u8_unsafe(T const val) noexcept -> bsl::safe_uint8
    {
        return static_cast<bsl::uint8>(val);
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
    [[nodiscard]] constexpr auto
    to_u16(safe_integral<T> const &val) noexcept -> bsl::safe_uint16
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
    [[nodiscard]] constexpr auto
    to_u16(T const val) noexcept -> bsl::safe_uint16
    {
        return convert<bsl::uint16>(val);
    }

    /// <!-- description -->
    ///   @brief Returns static_cast<bsl::uint16>(val.get())
    ///   @include convert/example_convert_to_u16_unsafe.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of integral to convert
    ///   @param val the integral to convert
    ///   @return Returns static_cast<bsl::uint16>(val.get())
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    to_u16_unsafe(safe_integral<T> const &val) noexcept -> bsl::safe_uint16
    {
        return static_cast<bsl::uint16>(val.get());
    }

    /// <!-- description -->
    ///   @brief Returns static_cast<bsl::uint16>(val);
    ///   @include convert/example_convert_to_u16_unsafe.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of integral to convert
    ///   @param val the integral to convert
    ///   @return Returns static_cast<bsl::uint16>(val);
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    to_u16_unsafe(T const val) noexcept -> bsl::safe_uint16
    {
        return static_cast<bsl::uint16>(val);
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
    [[nodiscard]] constexpr auto
    to_u32(safe_integral<T> const &val) noexcept -> bsl::safe_uint32
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
    [[nodiscard]] constexpr auto
    to_u32(T const val) noexcept -> bsl::safe_uint32
    {
        return convert<bsl::uint32>(val);
    }

    /// <!-- description -->
    ///   @brief Returns static_cast<bsl::uint32>(val.get())
    ///   @include convert/example_convert_to_u32_unsafe.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of integral to convert
    ///   @param val the integral to convert
    ///   @return Returns static_cast<bsl::uint32>(val.get())
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    to_u32_unsafe(safe_integral<T> const &val) noexcept -> bsl::safe_uint32
    {
        return static_cast<bsl::uint32>(val.get());
    }

    /// <!-- description -->
    ///   @brief Returns static_cast<bsl::uint32>(val);
    ///   @include convert/example_convert_to_u32_unsafe.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of integral to convert
    ///   @param val the integral to convert
    ///   @return Returns static_cast<bsl::uint32>(val);
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    to_u32_unsafe(T const val) noexcept -> bsl::safe_uint32
    {
        return static_cast<bsl::uint32>(val);
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
    [[nodiscard]] constexpr auto
    to_u64(safe_integral<T> const &val) noexcept -> bsl::safe_uint64
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
    [[nodiscard]] constexpr auto
    to_u64(T const val) noexcept -> bsl::safe_uint64
    {
        return convert<bsl::uint64>(val);
    }

    /// <!-- description -->
    ///   @brief Returns static_cast<bsl::uint64>(val.get())
    ///   @include convert/example_convert_to_u64_unsafe.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of integral to convert
    ///   @param val the integral to convert
    ///   @return Returns static_cast<bsl::uint64>(val.get())
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    to_u64_unsafe(safe_integral<T> const &val) noexcept -> bsl::safe_uint64
    {
        return static_cast<bsl::uint64>(val.get());
    }

    /// <!-- description -->
    ///   @brief Returns static_cast<bsl::uint64>(val);
    ///   @include convert/example_convert_to_u64_unsafe.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of integral to convert
    ///   @param val the integral to convert
    ///   @return Returns static_cast<bsl::uint64>(val);
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    to_u64_unsafe(T const val) noexcept -> bsl::safe_uint64
    {
        return static_cast<bsl::uint64>(val);
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
    [[nodiscard]] constexpr auto
    to_umax(safe_integral<T> const &val) noexcept -> bsl::safe_uintmax
    {
        return convert<bsl::uintmax>(val);
    }

    /// <!-- description -->
    ///   @brief Returns convert<bsl::uintmax>(val)
    ///   @include convert/example_convert_to_umax.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of integral/pointer to convert
    ///   @param val the integral/pointer to convert
    ///   @return Returns convert<bsl::uintmax>(val)
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    to_umax(T const val) noexcept -> bsl::safe_uintmax
    {
        if constexpr (bsl::is_pointer<T>::value) {
            static_assert(is_standard_layout<T>::value);

            if (nullptr == val) {
                return bsl::safe_uintmax::zero(true);
            }

            // A reinterpret cast is needed her as there is no other way
            // to perform the conversion. If a conversion like this is
            // needed, this is the compliant way to do it.
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
            return convert<bsl::uintmax>(reinterpret_cast<bsl::uintmax>(val));
        }
        else {
            return convert<bsl::uintmax>(val);
        }
    }

    /// <!-- description -->
    ///   @brief Returns static_cast<bsl::uintmax>(val.get())
    ///   @include convert/example_convert_to_umax_unsafe.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of integral to convert
    ///   @param val the integral to convert
    ///   @return Returns static_cast<bsl::uintmax>(val.get())
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    to_umax_unsafe(safe_integral<T> const &val) noexcept -> bsl::safe_uintmax
    {
        return static_cast<bsl::uintmax>(val.get());
    }

    /// <!-- description -->
    ///   @brief Returns static_cast<bsl::uintmax>(val);
    ///   @include convert/example_convert_to_umax_unsafe.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of integral to convert
    ///   @param val the integral to convert
    ///   @return Returns static_cast<bsl::uintmax>(val);
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    to_umax_unsafe(T const val) noexcept -> bsl::safe_uintmax
    {
        return static_cast<bsl::uintmax>(val);
    }

    /// <!-- description -->
    ///   @brief Returns reinterpret_cast<T *>(val.get())
    ///   @include convert/example_convert_to_ptr.hpp
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of integral to convert
    ///   @param val the integral to convert
    ///   @return Returns reinterpret_cast<T *>(val.get())
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    to_ptr(bsl::safe_uintmax const &val) noexcept -> T
    {
        static_assert(is_pointer<T>::value);
        static_assert(is_standard_layout<T>::value);

        if (!val) {
            return nullptr;
        }

        // A reinterpret cast is needed her as there is no other way
        // to perform the conversion. If a conversion like this is
        // needed, this is the compliant way to do it.
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        return reinterpret_cast<T>(val.get());
    }

    /// <!-- description -->
    ///   @brief Returns to_umax(sizeof(T))
    ///   @related bsl::safe_integral
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of integral to get the sizeof
    ///   @return Returns to_umax(sizeof(T))
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    size_of() noexcept -> bsl::safe_uintmax
    {
        return to_umax(sizeof(T));
    }
}

#endif
