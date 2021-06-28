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
/// @file numeric_limits.hpp
///

#ifndef BSL_NUMERIC_LIMITS_HPP
#define BSL_NUMERIC_LIMITS_HPP

#include "char_type.hpp"
#include "climits.hpp"
#include "cstdint.hpp"
#include "float_denorm_style.hpp"
#include "float_round_style.hpp"
#include "is_unsigned.hpp"

namespace bsl
{
    namespace details
    {
        /// <!-- description -->
        ///   @brief Returns the number of Radix digits for a given type.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T the type to query
        ///   @return Returns the number of Radix digits for a given type.
        ///
        template<typename T>
        [[nodiscard]] constexpr auto
        get_digits() noexcept -> bsl::int32
        {
            constexpr bsl::int32 dec{1};

            if constexpr (is_unsigned<T>::value) {
                return (CHAR_BIT * static_cast<bsl::int32>(sizeof(T)));
            }

            return (CHAR_BIT * static_cast<bsl::int32>(sizeof(T))) - dec;
        }
    }

    /// @class bsl::numeric_limits
    ///
    /// <!-- description -->
    ///   @brief Implements std::numeric_limits
    ///   @include example_numeric_limits_overview.hpp
    ///
    /// <!-- template parameters -->
    ///   @tparam T the type to get information about
    ///
    template<typename T>
    class numeric_limits final
    {
    public:
        /// @brief stores whether or not this is a specialization
        static constexpr bool is_specialized{false};
        /// @brief stores whether or not T is exact
        static constexpr bool is_exact{false};
        /// @brief stores whether or not T has defined infinity
        static constexpr bool has_infinity{false};
        /// @brief stores whether or not T has a quiet NaN
        // We want our implementation to mimic C++ here.
        // NOLINTNEXTLINE(bsl-name-case)
        static constexpr bool has_quiet_NaN{false};
        /// @brief stores whether or not T has a signaling NaN
        // We want our implementation to mimic C++ here.
        // NOLINTNEXTLINE(bsl-name-case)
        static constexpr bool has_signaling_NaN{false};
        /// @brief stores the denorm style of T
        static constexpr float_denorm_style has_denorm{float_denorm_style::denorm_absent};
        /// @brief stores whether or not floating points detect loss
        static constexpr bool has_denorm_loss{false};
        /// @brief stores the rounding style of T
        static constexpr float_round_style round_style{float_round_style::round_toward_zero};
        /// @brief stores the type of floating point
        static constexpr bool is_iec559{false};
        /// @brief stores whether or not T is bounded
        static constexpr bool is_bounded{false};
        /// @brief stores whether or not T handles overflow with modulo
        static constexpr bool is_modulo{false};
        /// @brief stores the number of radix digits for T
        static constexpr bsl::int32 digits{0};
        /// @brief stores the number of base 10 digits for T
        static constexpr bsl::int32 digits10{0};
        /// @brief stores the number of base 10 digits to diff T
        static constexpr bsl::int32 max_digits10{0};
        /// @brief stores the integer base that presents digits
        static constexpr bsl::int32 radix{0};
        /// @brief stores the smallest negative exponential number
        static constexpr bsl::int32 min_exponent{0};
        /// @brief stores the smallest negative exponential number in base 10
        static constexpr bsl::int32 min_exponent10{0};
        /// @brief stores the largest positive exponential number
        static constexpr bsl::int32 max_exponent{0};
        /// @brief stores the largest positive exponential number in base 10
        static constexpr bsl::int32 max_exponent10{0};
        /// @brief stores whether T can generate a trap
        static constexpr bool traps{false};
        /// @brief stores whether or T detected tinyness before rounding
        static constexpr bool tinyness_before{false};

        /// <!-- description -->
        ///   @brief Returns the min value of T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the min value of T
        ///
        [[nodiscard]] static constexpr auto
        min() noexcept -> T
        {
            return {};
        }

        /// <!-- description -->
        ///   @brief Returns the lowest value of T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the lowest value of T
        ///
        [[nodiscard]] static constexpr auto
        lowest() noexcept -> T
        {
            return {};
        }

        /// <!-- description -->
        ///   @brief Returns the max value of T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the max value of T
        ///
        [[nodiscard]] static constexpr auto
        max() noexcept -> T
        {
            return {};
        }

        /// <!-- description -->
        ///   @brief Returns the floating point resolution
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the max value of T
        ///
        [[nodiscard]] static constexpr auto
        epsilon() noexcept -> T
        {
            return {};
        }

        /// <!-- description -->
        ///   @brief Returns the rounding error of T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the rounding error of T
        ///
        [[nodiscard]] static constexpr auto
        round_error() noexcept -> T
        {
            return {};
        }

        /// <!-- description -->
        ///   @brief Returns the value of infinity for T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of infinity for T
        ///
        [[nodiscard]] static constexpr auto
        infinity() noexcept -> T
        {
            return {};
        }

        /// <!-- description -->
        ///   @brief Returns the quiet NaN value for T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the quiet NaN value for T
        ///
        [[nodiscard]] static constexpr auto
        // We want our implementation to mimic C++ here.
        // NOLINTNEXTLINE(bsl-name-case)
        quiet_NaN() noexcept -> T
        {
            return {};
        }

        /// <!-- description -->
        ///   @brief Returns the signaling NaN value for T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the signaling NaN value for T
        ///
        [[nodiscard]] static constexpr auto
        // We want our implementation to mimic C++ here.
        // NOLINTNEXTLINE(bsl-name-case)
        signaling_NaN() noexcept -> T
        {
            return {};
        }

        /// <!-- description -->
        ///   @brief Returns the smallest subnormal value for T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the smallest subnormal value for T
        ///
        [[nodiscard]] static constexpr auto
        denorm_min() noexcept -> T
        {
            return {};
        }
    };

    /// @cond doxygen off

    /// @class bsl::numeric_limits
    ///
    /// <!-- description -->
    ///   @brief Implements std::numeric_limits
    ///   @include example_numeric_limits_overview.hpp
    ///
    template<>
    class numeric_limits<bool> final
    {
    public:
        /// @brief stores whether or not this is a specialization
        static constexpr bool is_specialized{true};
        /// @brief stores whether or not T is exact
        static constexpr bool is_exact{true};
        /// @brief stores whether or not T has defined infinity
        static constexpr bool has_infinity{false};
        /// @brief stores whether or not T has a quiet NaN
        // We want our implementation to mimic C++ here.
        // NOLINTNEXTLINE(bsl-name-case)
        static constexpr bool has_quiet_NaN{false};
        /// @brief stores whether or not T has a signaling NaN
        // We want our implementation to mimic C++ here.
        // NOLINTNEXTLINE(bsl-name-case)
        static constexpr bool has_signaling_NaN{false};
        /// @brief stores the denorm style of T
        static constexpr float_denorm_style has_denorm{float_denorm_style::denorm_absent};
        /// @brief stores whether or not floating points detect loss
        static constexpr bool has_denorm_loss{false};
        /// @brief stores the rounding style of T
        static constexpr float_round_style round_style{float_round_style::round_toward_zero};
        /// @brief stores the type of floating point
        static constexpr bool is_iec559{false};
        /// @brief stores whether or not T is bounded
        static constexpr bool is_bounded{true};
        /// @brief stores whether or not T handles overflow with modulo
        static constexpr bool is_modulo{false};
        /// @brief stores the number of radix digits for T
        static constexpr bsl::int32 digits{1};
        /// @brief stores the number of base 10 digits for T
        static constexpr bsl::int32 digits10{0};
        /// @brief stores the number of base 10 digits to diff T
        static constexpr bsl::int32 max_digits10{0};
        /// @brief stores the integer base that presents digits
        static constexpr bsl::int32 radix{2};
        /// @brief stores the smallest negative exponential number
        static constexpr bsl::int32 min_exponent{0};
        /// @brief stores the smallest negative exponential number in base 10
        static constexpr bsl::int32 min_exponent10{0};
        /// @brief stores the largest positive exponential number
        static constexpr bsl::int32 max_exponent{0};
        /// @brief stores the largest positive exponential number in base 10
        static constexpr bsl::int32 max_exponent10{0};
        /// @brief stores whether T can generate a trap
        static constexpr bool traps{false};
        /// @brief stores whether or T detected tinyness before rounding
        static constexpr bool tinyness_before{false};

        /// <!-- description -->
        ///   @brief Returns the min value of T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the min value of T
        ///
        [[nodiscard]] static constexpr auto
        min() noexcept -> bool
        {
            return false;
        }

        /// <!-- description -->
        ///   @brief Returns the lowest value of T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the lowest value of T
        ///
        [[nodiscard]] static constexpr auto
        lowest() noexcept -> bool
        {
            return false;
        }

        /// <!-- description -->
        ///   @brief Returns the max value of T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the max value of T
        ///
        [[nodiscard]] static constexpr auto
        max() noexcept -> bool
        {
            return true;
        }

        /// <!-- description -->
        ///   @brief Returns the floating point resolution
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the max value of T
        ///
        [[nodiscard]] static constexpr auto
        epsilon() noexcept -> bool
        {
            return false;
        }

        /// <!-- description -->
        ///   @brief Returns the rounding error of T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the rounding error of T
        ///
        [[nodiscard]] static constexpr auto
        round_error() noexcept -> bool
        {
            return false;
        }

        /// <!-- description -->
        ///   @brief Returns the value of infinity for T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of infinity for T
        ///
        [[nodiscard]] static constexpr auto
        infinity() noexcept -> bool
        {
            return false;
        }

        /// <!-- description -->
        ///   @brief Returns the quiet NaN value for T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the quiet NaN value for T
        ///
        [[nodiscard]] static constexpr auto
        // We want our implementation to mimic C++ here.
        // NOLINTNEXTLINE(bsl-name-case)
        quiet_NaN() noexcept -> bool
        {
            return false;
        }

        /// <!-- description -->
        ///   @brief Returns the signaling NaN value for T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the signaling NaN value for T
        ///
        [[nodiscard]] static constexpr auto
        // We want our implementation to mimic C++ here.
        // NOLINTNEXTLINE(bsl-name-case)
        signaling_NaN() noexcept -> bool
        {
            return false;
        }

        /// <!-- description -->
        ///   @brief Returns the smallest subnormal value for T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the smallest subnormal value for T
        ///
        [[nodiscard]] static constexpr auto
        denorm_min() noexcept -> bool
        {
            return false;
        }
    };

    /// @class bsl::numeric_limits
    ///
    /// <!-- description -->
    ///   @brief Implements std::numeric_limits
    ///   @include example_numeric_limits_overview.hpp
    ///
    template<>
    class numeric_limits<char_type> final
    {
    public:
        /// @brief stores whether or not this is a specialization
        static constexpr bool is_specialized{true};
        /// @brief stores whether or not T is exact
        static constexpr bool is_exact{true};
        /// @brief stores whether or not T has defined infinity
        static constexpr bool has_infinity{false};
        /// @brief stores whether or not T has a quiet NaN
        // We want our implementation to mimic C++ here.
        // NOLINTNEXTLINE(bsl-name-case)
        static constexpr bool has_quiet_NaN{false};
        /// @brief stores whether or not T has a signaling NaN
        // We want our implementation to mimic C++ here.
        // NOLINTNEXTLINE(bsl-name-case)
        static constexpr bool has_signaling_NaN{false};
        /// @brief stores the denorm style of T
        static constexpr float_denorm_style has_denorm{float_denorm_style::denorm_absent};
        /// @brief stores whether or not floating points detect loss
        static constexpr bool has_denorm_loss{false};
        /// @brief stores the rounding style of T
        static constexpr float_round_style round_style{float_round_style::round_toward_zero};
        /// @brief stores the type of floating point
        static constexpr bool is_iec559{false};
        /// @brief stores whether or not T is bounded
        static constexpr bool is_bounded{true};
        /// @brief stores whether or not T handles overflow with modulo
        static constexpr bool is_modulo{false};
        /// @brief stores the number of radix digits for T
        static constexpr bsl::int32 digits{details::get_digits<char_type>()};
        /// @brief stores the number of base 10 digits for T
        static constexpr bsl::int32 digits10{0};    // TODO... need to sort out the need for log10
        /// @brief stores the number of base 10 digits to diff T
        static constexpr bsl::int32 max_digits10{0};
        /// @brief stores the integer base that presents digits
        static constexpr bsl::int32 radix{2};
        /// @brief stores the smallest negative exponential number
        static constexpr bsl::int32 min_exponent{0};
        /// @brief stores the smallest negative exponential number in base 10
        static constexpr bsl::int32 min_exponent10{0};
        /// @brief stores the largest positive exponential number
        static constexpr bsl::int32 max_exponent{0};
        /// @brief stores the largest positive exponential number in base 10
        static constexpr bsl::int32 max_exponent10{0};
        /// @brief stores whether T can generate a trap
        static constexpr bool traps{false};
        /// @brief stores whether or T detected tinyness before rounding
        static constexpr bool tinyness_before{false};

        /// <!-- description -->
        ///   @brief Returns the min value of T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the min value of T
        ///
        [[nodiscard]] static constexpr auto
        min() noexcept -> char_type
        {
            return static_cast<char_type>(CHAR_MIN);
        }

        /// <!-- description -->
        ///   @brief Returns the lowest value of T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the lowest value of T
        ///
        [[nodiscard]] static constexpr auto
        lowest() noexcept -> char_type
        {
            return static_cast<char_type>(CHAR_MIN);
        }

        /// <!-- description -->
        ///   @brief Returns the max value of T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the max value of T
        ///
        [[nodiscard]] static constexpr auto
        max() noexcept -> char_type
        {
            return static_cast<char_type>(CHAR_MAX);
        }

        /// <!-- description -->
        ///   @brief Returns the floating point resolution
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the max value of T
        ///
        [[nodiscard]] static constexpr auto
        epsilon() noexcept -> char_type
        {
            return static_cast<char_type>(0);
        }

        /// <!-- description -->
        ///   @brief Returns the rounding error of T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the rounding error of T
        ///
        [[nodiscard]] static constexpr auto
        round_error() noexcept -> char_type
        {
            return static_cast<char_type>(0);
        }

        /// <!-- description -->
        ///   @brief Returns the value of infinity for T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of infinity for T
        ///
        [[nodiscard]] static constexpr auto
        infinity() noexcept -> char_type
        {
            return static_cast<char_type>(0);
        }

        /// <!-- description -->
        ///   @brief Returns the quiet NaN value for T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the quiet NaN value for T
        ///
        [[nodiscard]] static constexpr auto
        // We want our implementation to mimic C++ here.
        // NOLINTNEXTLINE(bsl-name-case)
        quiet_NaN() noexcept -> char_type
        {
            return static_cast<char_type>(0);
        }

        /// <!-- description -->
        ///   @brief Returns the signaling NaN value for T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the signaling NaN value for T
        ///
        [[nodiscard]] static constexpr auto
        // We want our implementation to mimic C++ here.
        // NOLINTNEXTLINE(bsl-name-case)
        signaling_NaN() noexcept -> char_type
        {
            return static_cast<char_type>(0);
        }

        /// <!-- description -->
        ///   @brief Returns the smallest subnormal value for T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the smallest subnormal value for T
        ///
        [[nodiscard]] static constexpr auto
        denorm_min() noexcept -> char_type
        {
            return static_cast<char_type>(0);
        }
    };

    /// @class bsl::numeric_limits
    ///
    /// <!-- description -->
    ///   @brief Implements std::numeric_limits
    ///   @include example_numeric_limits_overview.hpp
    ///
    template<>
    class numeric_limits<bsl::int8> final
    {
    public:
        /// @brief stores whether or not this is a specialization
        static constexpr bool is_specialized{true};
        /// @brief stores whether or not T is exact
        static constexpr bool is_exact{true};
        /// @brief stores whether or not T has defined infinity
        static constexpr bool has_infinity{false};
        /// @brief stores whether or not T has a quiet NaN
        // We want our implementation to mimic C++ here.
        // NOLINTNEXTLINE(bsl-name-case)
        static constexpr bool has_quiet_NaN{false};
        /// @brief stores whether or not T has a signaling NaN
        // We want our implementation to mimic C++ here.
        // NOLINTNEXTLINE(bsl-name-case)
        static constexpr bool has_signaling_NaN{false};
        /// @brief stores the denorm style of T
        static constexpr float_denorm_style has_denorm{float_denorm_style::denorm_absent};
        /// @brief stores whether or not floating points detect loss
        static constexpr bool has_denorm_loss{false};
        /// @brief stores the rounding style of T
        static constexpr float_round_style round_style{float_round_style::round_toward_zero};
        /// @brief stores the type of floating point
        static constexpr bool is_iec559{false};
        /// @brief stores whether or not T is bounded
        static constexpr bool is_bounded{true};
        /// @brief stores whether or not T handles overflow with modulo
        static constexpr bool is_modulo{false};
        /// @brief stores the number of radix digits for T
        static constexpr bsl::int32 digits{details::get_digits<bsl::int8>()};
        /// @brief stores the number of base 10 digits for T
        static constexpr bsl::int32 digits10{0};    // TODO... need to sort out the need for log10
        /// @brief stores the number of base 10 digits to diff T
        static constexpr bsl::int32 max_digits10{0};
        /// @brief stores the integer base that presents digits
        static constexpr bsl::int32 radix{2};
        /// @brief stores the smallest negative exponential number
        static constexpr bsl::int32 min_exponent{0};
        /// @brief stores the smallest negative exponential number in base 10
        static constexpr bsl::int32 min_exponent10{0};
        /// @brief stores the largest positive exponential number
        static constexpr bsl::int32 max_exponent{0};
        /// @brief stores the largest positive exponential number in base 10
        static constexpr bsl::int32 max_exponent10{0};
        /// @brief stores whether T can generate a trap
        static constexpr bool traps{false};
        /// @brief stores whether or T detected tinyness before rounding
        static constexpr bool tinyness_before{false};

        /// <!-- description -->
        ///   @brief Returns the min value of T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the min value of T
        ///
        [[nodiscard]] static constexpr auto
        min() noexcept -> bsl::int8
        {
            // The macro itself might perform an implicit conversion
            // NOLINTNEXTLINE(bsl-implicit-conversions-forbidden)
            return static_cast<bsl::int8>(INT8_MIN);
        }

        /// <!-- description -->
        ///   @brief Returns the lowest value of T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the lowest value of T
        ///
        [[nodiscard]] static constexpr auto
        lowest() noexcept -> bsl::int8
        {
            // The macro itself might perform an implicit conversion
            // NOLINTNEXTLINE(bsl-implicit-conversions-forbidden)
            return static_cast<bsl::int8>(INT8_MIN);
        }

        /// <!-- description -->
        ///   @brief Returns the max value of T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the max value of T
        ///
        [[nodiscard]] static constexpr auto
        max() noexcept -> bsl::int8
        {
            // The macro itself might perform an implicit conversion
            // NOLINTNEXTLINE(bsl-implicit-conversions-forbidden)
            return static_cast<bsl::int8>(INT8_MAX);
        }

        /// <!-- description -->
        ///   @brief Returns the floating point resolution
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the max value of T
        ///
        [[nodiscard]] static constexpr auto
        epsilon() noexcept -> bsl::int8
        {
            return static_cast<bsl::int8>(0);
        }

        /// <!-- description -->
        ///   @brief Returns the rounding error of T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the rounding error of T
        ///
        [[nodiscard]] static constexpr auto
        round_error() noexcept -> bsl::int8
        {
            return static_cast<bsl::int8>(0);
        }

        /// <!-- description -->
        ///   @brief Returns the value of infinity for T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of infinity for T
        ///
        [[nodiscard]] static constexpr auto
        infinity() noexcept -> bsl::int8
        {
            return static_cast<bsl::int8>(0);
        }

        /// <!-- description -->
        ///   @brief Returns the quiet NaN value for T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the quiet NaN value for T
        ///
        [[nodiscard]] static constexpr auto
        // We want our implementation to mimic C++ here.
        // NOLINTNEXTLINE(bsl-name-case)
        quiet_NaN() noexcept -> bsl::int8
        {
            return static_cast<bsl::int8>(0);
        }

        /// <!-- description -->
        ///   @brief Returns the signaling NaN value for T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the signaling NaN value for T
        ///
        [[nodiscard]] static constexpr auto
        // We want our implementation to mimic C++ here.
        // NOLINTNEXTLINE(bsl-name-case)
        signaling_NaN() noexcept -> bsl::int8
        {
            return static_cast<bsl::int8>(0);
        }

        /// <!-- description -->
        ///   @brief Returns the smallest subnormal value for T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the smallest subnormal value for T
        ///
        [[nodiscard]] static constexpr auto
        denorm_min() noexcept -> bsl::int8
        {
            return static_cast<bsl::int8>(0);
        }
    };

    /// @class bsl::numeric_limits
    ///
    /// <!-- description -->
    ///   @brief Implements std::numeric_limits
    ///   @include example_numeric_limits_overview.hpp
    ///
    template<>
    class numeric_limits<bsl::int16> final
    {
    public:
        /// @brief stores whether or not this is a specialization
        static constexpr bool is_specialized{true};
        /// @brief stores whether or not T is exact
        static constexpr bool is_exact{true};
        /// @brief stores whether or not T has defined infinity
        static constexpr bool has_infinity{false};
        /// @brief stores whether or not T has a quiet NaN
        // We want our implementation to mimic C++ here.
        // NOLINTNEXTLINE(bsl-name-case)
        static constexpr bool has_quiet_NaN{false};
        /// @brief stores whether or not T has a signaling NaN
        // We want our implementation to mimic C++ here.
        // NOLINTNEXTLINE(bsl-name-case)
        static constexpr bool has_signaling_NaN{false};
        /// @brief stores the denorm style of T
        static constexpr float_denorm_style has_denorm{float_denorm_style::denorm_absent};
        /// @brief stores whether or not floating points detect loss
        static constexpr bool has_denorm_loss{false};
        /// @brief stores the rounding style of T
        static constexpr float_round_style round_style{float_round_style::round_toward_zero};
        /// @brief stores the type of floating point
        static constexpr bool is_iec559{false};
        /// @brief stores whether or not T is bounded
        static constexpr bool is_bounded{true};
        /// @brief stores whether or not T handles overflow with modulo
        static constexpr bool is_modulo{false};
        /// @brief stores the number of radix digits for T
        static constexpr bsl::int32 digits{details::get_digits<bsl::int16>()};
        /// @brief stores the number of base 10 digits for T
        static constexpr bsl::int32 digits10{0};    // TODO... need to sort out the need for log10
        /// @brief stores the number of base 10 digits to diff T
        static constexpr bsl::int32 max_digits10{0};
        /// @brief stores the integer base that presents digits
        static constexpr bsl::int32 radix{2};
        /// @brief stores the smallest negative exponential number
        static constexpr bsl::int32 min_exponent{0};
        /// @brief stores the smallest negative exponential number in base 10
        static constexpr bsl::int32 min_exponent10{0};
        /// @brief stores the largest positive exponential number
        static constexpr bsl::int32 max_exponent{0};
        /// @brief stores the largest positive exponential number in base 10
        static constexpr bsl::int32 max_exponent10{0};
        /// @brief stores whether T can generate a trap
        static constexpr bool traps{false};
        /// @brief stores whether or T detected tinyness before rounding
        static constexpr bool tinyness_before{false};

        /// <!-- description -->
        ///   @brief Returns the min value of T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the min value of T
        ///
        [[nodiscard]] static constexpr auto
        min() noexcept -> bsl::int16
        {
            // The macro itself might perform an implicit conversion
            // NOLINTNEXTLINE(bsl-implicit-conversions-forbidden)
            return static_cast<bsl::int16>(INT16_MIN);
        }

        /// <!-- description -->
        ///   @brief Returns the lowest value of T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the lowest value of T
        ///
        [[nodiscard]] static constexpr auto
        lowest() noexcept -> bsl::int16
        {
            // The macro itself might perform an implicit conversion
            // NOLINTNEXTLINE(bsl-implicit-conversions-forbidden)
            return static_cast<bsl::int16>(INT16_MIN);
        }

        /// <!-- description -->
        ///   @brief Returns the max value of T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the max value of T
        ///
        [[nodiscard]] static constexpr auto
        max() noexcept -> bsl::int16
        {
            // The macro itself might perform an implicit conversion
            // NOLINTNEXTLINE(bsl-implicit-conversions-forbidden)
            return static_cast<bsl::int16>(INT16_MAX);
        }

        /// <!-- description -->
        ///   @brief Returns the floating point resolution
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the max value of T
        ///
        [[nodiscard]] static constexpr auto
        epsilon() noexcept -> bsl::int16
        {
            return static_cast<bsl::int16>(0);
        }

        /// <!-- description -->
        ///   @brief Returns the rounding error of T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the rounding error of T
        ///
        [[nodiscard]] static constexpr auto
        round_error() noexcept -> bsl::int16
        {
            return static_cast<bsl::int16>(0);
        }

        /// <!-- description -->
        ///   @brief Returns the value of infinity for T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of infinity for T
        ///
        [[nodiscard]] static constexpr auto
        infinity() noexcept -> bsl::int16
        {
            return static_cast<bsl::int16>(0);
        }

        /// <!-- description -->
        ///   @brief Returns the quiet NaN value for T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the quiet NaN value for T
        ///
        [[nodiscard]] static constexpr auto
        // We want our implementation to mimic C++ here.
        // NOLINTNEXTLINE(bsl-name-case)
        quiet_NaN() noexcept -> bsl::int16
        {
            return static_cast<bsl::int16>(0);
        }

        /// <!-- description -->
        ///   @brief Returns the signaling NaN value for T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the signaling NaN value for T
        ///
        [[nodiscard]] static constexpr auto
        // We want our implementation to mimic C++ here.
        // NOLINTNEXTLINE(bsl-name-case)
        signaling_NaN() noexcept -> bsl::int16
        {
            return static_cast<bsl::int16>(0);
        }

        /// <!-- description -->
        ///   @brief Returns the smallest subnormal value for T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the smallest subnormal value for T
        ///
        [[nodiscard]] static constexpr auto
        denorm_min() noexcept -> bsl::int16
        {
            return static_cast<bsl::int16>(0);
        }
    };

    /// @class bsl::numeric_limits
    ///
    /// <!-- description -->
    ///   @brief Implements std::numeric_limits
    ///   @include example_numeric_limits_overview.hpp
    ///
    template<>
    class numeric_limits<bsl::int32> final
    {
    public:
        /// @brief stores whether or not this is a specialization
        static constexpr bool is_specialized{true};
        /// @brief stores whether or not T is exact
        static constexpr bool is_exact{true};
        /// @brief stores whether or not T has defined infinity
        static constexpr bool has_infinity{false};
        /// @brief stores whether or not T has a quiet NaN
        // We want our implementation to mimic C++ here.
        // NOLINTNEXTLINE(bsl-name-case)
        static constexpr bool has_quiet_NaN{false};
        /// @brief stores whether or not T has a signaling NaN
        // We want our implementation to mimic C++ here.
        // NOLINTNEXTLINE(bsl-name-case)
        static constexpr bool has_signaling_NaN{false};
        /// @brief stores the denorm style of T
        static constexpr float_denorm_style has_denorm{float_denorm_style::denorm_absent};
        /// @brief stores whether or not floating points detect loss
        static constexpr bool has_denorm_loss{false};
        /// @brief stores the rounding style of T
        static constexpr float_round_style round_style{float_round_style::round_toward_zero};
        /// @brief stores the type of floating point
        static constexpr bool is_iec559{false};
        /// @brief stores whether or not T is bounded
        static constexpr bool is_bounded{true};
        /// @brief stores whether or not T handles overflow with modulo
        static constexpr bool is_modulo{false};
        /// @brief stores the number of radix digits for T
        static constexpr bsl::int32 digits{details::get_digits<bsl::int32>()};
        /// @brief stores the number of base 10 digits for T
        static constexpr bsl::int32 digits10{0};    // TODO... need to sort out the need for log10
        /// @brief stores the number of base 10 digits to diff T
        static constexpr bsl::int32 max_digits10{0};
        /// @brief stores the integer base that presents digits
        static constexpr bsl::int32 radix{2};
        /// @brief stores the smallest negative exponential number
        static constexpr bsl::int32 min_exponent{0};
        /// @brief stores the smallest negative exponential number in base 10
        static constexpr bsl::int32 min_exponent10{0};
        /// @brief stores the largest positive exponential number
        static constexpr bsl::int32 max_exponent{0};
        /// @brief stores the largest positive exponential number in base 10
        static constexpr bsl::int32 max_exponent10{0};
        /// @brief stores whether T can generate a trap
        static constexpr bool traps{false};
        /// @brief stores whether or T detected tinyness before rounding
        static constexpr bool tinyness_before{false};

        /// <!-- description -->
        ///   @brief Returns the min value of T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the min value of T
        ///
        [[nodiscard]] static constexpr auto
        min() noexcept -> bsl::int32
        {
            // The macro itself might perform an implicit conversion
            // NOLINTNEXTLINE(bsl-implicit-conversions-forbidden)
            return static_cast<bsl::int32>(INT32_MIN);
        }

        /// <!-- description -->
        ///   @brief Returns the lowest value of T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the lowest value of T
        ///
        [[nodiscard]] static constexpr auto
        lowest() noexcept -> bsl::int32
        {
            // The macro itself might perform an implicit conversion
            // NOLINTNEXTLINE(bsl-implicit-conversions-forbidden)
            return static_cast<bsl::int32>(INT32_MIN);
        }

        /// <!-- description -->
        ///   @brief Returns the max value of T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the max value of T
        ///
        [[nodiscard]] static constexpr auto
        max() noexcept -> bsl::int32
        {
            // The macro itself might perform an implicit conversion
            // NOLINTNEXTLINE(bsl-implicit-conversions-forbidden)
            return static_cast<bsl::int32>(INT32_MAX);
        }

        /// <!-- description -->
        ///   @brief Returns the floating point resolution
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the max value of T
        ///
        [[nodiscard]] static constexpr auto
        epsilon() noexcept -> bsl::int32
        {
            return static_cast<bsl::int32>(0);
        }

        /// <!-- description -->
        ///   @brief Returns the rounding error of T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the rounding error of T
        ///
        [[nodiscard]] static constexpr auto
        round_error() noexcept -> bsl::int32
        {
            return static_cast<bsl::int32>(0);
        }

        /// <!-- description -->
        ///   @brief Returns the value of infinity for T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of infinity for T
        ///
        [[nodiscard]] static constexpr auto
        infinity() noexcept -> bsl::int32
        {
            return static_cast<bsl::int32>(0);
        }

        /// <!-- description -->
        ///   @brief Returns the quiet NaN value for T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the quiet NaN value for T
        ///
        [[nodiscard]] static constexpr auto
        // We want our implementation to mimic C++ here.
        // NOLINTNEXTLINE(bsl-name-case)
        quiet_NaN() noexcept -> bsl::int32
        {
            return static_cast<bsl::int32>(0);
        }

        /// <!-- description -->
        ///   @brief Returns the signaling NaN value for T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the signaling NaN value for T
        ///
        [[nodiscard]] static constexpr auto
        // We want our implementation to mimic C++ here.
        // NOLINTNEXTLINE(bsl-name-case)
        signaling_NaN() noexcept -> bsl::int32
        {
            return static_cast<bsl::int32>(0);
        }

        /// <!-- description -->
        ///   @brief Returns the smallest subnormal value for T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the smallest subnormal value for T
        ///
        [[nodiscard]] static constexpr auto
        denorm_min() noexcept -> bsl::int32
        {
            return static_cast<bsl::int32>(0);
        }
    };

    /// @class bsl::numeric_limits
    ///
    /// <!-- description -->
    ///   @brief Implements std::numeric_limits
    ///   @include example_numeric_limits_overview.hpp
    ///
    template<>
    class numeric_limits<bsl::int64> final
    {
    public:
        /// @brief stores whether or not this is a specialization
        static constexpr bool is_specialized{true};
        /// @brief stores whether or not T is exact
        static constexpr bool is_exact{true};
        /// @brief stores whether or not T has defined infinity
        static constexpr bool has_infinity{false};
        /// @brief stores whether or not T has a quiet NaN
        // We want our implementation to mimic C++ here.
        // NOLINTNEXTLINE(bsl-name-case)
        static constexpr bool has_quiet_NaN{false};
        /// @brief stores whether or not T has a signaling NaN
        // We want our implementation to mimic C++ here.
        // NOLINTNEXTLINE(bsl-name-case)
        static constexpr bool has_signaling_NaN{false};
        /// @brief stores the denorm style of T
        static constexpr float_denorm_style has_denorm{float_denorm_style::denorm_absent};
        /// @brief stores whether or not floating points detect loss
        static constexpr bool has_denorm_loss{false};
        /// @brief stores the rounding style of T
        static constexpr float_round_style round_style{float_round_style::round_toward_zero};
        /// @brief stores the type of floating point
        static constexpr bool is_iec559{false};
        /// @brief stores whether or not T is bounded
        static constexpr bool is_bounded{true};
        /// @brief stores whether or not T handles overflow with modulo
        static constexpr bool is_modulo{false};
        /// @brief stores the number of radix digits for T
        static constexpr bsl::int32 digits{details::get_digits<bsl::int64>()};
        /// @brief stores the number of base 10 digits for T
        static constexpr bsl::int32 digits10{0};    // TODO... need to sort out the need for log10
        /// @brief stores the number of base 10 digits to diff T
        static constexpr bsl::int32 max_digits10{0};
        /// @brief stores the integer base that presents digits
        static constexpr bsl::int32 radix{2};
        /// @brief stores the smallest negative exponential number
        static constexpr bsl::int32 min_exponent{0};
        /// @brief stores the smallest negative exponential number in base 10
        static constexpr bsl::int32 min_exponent10{0};
        /// @brief stores the largest positive exponential number
        static constexpr bsl::int32 max_exponent{0};
        /// @brief stores the largest positive exponential number in base 10
        static constexpr bsl::int32 max_exponent10{0};
        /// @brief stores whether T can generate a trap
        static constexpr bool traps{false};
        /// @brief stores whether or T detected tinyness before rounding
        static constexpr bool tinyness_before{false};

        /// <!-- description -->
        ///   @brief Returns the min value of T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the min value of T
        ///
        [[nodiscard]] static constexpr auto
        min() noexcept -> bsl::int64
        {
            // The macro itself might perform an implicit conversion
            // NOLINTNEXTLINE(bsl-implicit-conversions-forbidden)
            return static_cast<bsl::int64>(INT64_MIN);
        }

        /// <!-- description -->
        ///   @brief Returns the lowest value of T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the lowest value of T
        ///
        [[nodiscard]] static constexpr auto
        lowest() noexcept -> bsl::int64
        {
            // The macro itself might perform an implicit conversion
            // NOLINTNEXTLINE(bsl-implicit-conversions-forbidden)
            return static_cast<bsl::int64>(INT64_MIN);
        }

        /// <!-- description -->
        ///   @brief Returns the max value of T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the max value of T
        ///
        [[nodiscard]] static constexpr auto
        max() noexcept -> bsl::int64
        {
            // The macro itself might perform an implicit conversion
            // NOLINTNEXTLINE(bsl-implicit-conversions-forbidden)
            return static_cast<bsl::int64>(INT64_MAX);
        }

        /// <!-- description -->
        ///   @brief Returns the floating point resolution
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the max value of T
        ///
        [[nodiscard]] static constexpr auto
        epsilon() noexcept -> bsl::int64
        {
            return static_cast<bsl::int64>(0);
        }

        /// <!-- description -->
        ///   @brief Returns the rounding error of T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the rounding error of T
        ///
        [[nodiscard]] static constexpr auto
        round_error() noexcept -> bsl::int64
        {
            return static_cast<bsl::int64>(0);
        }

        /// <!-- description -->
        ///   @brief Returns the value of infinity for T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of infinity for T
        ///
        [[nodiscard]] static constexpr auto
        infinity() noexcept -> bsl::int64
        {
            return static_cast<bsl::int64>(0);
        }

        /// <!-- description -->
        ///   @brief Returns the quiet NaN value for T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the quiet NaN value for T
        ///
        [[nodiscard]] static constexpr auto
        // We want our implementation to mimic C++ here.
        // NOLINTNEXTLINE(bsl-name-case)
        quiet_NaN() noexcept -> bsl::int64
        {
            return static_cast<bsl::int64>(0);
        }

        /// <!-- description -->
        ///   @brief Returns the signaling NaN value for T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the signaling NaN value for T
        ///
        [[nodiscard]] static constexpr auto
        // We want our implementation to mimic C++ here.
        // NOLINTNEXTLINE(bsl-name-case)
        signaling_NaN() noexcept -> bsl::int64
        {
            return static_cast<bsl::int64>(0);
        }

        /// <!-- description -->
        ///   @brief Returns the smallest subnormal value for T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the smallest subnormal value for T
        ///
        [[nodiscard]] static constexpr auto
        denorm_min() noexcept -> bsl::int64
        {
            return static_cast<bsl::int64>(0);
        }
    };

    /// @class bsl::numeric_limits
    ///
    /// <!-- description -->
    ///   @brief Implements std::numeric_limits
    ///   @include example_numeric_limits_overview.hpp
    ///
    template<>
    class numeric_limits<bsl::uint8> final
    {
    public:
        /// @brief stores whether or not this is a specialization
        static constexpr bool is_specialized{true};
        /// @brief stores whether or not T is exact
        static constexpr bool is_exact{true};
        /// @brief stores whether or not T has defined infinity
        static constexpr bool has_infinity{false};
        /// @brief stores whether or not T has a quiet NaN
        // We want our implementation to mimic C++ here.
        // NOLINTNEXTLINE(bsl-name-case)
        static constexpr bool has_quiet_NaN{false};
        /// @brief stores whether or not T has a signaling NaN
        // We want our implementation to mimic C++ here.
        // NOLINTNEXTLINE(bsl-name-case)
        static constexpr bool has_signaling_NaN{false};
        /// @brief stores the denorm style of T
        static constexpr float_denorm_style has_denorm{float_denorm_style::denorm_absent};
        /// @brief stores whether or not floating points detect loss
        static constexpr bool has_denorm_loss{false};
        /// @brief stores the rounding style of T
        static constexpr float_round_style round_style{float_round_style::round_toward_zero};
        /// @brief stores the type of floating point
        static constexpr bool is_iec559{false};
        /// @brief stores whether or not T is bounded
        static constexpr bool is_bounded{true};
        /// @brief stores whether or not T handles overflow with modulo
        static constexpr bool is_modulo{true};
        /// @brief stores the number of radix digits for T
        static constexpr bsl::int32 digits{details::get_digits<bsl::uint8>()};
        /// @brief stores the number of base 10 digits for T
        static constexpr bsl::int32 digits10{0};    // TODO... need to sort out the need for log10
        /// @brief stores the number of base 10 digits to diff T
        static constexpr bsl::int32 max_digits10{0};
        /// @brief stores the integer base that presents digits
        static constexpr bsl::int32 radix{2};
        /// @brief stores the smallest negative exponential number
        static constexpr bsl::int32 min_exponent{0};
        /// @brief stores the smallest negative exponential number in base 10
        static constexpr bsl::int32 min_exponent10{0};
        /// @brief stores the largest positive exponential number
        static constexpr bsl::int32 max_exponent{0};
        /// @brief stores the largest positive exponential number in base 10
        static constexpr bsl::int32 max_exponent10{0};
        /// @brief stores whether T can generate a trap
        static constexpr bool traps{false};
        /// @brief stores whether or T detected tinyness before rounding
        static constexpr bool tinyness_before{false};

        /// <!-- description -->
        ///   @brief Returns the min value of T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the min value of T
        ///
        [[nodiscard]] static constexpr auto
        min() noexcept -> bsl::uint8
        {
            return static_cast<bsl::uint8>(0);
        }

        /// <!-- description -->
        ///   @brief Returns the lowest value of T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the lowest value of T
        ///
        [[nodiscard]] static constexpr auto
        lowest() noexcept -> bsl::uint8
        {
            return static_cast<bsl::uint8>(0);
        }

        /// <!-- description -->
        ///   @brief Returns the max value of T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the max value of T
        ///
        [[nodiscard]] static constexpr auto
        max() noexcept -> bsl::uint8
        {
            return static_cast<bsl::uint8>(UINT8_MAX);
        }

        /// <!-- description -->
        ///   @brief Returns the floating point resolution
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the max value of T
        ///
        [[nodiscard]] static constexpr auto
        epsilon() noexcept -> bsl::uint8
        {
            return static_cast<bsl::uint8>(0);
        }

        /// <!-- description -->
        ///   @brief Returns the rounding error of T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the rounding error of T
        ///
        [[nodiscard]] static constexpr auto
        round_error() noexcept -> bsl::uint8
        {
            return static_cast<bsl::uint8>(0);
        }

        /// <!-- description -->
        ///   @brief Returns the value of infinity for T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of infinity for T
        ///
        [[nodiscard]] static constexpr auto
        infinity() noexcept -> bsl::uint8
        {
            return static_cast<bsl::uint8>(0);
        }

        /// <!-- description -->
        ///   @brief Returns the quiet NaN value for T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the quiet NaN value for T
        ///
        [[nodiscard]] static constexpr auto
        // We want our implementation to mimic C++ here.
        // NOLINTNEXTLINE(bsl-name-case)
        quiet_NaN() noexcept -> bsl::uint8
        {
            return static_cast<bsl::uint8>(0);
        }

        /// <!-- description -->
        ///   @brief Returns the signaling NaN value for T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the signaling NaN value for T
        ///
        [[nodiscard]] static constexpr auto
        // We want our implementation to mimic C++ here.
        // NOLINTNEXTLINE(bsl-name-case)
        signaling_NaN() noexcept -> bsl::uint8
        {
            return static_cast<bsl::uint8>(0);
        }

        /// <!-- description -->
        ///   @brief Returns the smallest subnormal value for T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the smallest subnormal value for T
        ///
        [[nodiscard]] static constexpr auto
        denorm_min() noexcept -> bsl::uint8
        {
            return static_cast<bsl::uint8>(0);
        }
    };

    /// @class bsl::numeric_limits
    ///
    /// <!-- description -->
    ///   @brief Implements std::numeric_limits
    ///   @include example_numeric_limits_overview.hpp
    ///
    template<>
    class numeric_limits<bsl::uint16> final
    {
    public:
        /// @brief stores whether or not this is a specialization
        static constexpr bool is_specialized{true};
        /// @brief stores whether or not T is exact
        static constexpr bool is_exact{true};
        /// @brief stores whether or not T has defined infinity
        static constexpr bool has_infinity{false};
        /// @brief stores whether or not T has a quiet NaN
        // We want our implementation to mimic C++ here.
        // NOLINTNEXTLINE(bsl-name-case)
        static constexpr bool has_quiet_NaN{false};
        /// @brief stores whether or not T has a signaling NaN
        // We want our implementation to mimic C++ here.
        // NOLINTNEXTLINE(bsl-name-case)
        static constexpr bool has_signaling_NaN{false};
        /// @brief stores the denorm style of T
        static constexpr float_denorm_style has_denorm{float_denorm_style::denorm_absent};
        /// @brief stores whether or not floating points detect loss
        static constexpr bool has_denorm_loss{false};
        /// @brief stores the rounding style of T
        static constexpr float_round_style round_style{float_round_style::round_toward_zero};
        /// @brief stores the type of floating point
        static constexpr bool is_iec559{false};
        /// @brief stores whether or not T is bounded
        static constexpr bool is_bounded{true};
        /// @brief stores whether or not T handles overflow with modulo
        static constexpr bool is_modulo{true};
        /// @brief stores the number of radix digits for T
        static constexpr bsl::int32 digits{details::get_digits<bsl::uint16>()};
        /// @brief stores the number of base 10 digits for T
        static constexpr bsl::int32 digits10{0};    // TODO... need to sort out the need for log10
        /// @brief stores the number of base 10 digits to diff T
        static constexpr bsl::int32 max_digits10{0};
        /// @brief stores the integer base that presents digits
        static constexpr bsl::int32 radix{2};
        /// @brief stores the smallest negative exponential number
        static constexpr bsl::int32 min_exponent{0};
        /// @brief stores the smallest negative exponential number in base 10
        static constexpr bsl::int32 min_exponent10{0};
        /// @brief stores the largest positive exponential number
        static constexpr bsl::int32 max_exponent{0};
        /// @brief stores the largest positive exponential number in base 10
        static constexpr bsl::int32 max_exponent10{0};
        /// @brief stores whether T can generate a trap
        static constexpr bool traps{false};
        /// @brief stores whether or T detected tinyness before rounding
        static constexpr bool tinyness_before{false};

        /// <!-- description -->
        ///   @brief Returns the min value of T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the min value of T
        ///
        [[nodiscard]] static constexpr auto
        min() noexcept -> bsl::uint16
        {
            return static_cast<bsl::uint16>(0);
        }

        /// <!-- description -->
        ///   @brief Returns the lowest value of T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the lowest value of T
        ///
        [[nodiscard]] static constexpr auto
        lowest() noexcept -> bsl::uint16
        {
            return static_cast<bsl::uint16>(0);
        }

        /// <!-- description -->
        ///   @brief Returns the max value of T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the max value of T
        ///
        [[nodiscard]] static constexpr auto
        max() noexcept -> bsl::uint16
        {
            return static_cast<bsl::uint16>(UINT16_MAX);
        }

        /// <!-- description -->
        ///   @brief Returns the floating point resolution
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the max value of T
        ///
        [[nodiscard]] static constexpr auto
        epsilon() noexcept -> bsl::uint16
        {
            return static_cast<bsl::uint16>(0);
        }

        /// <!-- description -->
        ///   @brief Returns the rounding error of T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the rounding error of T
        ///
        [[nodiscard]] static constexpr auto
        round_error() noexcept -> bsl::uint16
        {
            return static_cast<bsl::uint16>(0);
        }

        /// <!-- description -->
        ///   @brief Returns the value of infinity for T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of infinity for T
        ///
        [[nodiscard]] static constexpr auto
        infinity() noexcept -> bsl::uint16
        {
            return static_cast<bsl::uint16>(0);
        }

        /// <!-- description -->
        ///   @brief Returns the quiet NaN value for T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the quiet NaN value for T
        ///
        [[nodiscard]] static constexpr auto
        // We want our implementation to mimic C++ here.
        // NOLINTNEXTLINE(bsl-name-case)
        quiet_NaN() noexcept -> bsl::uint16
        {
            return static_cast<bsl::uint16>(0);
        }

        /// <!-- description -->
        ///   @brief Returns the signaling NaN value for T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the signaling NaN value for T
        ///
        [[nodiscard]] static constexpr auto
        // We want our implementation to mimic C++ here.
        // NOLINTNEXTLINE(bsl-name-case)
        signaling_NaN() noexcept -> bsl::uint16
        {
            return static_cast<bsl::uint16>(0);
        }

        /// <!-- description -->
        ///   @brief Returns the smallest subnormal value for T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the smallest subnormal value for T
        ///
        [[nodiscard]] static constexpr auto
        denorm_min() noexcept -> bsl::uint16
        {
            return static_cast<bsl::uint16>(0);
        }
    };

    /// @class bsl::numeric_limits
    ///
    /// <!-- description -->
    ///   @brief Implements std::numeric_limits
    ///   @include example_numeric_limits_overview.hpp
    ///
    template<>
    class numeric_limits<bsl::uint32> final
    {
    public:
        /// @brief stores whether or not this is a specialization
        static constexpr bool is_specialized{true};
        /// @brief stores whether or not T is exact
        static constexpr bool is_exact{true};
        /// @brief stores whether or not T has defined infinity
        static constexpr bool has_infinity{false};
        /// @brief stores whether or not T has a quiet NaN
        // We want our implementation to mimic C++ here.
        // NOLINTNEXTLINE(bsl-name-case)
        static constexpr bool has_quiet_NaN{false};
        /// @brief stores whether or not T has a signaling NaN
        // We want our implementation to mimic C++ here.
        // NOLINTNEXTLINE(bsl-name-case)
        static constexpr bool has_signaling_NaN{false};
        /// @brief stores the denorm style of T
        static constexpr float_denorm_style has_denorm{float_denorm_style::denorm_absent};
        /// @brief stores whether or not floating points detect loss
        static constexpr bool has_denorm_loss{false};
        /// @brief stores the rounding style of T
        static constexpr float_round_style round_style{float_round_style::round_toward_zero};
        /// @brief stores the type of floating point
        static constexpr bool is_iec559{false};
        /// @brief stores whether or not T is bounded
        static constexpr bool is_bounded{true};
        /// @brief stores whether or not T handles overflow with modulo
        static constexpr bool is_modulo{true};
        /// @brief stores the number of radix digits for T
        static constexpr bsl::int32 digits{details::get_digits<bsl::uint32>()};
        /// @brief stores the number of base 10 digits for T
        static constexpr bsl::int32 digits10{0};    // TODO... need to sort out the need for log10
        /// @brief stores the number of base 10 digits to diff T
        static constexpr bsl::int32 max_digits10{0};
        /// @brief stores the integer base that presents digits
        static constexpr bsl::int32 radix{2};
        /// @brief stores the smallest negative exponential number
        static constexpr bsl::int32 min_exponent{0};
        /// @brief stores the smallest negative exponential number in base 10
        static constexpr bsl::int32 min_exponent10{0};
        /// @brief stores the largest positive exponential number
        static constexpr bsl::int32 max_exponent{0};
        /// @brief stores the largest positive exponential number in base 10
        static constexpr bsl::int32 max_exponent10{0};
        /// @brief stores whether T can generate a trap
        static constexpr bool traps{false};
        /// @brief stores whether or T detected tinyness before rounding
        static constexpr bool tinyness_before{false};

        /// <!-- description -->
        ///   @brief Returns the min value of T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the min value of T
        ///
        [[nodiscard]] static constexpr auto
        min() noexcept -> bsl::uint32
        {
            return static_cast<bsl::uint32>(0);
        }

        /// <!-- description -->
        ///   @brief Returns the lowest value of T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the lowest value of T
        ///
        [[nodiscard]] static constexpr auto
        lowest() noexcept -> bsl::uint32
        {
            return static_cast<bsl::uint32>(0);
        }

        /// <!-- description -->
        ///   @brief Returns the max value of T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the max value of T
        ///
        [[nodiscard]] static constexpr auto
        max() noexcept -> bsl::uint32
        {
            return UINT32_MAX;
        }

        /// <!-- description -->
        ///   @brief Returns the floating point resolution
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the max value of T
        ///
        [[nodiscard]] static constexpr auto
        epsilon() noexcept -> bsl::uint32
        {
            return static_cast<bsl::uint32>(0);
        }

        /// <!-- description -->
        ///   @brief Returns the rounding error of T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the rounding error of T
        ///
        [[nodiscard]] static constexpr auto
        round_error() noexcept -> bsl::uint32
        {
            return static_cast<bsl::uint32>(0);
        }

        /// <!-- description -->
        ///   @brief Returns the value of infinity for T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of infinity for T
        ///
        [[nodiscard]] static constexpr auto
        infinity() noexcept -> bsl::uint32
        {
            return static_cast<bsl::uint32>(0);
        }

        /// <!-- description -->
        ///   @brief Returns the quiet NaN value for T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the quiet NaN value for T
        ///
        [[nodiscard]] static constexpr auto
        // We want our implementation to mimic C++ here.
        // NOLINTNEXTLINE(bsl-name-case)
        quiet_NaN() noexcept -> bsl::uint32
        {
            return static_cast<bsl::uint32>(0);
        }

        /// <!-- description -->
        ///   @brief Returns the signaling NaN value for T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the signaling NaN value for T
        ///
        [[nodiscard]] static constexpr auto
        // We want our implementation to mimic C++ here.
        // NOLINTNEXTLINE(bsl-name-case)
        signaling_NaN() noexcept -> bsl::uint32
        {
            return static_cast<bsl::uint32>(0);
        }

        /// <!-- description -->
        ///   @brief Returns the smallest subnormal value for T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the smallest subnormal value for T
        ///
        [[nodiscard]] static constexpr auto
        denorm_min() noexcept -> bsl::uint32
        {
            return static_cast<bsl::uint32>(0);
        }
    };

    /// @class bsl::numeric_limits
    ///
    /// <!-- description -->
    ///   @brief Implements std::numeric_limits
    ///   @include example_numeric_limits_overview.hpp
    ///
    template<>
    class numeric_limits<bsl::uint64> final
    {
    public:
        /// @brief stores whether or not this is a specialization
        static constexpr bool is_specialized{true};
        /// @brief stores whether or not T is exact
        static constexpr bool is_exact{true};
        /// @brief stores whether or not T has defined infinity
        static constexpr bool has_infinity{false};
        /// @brief stores whether or not T has a quiet NaN
        // We want our implementation to mimic C++ here.
        // NOLINTNEXTLINE(bsl-name-case)
        static constexpr bool has_quiet_NaN{false};
        /// @brief stores whether or not T has a signaling NaN
        // We want our implementation to mimic C++ here.
        // NOLINTNEXTLINE(bsl-name-case)
        static constexpr bool has_signaling_NaN{false};
        /// @brief stores the denorm style of T
        static constexpr float_denorm_style has_denorm{float_denorm_style::denorm_absent};
        /// @brief stores whether or not floating points detect loss
        static constexpr bool has_denorm_loss{false};
        /// @brief stores the rounding style of T
        static constexpr float_round_style round_style{float_round_style::round_toward_zero};
        /// @brief stores the type of floating point
        static constexpr bool is_iec559{false};
        /// @brief stores whether or not T is bounded
        static constexpr bool is_bounded{true};
        /// @brief stores whether or not T handles overflow with modulo
        static constexpr bool is_modulo{true};
        /// @brief stores the number of radix digits for T
        static constexpr bsl::int32 digits{details::get_digits<bsl::uint64>()};
        /// @brief stores the number of base 10 digits for T
        static constexpr bsl::int32 digits10{0};    // TODO... need to sort out the need for log10
        /// @brief stores the number of base 10 digits to diff T
        static constexpr bsl::int32 max_digits10{0};
        /// @brief stores the integer base that presents digits
        static constexpr bsl::int32 radix{2};
        /// @brief stores the smallest negative exponential number
        static constexpr bsl::int32 min_exponent{0};
        /// @brief stores the smallest negative exponential number in base 10
        static constexpr bsl::int32 min_exponent10{0};
        /// @brief stores the largest positive exponential number
        static constexpr bsl::int32 max_exponent{0};
        /// @brief stores the largest positive exponential number in base 10
        static constexpr bsl::int32 max_exponent10{0};
        /// @brief stores whether T can generate a trap
        static constexpr bool traps{false};
        /// @brief stores whether or T detected tinyness before rounding
        static constexpr bool tinyness_before{false};

        /// <!-- description -->
        ///   @brief Returns the min value of T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the min value of T
        ///
        [[nodiscard]] static constexpr auto
        min() noexcept -> bsl::uint64
        {
            return static_cast<bsl::uint64>(0);
        }

        /// <!-- description -->
        ///   @brief Returns the lowest value of T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the lowest value of T
        ///
        [[nodiscard]] static constexpr auto
        lowest() noexcept -> bsl::uint64
        {
            return static_cast<bsl::uint64>(0);
        }

        /// <!-- description -->
        ///   @brief Returns the max value of T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the max value of T
        ///
        [[nodiscard]] static constexpr auto
        max() noexcept -> bsl::uint64
        {
            return UINT64_MAX;
        }

        /// <!-- description -->
        ///   @brief Returns the floating point resolution
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the max value of T
        ///
        [[nodiscard]] static constexpr auto
        epsilon() noexcept -> bsl::uint64
        {
            return static_cast<bsl::uint64>(0);
        }

        /// <!-- description -->
        ///   @brief Returns the rounding error of T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the rounding error of T
        ///
        [[nodiscard]] static constexpr auto
        round_error() noexcept -> bsl::uint64
        {
            return static_cast<bsl::uint64>(0);
        }

        /// <!-- description -->
        ///   @brief Returns the value of infinity for T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of infinity for T
        ///
        [[nodiscard]] static constexpr auto
        infinity() noexcept -> bsl::uint64
        {
            return static_cast<bsl::uint64>(0);
        }

        /// <!-- description -->
        ///   @brief Returns the quiet NaN value for T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the quiet NaN value for T
        ///
        [[nodiscard]] static constexpr auto
        // We want our implementation to mimic C++ here.
        // NOLINTNEXTLINE(bsl-name-case)
        quiet_NaN() noexcept -> bsl::uint64
        {
            return static_cast<bsl::uint64>(0);
        }

        /// <!-- description -->
        ///   @brief Returns the signaling NaN value for T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the signaling NaN value for T
        ///
        [[nodiscard]] static constexpr auto
        // We want our implementation to mimic C++ here.
        // NOLINTNEXTLINE(bsl-name-case)
        signaling_NaN() noexcept -> bsl::uint64
        {
            return static_cast<bsl::uint64>(0);
        }

        /// <!-- description -->
        ///   @brief Returns the smallest subnormal value for T
        ///   @include example_numeric_limits_overview.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the smallest subnormal value for T
        ///
        [[nodiscard]] static constexpr auto
        denorm_min() noexcept -> bsl::uint64
        {
            return static_cast<bsl::uint64>(0);
        }
    };

    /// @endcond doxygen on
}

#endif
