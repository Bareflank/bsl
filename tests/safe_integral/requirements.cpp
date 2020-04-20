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

#include <bsl/safe_integral.hpp>
#include <bsl/is_pod.hpp>
#include <bsl/ut.hpp>

namespace
{
    bsl::safe_int32 pod;

    class fixture_t final
    {
        bsl::safe_int32 val1{};
        bsl::safe_int32 val2{};

    public:
        [[nodiscard]] constexpr bool
        test_member_const() const
        {
            bsl::discard(val1.get());
            bsl::discard(!!val1);
            bsl::discard(val1.failure());
            bsl::discard(val1.max());
            bsl::discard(val1.max(val2));
            bsl::discard(val1.max(42));
            bsl::discard(val1.min());
            bsl::discard(val1.min(val2));
            bsl::discard(val1.min(42));
            bsl::discard(val1.is_signed_type());
            bsl::discard(val1.is_unsigned_type());

            return true;
        }

        [[nodiscard]] constexpr bool
        test_member_nonconst()
        {
            bsl::discard(val1 = 42);
            bsl::discard(val1.get());
            bsl::discard(!!val1);
            bsl::discard(val1.failure());
            bsl::discard(val1.max());
            bsl::discard(val1.max(val2));
            bsl::discard(val1.max(42));
            bsl::discard(val1.min());
            bsl::discard(val1.min(val2));
            bsl::discard(val1.min(42));
            bsl::discard(val1.is_signed_type());
            bsl::discard(val1.is_unsigned_type());
            bsl::discard(val1 += val2);
            bsl::discard(val1 += 42);
            bsl::discard(val1 -= val2);
            bsl::discard(val1 -= 42);
            bsl::discard(val1 *= val2);
            bsl::discard(val1 *= 42);
            bsl::discard(val1 /= val2);
            bsl::discard(val1 /= 42);
            bsl::discard(val1 %= val2);
            bsl::discard(val1 %= 42);
            bsl::discard(++val1);
            bsl::discard(--val1);

            return true;
        }
    };

    constexpr fixture_t fixture1{};
}

/// <!-- description -->
///   @brief Main function for this unit test. If a call to ut_check() fails
///     the application will fast fail. If all calls to ut_check() pass, this
///     function will successfully return with bsl::exit_success.
///
/// <!-- inputs/outputs -->
///   @return Always returns bsl::exit_success.
///
bsl::exit_code
main() noexcept
{
    using namespace bsl;

    bsl::ut_scenario{"verify supports global POD"} = []() {
        bsl::discard(pod);
        static_assert(is_pod<decltype(pod)>::value);
    };

    bsl::ut_scenario{"verify noexcept"} = []() {
        bsl::ut_given{} = []() {
            bsl::safe_int32 val1{42};
            bsl::safe_int32 val2{42};
            bsl::safe_uint32 val3{42U};
            bsl::safe_uint32 val4{42U};
            bsl::ut_then{} = []() {
                static_assert(noexcept(bsl::safe_int32{}));
                static_assert(noexcept(bsl::safe_int32{42}));
                static_assert(noexcept(bsl::safe_int32{42, true}));
                static_assert(noexcept(val1 = 42));
                static_assert(noexcept(val1.get()));
                static_assert(noexcept(!!val1));
                static_assert(noexcept(val1.failure()));
                static_assert(noexcept(val1.max()));
                static_assert(noexcept(val1.max(val2)));
                static_assert(noexcept(val1.max(42)));
                static_assert(noexcept(val1.min()));
                static_assert(noexcept(val1.min(val2)));
                static_assert(noexcept(val1.min(42)));
                static_assert(noexcept(val1.is_signed_type()));
                static_assert(noexcept(val1.is_unsigned_type()));
                static_assert(noexcept(val1 += val2));
                static_assert(noexcept(val1 += 42));
                static_assert(noexcept(val1 -= val2));
                static_assert(noexcept(val1 -= 42));
                static_assert(noexcept(val1 *= val2));
                static_assert(noexcept(val1 *= 42));
                static_assert(noexcept(val1 /= val2));
                static_assert(noexcept(val1 /= 42));
                static_assert(noexcept(val1 %= val2));
                static_assert(noexcept(val1 %= 42));
                static_assert(noexcept(++val1));
                static_assert(noexcept(--val1));
                static_assert(noexcept(val1 == val2));
                static_assert(noexcept(val1 == 42));
                static_assert(noexcept(42 == val1));
                static_assert(noexcept(val1 != val2));
                static_assert(noexcept(val1 != 42));
                static_assert(noexcept(42 != val1));
                static_assert(noexcept(val1 < val2));
                static_assert(noexcept(val1 < 42));
                static_assert(noexcept(42 < val1));
                static_assert(noexcept(val1 <= val2));
                static_assert(noexcept(val1 <= 42));
                static_assert(noexcept(42 <= val1));
                static_assert(noexcept(val1 > val2));
                static_assert(noexcept(val1 > 42));
                static_assert(noexcept(42 > val1));
                static_assert(noexcept(val1 >= val2));
                static_assert(noexcept(val1 >= 42));
                static_assert(noexcept(42 >= val1));
                static_assert(noexcept(val1 + val2));
                static_assert(noexcept(val1 + 42));
                static_assert(noexcept(42 + val1));
                static_assert(noexcept(val1 - val2));
                static_assert(noexcept(val1 - 42));
                static_assert(noexcept(42 - val1));
                static_assert(noexcept(val1 * val2));
                static_assert(noexcept(val1 * 42));
                static_assert(noexcept(42 * val1));
                static_assert(noexcept(val1 / val2));
                static_assert(noexcept(val1 / 42));
                static_assert(noexcept(42 / val1));
                static_assert(noexcept(val1 % val2));
                static_assert(noexcept(val1 % 42));
                static_assert(noexcept(42 % val1));
                static_assert(noexcept(val3 <<= 42U));
                static_assert(noexcept(val3 << 42U));
                static_assert(noexcept(val3 >>= 42U));
                static_assert(noexcept(val3 >> 42U));
                static_assert(noexcept(val3 &= val4));
                static_assert(noexcept(val3 &= 42U));
                static_assert(noexcept(val3 & val4));
                static_assert(noexcept(val3 & 42U));
                static_assert(noexcept(42U & val3));
                static_assert(noexcept(val3 |= val4));
                static_assert(noexcept(val3 |= 42U));
                static_assert(noexcept(val3 | val4));
                static_assert(noexcept(val3 | 42U));
                static_assert(noexcept(42U | val3));
                static_assert(noexcept(val3 ^= val4));
                static_assert(noexcept(val3 ^= 42U));
                static_assert(noexcept(val3 ^ val4));
                static_assert(noexcept(val3 ^ 42U));
                static_assert(noexcept(42U ^ val3));
                static_assert(noexcept(~val3));
                static_assert(noexcept(-val1));
            };
        };
    };

    bsl::ut_scenario{"verify constness"} = []() {
        bsl::ut_given{} = []() {
            fixture_t fixture2{};
            bsl::ut_then{} = [&fixture2]() {
                static_assert(fixture1.test_member_const());
                ut_check(fixture2.test_member_nonconst());
            };
        };
    };

    return bsl::ut_success();
}
