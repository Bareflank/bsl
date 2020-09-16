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

#include <bsl/arguments.hpp>
#include <bsl/convert.hpp>
#include <bsl/discard.hpp>
#include <bsl/ut.hpp>

namespace
{
    // Needed for requirements testing
    // NOLINTNEXTLINE(bsl-user-defined-type-names-match-header-name)
    class fixture_t final
    {
        bsl::arguments args{bsl::to_umax(0), nullptr};

    public:
        [[nodiscard]] constexpr auto
        test_member_const() const noexcept -> bool
        {
            bsl::discard(args.args());
            bsl::discard(args.index());
            bsl::discard(args.get<bool>(bsl::to_umax(0)));
            bsl::discard(args.get<bsl::string_view>(bsl::to_umax(0)));
            bsl::discard(args.get<bsl::safe_int8>(bsl::to_umax(0)));
            bsl::discard(args.get<bsl::safe_int16>(bsl::to_umax(0)));
            bsl::discard(args.get<bsl::safe_int32>(bsl::to_umax(0)));
            bsl::discard(args.get<bsl::safe_int64>(bsl::to_umax(0)));
            bsl::discard(args.get<bsl::safe_uint8>(bsl::to_umax(0)));
            bsl::discard(args.get<bsl::safe_uint16>(bsl::to_umax(0)));
            bsl::discard(args.get<bsl::safe_uint32>(bsl::to_umax(0)));
            bsl::discard(args.get<bsl::safe_uint64>(bsl::to_umax(0)));
            bsl::discard(args.get<bool>(""));
            bsl::discard(args.get<bsl::string_view>(""));
            bsl::discard(args.get<bsl::safe_int8>(""));
            bsl::discard(args.get<bsl::safe_int16>(""));
            bsl::discard(args.get<bsl::safe_int32>(""));
            bsl::discard(args.get<bsl::safe_int64>(""));
            bsl::discard(args.get<bsl::safe_uint8>(""));
            bsl::discard(args.get<bsl::safe_uint16>(""));
            bsl::discard(args.get<bsl::safe_uint32>(""));
            bsl::discard(args.get<bsl::safe_uint64>(""));
            bsl::discard(args.at<bool>(bsl::to_umax(0)));
            bsl::discard(args.at<bsl::string_view>(bsl::to_umax(0)));
            bsl::discard(args.at<bsl::safe_int8>(bsl::to_umax(0)));
            bsl::discard(args.at<bsl::safe_int16>(bsl::to_umax(0)));
            bsl::discard(args.at<bsl::safe_int32>(bsl::to_umax(0)));
            bsl::discard(args.at<bsl::safe_int64>(bsl::to_umax(0)));
            bsl::discard(args.at<bsl::safe_uint8>(bsl::to_umax(0)));
            bsl::discard(args.at<bsl::safe_uint16>(bsl::to_umax(0)));
            bsl::discard(args.at<bsl::safe_uint32>(bsl::to_umax(0)));
            bsl::discard(args.at<bsl::safe_uint64>(bsl::to_umax(0)));
            bsl::discard(args.front<bool>());
            bsl::discard(args.front<bsl::string_view>());
            bsl::discard(args.front<bsl::safe_int8>());
            bsl::discard(args.front<bsl::safe_int16>());
            bsl::discard(args.front<bsl::safe_int32>());
            bsl::discard(args.front<bsl::safe_int64>());
            bsl::discard(args.front<bsl::safe_uint8>());
            bsl::discard(args.front<bsl::safe_uint16>());
            bsl::discard(args.front<bsl::safe_uint32>());
            bsl::discard(args.front<bsl::safe_uint64>());
            bsl::discard(args.empty());
            bsl::discard(!!args);
            bsl::discard(args.size());
            bsl::discard(args.remaining());

            return true;
        }

        [[nodiscard]] constexpr auto
        test_member_nonconst() noexcept -> bool
        {
            bsl::discard(args.args());
            bsl::discard(args.index());
            bsl::discard(args.get<bool>(bsl::to_umax(0)));
            bsl::discard(args.get<bsl::string_view>(bsl::to_umax(0)));
            bsl::discard(args.get<bsl::safe_int8>(bsl::to_umax(0)));
            bsl::discard(args.get<bsl::safe_int16>(bsl::to_umax(0)));
            bsl::discard(args.get<bsl::safe_int32>(bsl::to_umax(0)));
            bsl::discard(args.get<bsl::safe_int64>(bsl::to_umax(0)));
            bsl::discard(args.get<bsl::safe_uint8>(bsl::to_umax(0)));
            bsl::discard(args.get<bsl::safe_uint16>(bsl::to_umax(0)));
            bsl::discard(args.get<bsl::safe_uint32>(bsl::to_umax(0)));
            bsl::discard(args.get<bsl::safe_uint64>(bsl::to_umax(0)));
            bsl::discard(args.get<bool>(""));
            bsl::discard(args.get<bsl::string_view>(""));
            bsl::discard(args.get<bsl::safe_int8>(""));
            bsl::discard(args.get<bsl::safe_int16>(""));
            bsl::discard(args.get<bsl::safe_int32>(""));
            bsl::discard(args.get<bsl::safe_int64>(""));
            bsl::discard(args.get<bsl::safe_uint8>(""));
            bsl::discard(args.get<bsl::safe_uint16>(""));
            bsl::discard(args.get<bsl::safe_uint32>(""));
            bsl::discard(args.get<bsl::safe_uint64>(""));
            bsl::discard(args.at<bool>(bsl::to_umax(0)));
            bsl::discard(args.at<bsl::string_view>(bsl::to_umax(0)));
            bsl::discard(args.at<bsl::safe_int8>(bsl::to_umax(0)));
            bsl::discard(args.at<bsl::safe_int16>(bsl::to_umax(0)));
            bsl::discard(args.at<bsl::safe_int32>(bsl::to_umax(0)));
            bsl::discard(args.at<bsl::safe_int64>(bsl::to_umax(0)));
            bsl::discard(args.at<bsl::safe_uint8>(bsl::to_umax(0)));
            bsl::discard(args.at<bsl::safe_uint16>(bsl::to_umax(0)));
            bsl::discard(args.at<bsl::safe_uint32>(bsl::to_umax(0)));
            bsl::discard(args.at<bsl::safe_uint64>(bsl::to_umax(0)));
            bsl::discard(args.front<bool>());
            bsl::discard(args.front<bsl::string_view>());
            bsl::discard(args.front<bsl::safe_int8>());
            bsl::discard(args.front<bsl::safe_int16>());
            bsl::discard(args.front<bsl::safe_int32>());
            bsl::discard(args.front<bsl::safe_int64>());
            bsl::discard(args.front<bsl::safe_uint8>());
            bsl::discard(args.front<bsl::safe_uint16>());
            bsl::discard(args.front<bsl::safe_uint32>());
            bsl::discard(args.front<bsl::safe_uint64>());
            bsl::discard(args.empty());
            bsl::discard(!!args);
            bsl::discard(args.size());
            bsl::discard(args.remaining());
            bsl::discard(++args);

            return true;
        }
    };

    constexpr fixture_t fixture1{};
}

/// <!-- description -->
///   @brief Main function for this unit test. If a call to bsl::ut_check() fails
///     the application will fast fail. If all calls to bsl::ut_check() pass, this
///     function will successfully return with bsl::exit_success.
///
/// <!-- inputs/outputs -->
///   @return Always returns bsl::exit_success.
///
[[nodiscard]] auto
main() noexcept -> bsl::exit_code
{
    bsl::ut_scenario{"verify noexcept"} = []() {
        bsl::ut_given{} = []() {
            bsl::arguments args{bsl::to_umax(0), nullptr};
            bsl::ut_then{} = []() {
                static_assert(noexcept(bsl::arguments{bsl::to_umax(0), nullptr}));
                static_assert(noexcept(args.args()));
                static_assert(noexcept(args.index()));
                static_assert(noexcept(args.get<bool>(bsl::to_umax(0))));
                static_assert(noexcept(args.get<bsl::string_view>(bsl::to_umax(0))));
                static_assert(noexcept(args.get<bsl::safe_int8>(bsl::to_umax(0))));
                static_assert(noexcept(args.get<bsl::safe_int16>(bsl::to_umax(0))));
                static_assert(noexcept(args.get<bsl::safe_int32>(bsl::to_umax(0))));
                static_assert(noexcept(args.get<bsl::safe_int64>(bsl::to_umax(0))));
                static_assert(noexcept(args.get<bsl::safe_uint8>(bsl::to_umax(0))));
                static_assert(noexcept(args.get<bsl::safe_uint16>(bsl::to_umax(0))));
                static_assert(noexcept(args.get<bsl::safe_uint32>(bsl::to_umax(0))));
                static_assert(noexcept(args.get<bsl::safe_uint64>(bsl::to_umax(0))));
                static_assert(noexcept(args.get<bool>("")));
                static_assert(noexcept(args.get<bsl::string_view>("")));
                static_assert(noexcept(args.get<bsl::safe_int8>("")));
                static_assert(noexcept(args.get<bsl::safe_int16>("")));
                static_assert(noexcept(args.get<bsl::safe_int32>("")));
                static_assert(noexcept(args.get<bsl::safe_int64>("")));
                static_assert(noexcept(args.get<bsl::safe_uint8>("")));
                static_assert(noexcept(args.get<bsl::safe_uint16>("")));
                static_assert(noexcept(args.get<bsl::safe_uint32>("")));
                static_assert(noexcept(args.get<bsl::safe_uint64>("")));
                static_assert(noexcept(args.at<bool>(bsl::to_umax(0))));
                static_assert(noexcept(args.at<bsl::string_view>(bsl::to_umax(0))));
                static_assert(noexcept(args.at<bsl::safe_int8>(bsl::to_umax(0))));
                static_assert(noexcept(args.at<bsl::safe_int16>(bsl::to_umax(0))));
                static_assert(noexcept(args.at<bsl::safe_int32>(bsl::to_umax(0))));
                static_assert(noexcept(args.at<bsl::safe_int64>(bsl::to_umax(0))));
                static_assert(noexcept(args.at<bsl::safe_uint8>(bsl::to_umax(0))));
                static_assert(noexcept(args.at<bsl::safe_uint16>(bsl::to_umax(0))));
                static_assert(noexcept(args.at<bsl::safe_uint32>(bsl::to_umax(0))));
                static_assert(noexcept(args.at<bsl::safe_uint64>(bsl::to_umax(0))));
                static_assert(noexcept(args.front<bool>()));
                static_assert(noexcept(args.front<bsl::string_view>()));
                static_assert(noexcept(args.front<bsl::safe_int8>()));
                static_assert(noexcept(args.front<bsl::safe_int16>()));
                static_assert(noexcept(args.front<bsl::safe_int32>()));
                static_assert(noexcept(args.front<bsl::safe_int64>()));
                static_assert(noexcept(args.front<bsl::safe_uint8>()));
                static_assert(noexcept(args.front<bsl::safe_uint16>()));
                static_assert(noexcept(args.front<bsl::safe_uint32>()));
                static_assert(noexcept(args.front<bsl::safe_uint64>()));
                static_assert(noexcept(args.empty()));
                static_assert(noexcept(!!args));
                static_assert(noexcept(args.size()));
                static_assert(noexcept(args.remaining()));
                static_assert(noexcept(++args));
            };
        };
    };

    bsl::ut_scenario{"verify constness"} = []() {
        bsl::ut_given{} = []() {
            fixture_t fixture2{};
            bsl::ut_then{} = [&fixture2]() {
                static_assert(fixture1.test_member_const());
                bsl::ut_check(fixture2.test_member_nonconst());
            };
        };
    };

    return bsl::ut_success();
}
