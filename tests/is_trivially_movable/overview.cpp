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

#include <bsl/is_trivially_movable.hpp>
#include <bsl/ut.hpp>

namespace
{
    class myclass final
    {};

    struct mystruct final
    {};

    // Needed for testing type traits
    // NOLINTNEXTLINE(bsl-decl-forbidden)
    union myunion final
    {};

    enum class myenum : bsl::int32
    {
    };

    class myclass_abstract
    {
    public:
        constexpr myclass_abstract() noexcept = default;
        virtual constexpr ~myclass_abstract() noexcept = default;

        virtual void foo() noexcept = 0;

    protected:
        constexpr myclass_abstract(myclass_abstract const &) noexcept = default;
        [[maybe_unused]] constexpr auto operator=(myclass_abstract const &) &noexcept
            -> myclass_abstract & = default;
        constexpr myclass_abstract(myclass_abstract &&) noexcept = default;
        [[maybe_unused]] constexpr auto operator=(myclass_abstract &&) &noexcept
            -> myclass_abstract & = default;
    };

    class myclass_base
    {};

    class myclass_subclass : public myclass_base
    {};
}

/// <!-- description -->
///   @brief Main function for this unit test. If a call to ut_check() fails
///     the application will fast fail. If all calls to ut_check() pass, this
///     function will successfully return with bsl::exit_success.
///
/// <!-- inputs/outputs -->
///   @return Always returns bsl::exit_success.
///
[[nodiscard]] auto
main() noexcept -> bsl::exit_code
{
    using namespace bsl;

    static_assert(is_trivially_movable<bool>::value);
    static_assert(is_trivially_movable<bool const>::value);
    static_assert(is_trivially_movable<bsl::int8>::value);
    static_assert(is_trivially_movable<bsl::int8 const>::value);
    static_assert(is_trivially_movable<bsl::int16>::value);
    static_assert(is_trivially_movable<bsl::int16 const>::value);
    static_assert(is_trivially_movable<bsl::int32>::value);
    static_assert(is_trivially_movable<bsl::int32 const>::value);
    static_assert(is_trivially_movable<bsl::int64>::value);
    static_assert(is_trivially_movable<bsl::int64 const>::value);
    static_assert(is_trivially_movable<bsl::int_least8>::value);
    static_assert(is_trivially_movable<bsl::int_least8 const>::value);
    static_assert(is_trivially_movable<bsl::int_least16>::value);
    static_assert(is_trivially_movable<bsl::int_least16 const>::value);
    static_assert(is_trivially_movable<bsl::int_least32>::value);
    static_assert(is_trivially_movable<bsl::int_least32 const>::value);
    static_assert(is_trivially_movable<bsl::int_least64>::value);
    static_assert(is_trivially_movable<bsl::int_least64 const>::value);
    static_assert(is_trivially_movable<bsl::int_fast8>::value);
    static_assert(is_trivially_movable<bsl::int_fast8 const>::value);
    static_assert(is_trivially_movable<bsl::int_fast16>::value);
    static_assert(is_trivially_movable<bsl::int_fast16 const>::value);
    static_assert(is_trivially_movable<bsl::int_fast32>::value);
    static_assert(is_trivially_movable<bsl::int_fast32 const>::value);
    static_assert(is_trivially_movable<bsl::int_fast64>::value);
    static_assert(is_trivially_movable<bsl::int_fast64 const>::value);
    static_assert(is_trivially_movable<bsl::intptr>::value);
    static_assert(is_trivially_movable<bsl::intptr const>::value);
    static_assert(is_trivially_movable<bsl::intmax>::value);
    static_assert(is_trivially_movable<bsl::intmax const>::value);
    static_assert(is_trivially_movable<bsl::uint8>::value);
    static_assert(is_trivially_movable<bsl::uint8 const>::value);
    static_assert(is_trivially_movable<bsl::uint16>::value);
    static_assert(is_trivially_movable<bsl::uint16 const>::value);
    static_assert(is_trivially_movable<bsl::uint32>::value);
    static_assert(is_trivially_movable<bsl::uint32 const>::value);
    static_assert(is_trivially_movable<bsl::uint64>::value);
    static_assert(is_trivially_movable<bsl::uint64 const>::value);
    static_assert(is_trivially_movable<bsl::uint_least8>::value);
    static_assert(is_trivially_movable<bsl::uint_least8 const>::value);
    static_assert(is_trivially_movable<bsl::uint_least16>::value);
    static_assert(is_trivially_movable<bsl::uint_least16 const>::value);
    static_assert(is_trivially_movable<bsl::uint_least32>::value);
    static_assert(is_trivially_movable<bsl::uint_least32 const>::value);
    static_assert(is_trivially_movable<bsl::uint_least64>::value);
    static_assert(is_trivially_movable<bsl::uint_least64 const>::value);
    static_assert(is_trivially_movable<bsl::uint_fast8>::value);
    static_assert(is_trivially_movable<bsl::uint_fast8 const>::value);
    static_assert(is_trivially_movable<bsl::uint_fast16>::value);
    static_assert(is_trivially_movable<bsl::uint_fast16 const>::value);
    static_assert(is_trivially_movable<bsl::uint_fast32>::value);
    static_assert(is_trivially_movable<bsl::uint_fast32 const>::value);
    static_assert(is_trivially_movable<bsl::uint_fast64>::value);
    static_assert(is_trivially_movable<bsl::uint_fast64 const>::value);
    static_assert(is_trivially_movable<bsl::uintptr>::value);
    static_assert(is_trivially_movable<bsl::uintptr const>::value);
    static_assert(is_trivially_movable<bsl::uintmax>::value);
    static_assert(is_trivially_movable<bsl::uintmax const>::value);
    static_assert(is_trivially_movable<myclass>::value);
    static_assert(is_trivially_movable<myclass const>::value);
    static_assert(is_trivially_movable<mystruct>::value);
    static_assert(is_trivially_movable<mystruct const>::value);
    static_assert(is_trivially_movable<myunion>::value);
    static_assert(is_trivially_movable<myunion const>::value);
    static_assert(is_trivially_movable<myenum>::value);
    static_assert(is_trivially_movable<myenum const>::value);
    static_assert(is_trivially_movable<myclass_base>::value);
    static_assert(is_trivially_movable<myclass_base const>::value);
    static_assert(is_trivially_movable<myclass_subclass>::value);
    static_assert(is_trivially_movable<myclass_subclass const>::value);
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-c-arrays, hicpp-avoid-c-arrays, modernize-avoid-c-arrays)
    static_assert(is_trivially_movable<bool[]>::value);
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-c-arrays, hicpp-avoid-c-arrays, modernize-avoid-c-arrays)
    static_assert(is_trivially_movable<bool[1]>::value);
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-c-arrays, hicpp-avoid-c-arrays, modernize-avoid-c-arrays)
    static_assert(is_trivially_movable<bool[][1]>::value);
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-c-arrays, hicpp-avoid-c-arrays, modernize-avoid-c-arrays)
    static_assert(is_trivially_movable<bool[1][1]>::value);
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-c-arrays, hicpp-avoid-c-arrays, modernize-avoid-c-arrays)
    static_assert(is_trivially_movable<bool const[]>::value);
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-c-arrays, hicpp-avoid-c-arrays, modernize-avoid-c-arrays)
    static_assert(is_trivially_movable<bool const[1]>::value);
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-c-arrays, hicpp-avoid-c-arrays, modernize-avoid-c-arrays)
    static_assert(is_trivially_movable<bool const[][1]>::value);
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-c-arrays, hicpp-avoid-c-arrays, modernize-avoid-c-arrays)
    static_assert(is_trivially_movable<bool const[1][1]>::value);
    static_assert(is_trivially_movable<void *>::value);
    static_assert(is_trivially_movable<void const *>::value);
    static_assert(is_trivially_movable<void *const>::value);
    static_assert(is_trivially_movable<void const *const>::value);
    static_assert(is_trivially_movable<bool (*)(bool)>::value);

    static_assert(!is_trivially_movable<myclass_abstract>::value);
    static_assert(!is_trivially_movable<myclass_abstract const>::value);
    static_assert(!is_trivially_movable<void>::value);
    static_assert(!is_trivially_movable<void const>::value);
    static_assert(!is_trivially_movable<bool &>::value);
    static_assert(!is_trivially_movable<bool &&>::value);
    static_assert(!is_trivially_movable<bool const &>::value);
    static_assert(!is_trivially_movable<bool const &&>::value);
    static_assert(!is_trivially_movable<bool(bool)>::value);

    return bsl::ut_success();
}
