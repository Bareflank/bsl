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

#ifndef BSL_EXAMPLE_CLASS_NODEFAULT_HPP
#define BSL_EXAMPLE_CLASS_NODEFAULT_HPP

namespace bsl
{
    /// @class bsl::example_class_nodefault
    ///
    /// <!-- description -->
    ///   @brief An example of a class with no default constructor which can
    ///     be used to demonstrate how declval can get the type of a member
    ///     function even if it doesn't have a default constructor.
    ///
    class example_class_nodefault final
    {
    public:
        /// <!-- description -->
        ///   @brief Deleted default constructor
        ///
        constexpr example_class_nodefault() noexcept = delete;

        /// <!-- description -->
        ///   @brief Destroyes a previously created bsl::example_class_nodefault
        ///
        constexpr ~example_class_nodefault() noexcept = default;

        /// <!-- description -->
        ///   @brief copy constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///
        constexpr example_class_nodefault(example_class_nodefault const &o) noexcept = default;

        /// <!-- description -->
        ///   @brief move constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_o the object being moved
        ///
        constexpr example_class_nodefault(example_class_nodefault &&mut_o) noexcept = default;

        /// <!-- description -->
        ///   @brief copy assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr auto operator=(example_class_nodefault const &o) &noexcept
            -> example_class_nodefault & = default;

        /// <!-- description -->
        ///   @brief move assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_o the object being moved
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr auto operator=(example_class_nodefault &&mut_o) &noexcept
            -> example_class_nodefault & = default;

        /// <!-- description -->
        ///   @brief Simple example of a getter
        ///
        /// <!-- inputs/outputs -->
        ///   @return returns the value of m_data1;
        ///
        [[nodiscard]] constexpr auto
        get() const noexcept -> bool
        {
            return m_data1;
        }

    private:
        /// @brief dummy data #1
        bool m_data1{true};
    };
}

#endif
