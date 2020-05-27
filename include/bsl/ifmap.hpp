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
/// @file ifmap.hpp
///

#ifndef BSL_IFMAP_HPP
#define BSL_IFMAP_HPP

#include "cstdint.hpp"
#include "debug.hpp"
#include "discard.hpp"
#include "safe_integral.hpp"
#include "string_view.hpp"

#if defined(_WIN32) && !BSL_PERFORCE && !defined(BAREFLANK)
#include "details/ifmap_windows.hpp"
#elif defined(__linux__) && !BSL_PERFORCE && !defined(BAREFLANK)
#include "details/ifmap_linux.hpp"
#else

namespace bsl
{
    /// @class bsl::ifmap
    ///
    /// <!-- description -->
    ///   @brief Maps a file as read-only, and returns a pointer to the file
    ///     via data() as well as the size of the mapped file via size().
    ///   @include example_ifmap_overview.hpp
    ///
    class ifmap final
    {
    public:
        /// @brief alias for: void
        using value_type = void;
        /// @brief alias for: safe_uintmax
        using size_type = safe_uintmax;
        /// @brief alias for: safe_uintmax
        using difference_type = safe_uintmax;
        /// @brief alias for: void *
        using pointer_type = void *;
        /// @brief alias for: void const *
        using const_pointer_type = void const *;

        /// <!-- description -->
        ///   @brief Creates a default ifmap that has not yet been mapped.
        ///   @include ifmap/example_ifmap_default_constructor.hpp
        ///
        ifmap() noexcept = default;

        /// <!-- description -->
        ///   @brief Creates a bsl::ifmap given a the filename and path of
        ///     the file to map as read-only.
        ///   @include ifmap/example_ifmap_constructor.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param filename the filename and path of the file to map
        ///
        explicit ifmap(string_view const &filename) noexcept
        {
            bsl::discard(filename);
            bsl::error() << "bsl::ifmap is unsupported on this platform\n";
        }

        /// <!-- description -->
        ///   @brief Returns a pointer to the read-only mapped file.
        ///   @include ifmap/example_ifmap_data.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a pointer to the read-only mapped file.
        ///
        [[nodiscard]] static constexpr const_pointer_type
        data() noexcept
        {
            return nullptr;
        }

        /// <!-- description -->
        ///   @brief Returns true if the file failed to be mapped, false
        ///     otherwise.
        ///   @include ifmap/example_ifmap_empty.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if the file failed to be mapped, false
        ///     otherwise.
        ///
        [[nodiscard]] static constexpr bool
        empty() noexcept
        {
            return true;
        }

        /// <!-- description -->
        ///   @brief Returns !empty()
        ///   @include ifmap/example_ifmap_operator_bool.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns !empty()
        ///
        [[nodiscard]] constexpr explicit operator bool() const noexcept
        {
            return !this->empty();
        }

        /// <!-- description -->
        ///   @brief Returns the number of bytes in the file being
        ///     mapped.
        ///   @include ifmap/example_ifmap_size.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the number of bytes in the file being
        ///     mapped.
        ///
        [[nodiscard]] static constexpr size_type
        size() noexcept
        {
            return size_type::zero();
        }

        /// <!-- description -->
        ///   @brief Returns the max number of bytes the BSL supports.
        ///   @include ifmap/example_ifmap_max_size.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the max number of bytes the BSL supports.
        ///
        [[nodiscard]] static constexpr size_type
        max_size() noexcept
        {
            return to_umax(size_type::max());
        }

        /// <!-- description -->
        ///   @brief Returns the number of bytes in the file being
        ///     mapped.
        ///   @include ifmap/example_ifmap_size_bytes.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the number of bytes in the file being
        ///     mapped.
        ///
        [[nodiscard]] static constexpr size_type
        size_bytes() noexcept
        {
            return size_type::zero();
        }
    };
}

#endif

#endif
