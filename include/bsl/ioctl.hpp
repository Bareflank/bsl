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
/// @file ioctl.hpp
///

#ifndef BSL_IOCTL_HPP
#define BSL_IOCTL_HPP

#include "debug.hpp"
#include "discard.hpp"
#include "safe_integral.hpp"

#if defined(_WIN32) && !BSL_PERFORCE && !defined(BAREFLANK)
#include "details/ioctl_windows.hpp"
#elif defined(__linux__) && !BSL_PERFORCE && !defined(BAREFLANK)
#include "details/ioctl_linux.hpp"
#else

namespace bsl
{
    /// @class bsl::ioctl
    ///
    /// <!-- description -->
    ///   @brief Executes IOCTL commands to a driver.
    ///
    class ioctl final
    {
    public:
        /// <!-- description -->
        ///   @brief Creates a bsl::ioctl that can be used to communicate
        ///     with a device driver through an IOCTL interface.
        ///
        /// <!-- inputs/outputs -->
        ///   @param name the name of the device driver to IOCTL.
        ///
        template<typename T>
        explicit ioctl(T name) noexcept
        {
            bsl::discard(name);
            bsl::error() << "bsl::ioctl is unsupported on this platform\n";
        }

        /// <!-- description -->
        ///   @brief Sends a request to the driver without read or writing
        ///     data.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam REQUEST the type of request
        ///   @param req the request
        ///   @return Returns true if the IOCTL succeeded, false otherwise.
        ///
        template<typename REQUEST>
        [[nodiscard]] static constexpr bool
        send(REQUEST req) noexcept
        {
            bsl::discard(req);

            bsl::error() << "bsl::ioctl is unsupported on this platform\n";
            return false;
        }

        /// <!-- description -->
        ///   @brief Reads data from the device driver
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam REQUEST the type of request
        ///   @param req the request
        ///   @param data a pointer to read data to
        ///   @param size the size of the buffer being read to
        ///   @return Returns true if the IOCTL succeeded, false otherwise.
        ///
        template<typename REQUEST>
        [[nodiscard]] static constexpr bool
        read(REQUEST req, void *const data, safe_uintmax const &size) noexcept
        {
            bsl::discard(req);
            bsl::discard(data);
            bsl::discard(size);

            bsl::error() << "bsl::ioctl is unsupported on this platform\n";
            return false;
        }

        /// <!-- description -->
        ///   @brief Writes data to the device driver
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam REQUEST the type of request
        ///   @param req the request
        ///   @param data a pointer to write data from
        ///   @param size the size of the buffer being written from
        ///   @return Returns true if the IOCTL succeeded, false otherwise.
        ///
        template<typename REQUEST>
        [[nodiscard]] static constexpr bool
        write(REQUEST req, void const *const data, safe_uintmax const &size) noexcept
        {
            bsl::discard(req);
            bsl::discard(data);
            bsl::discard(size);

            bsl::error() << "bsl::ioctl is unsupported on this platform\n";
            return false;
        }

        /// <!-- description -->
        ///   @brief Reads/writes data from/to the device driver
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam REQUEST the type of request
        ///   @param req the request
        ///   @param data a pointer to read/write data to/from
        ///   @param size the size of the buffer being read/written to/from
        ///   @return Returns true if the IOCTL succeeded, false otherwise.
        ///
        template<typename REQUEST>
        [[nodiscard]] static constexpr bool
        read_write(REQUEST req, void *const data, safe_uintmax const &size) noexcept
        {
            bsl::discard(req);
            bsl::discard(data);
            bsl::discard(size);

            bsl::error() << "bsl::ioctl is unsupported on this platform\n";
            return false;
        }
    };
}

#endif

#endif
