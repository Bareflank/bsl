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

#ifndef BSL_DETAILS_IOCTL_LINUX_HPP
#define BSL_DETAILS_IOCTL_LINUX_HPP

#include "../cstdint.hpp"
#include "../debug.hpp"
#include "../discard.hpp"
#include "../safe_integral.hpp"

#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

namespace bsl
{
    /// @class bsl::ioctl
    ///
    /// <!-- description -->
    ///   @brief Executes IOCTL commands to a driver.
    ///
    class ioctl final
    {
        /// @brief stores a handle to the device driver.
        bsl::int32 m_hndl{};

    public:
        /// <!-- description -->
        ///   @brief Creates a bsl::ioctl that can be used to communicate
        ///     with a device driver through an IOCTL interface.
        ///
        /// <!-- inputs/outputs -->
        ///   @param name the name of the device driver to IOCTL.
        ///
        template<typename CSTR>
        explicit ioctl(CSTR name) noexcept
        {
            m_hndl = open(name, O_RDWR);    // NOLINT

            if (0 == m_hndl) {
                bsl::error() << "ioctl open failed\n";
                return;
            }
        }

        /// <!-- description -->
        ///   @brief Destructor
        ///
        ~ioctl() noexcept
        {
            close(m_hndl);
        }

        /// <!-- description -->
        ///   @brief copy constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///
        constexpr ioctl(ioctl const &o) noexcept = default;

        /// <!-- description -->
        ///   @brief move constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being moved
        ///
        constexpr ioctl(ioctl &&o) noexcept = default;

        /// <!-- description -->
        ///   @brief copy assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///   @return a reference to *this
        ///
        ioctl &operator=(ioctl const &o) &noexcept = default;

        /// <!-- description -->
        ///   @brief move assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being moved
        ///   @return a reference to *this
        ///
        ioctl &operator=(ioctl &&o) &noexcept = default;

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
        [[nodiscard]] constexpr bool
        send(REQUEST req) const noexcept
        {
            if (0 == m_hndl) {
                bsl::error() << "failed to send, ioctl not properly initialized\n";
                return false;
            }

            if (::ioctl(m_hndl, req) < 0) {    // NOLINT
                bsl::error() << "ioctl failed\n";
                return false;
            }

            return true;
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
        [[nodiscard]] constexpr bool
        read(REQUEST req, void *const data, safe_uintmax const &size) const noexcept
        {
            bsl::discard(size);

            if (0 == m_hndl) {
                bsl::error() << "failed to read, ioctl not properly initialized\n";
                return false;
            }

            if (::ioctl(m_hndl, req, data) < 0) {    // NOLINT
                bsl::error() << "ioctl failed\n";
                return false;
            }

            return true;
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
        [[nodiscard]] constexpr bool
        write(REQUEST req, void const *const data, safe_uintmax const &size) const noexcept
        {
            bsl::discard(size);

            if (0 == m_hndl) {
                bsl::error() << "failed to write, ioctl not properly initialized\n";
                return false;
            }

            if (::ioctl(m_hndl, req, data) < 0) {    // NOLINT
                bsl::error() << "ioctl failed\n";
                return false;
            }

            return true;
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
        [[nodiscard]] constexpr bool
        read_write(REQUEST req, void *const data, safe_uintmax const &size) const noexcept
        {
            bsl::discard(size);

            if (0 == m_hndl) {
                bsl::error() << "failed to read/write, ioctl not properly initialized\n";
                return false;
            }

            if (::ioctl(m_hndl, req, data) < 0) {    // NOLINT
                bsl::error() << "ioctl failed\n";
                return false;
            }

            return true;
        }
    };
}

#endif
