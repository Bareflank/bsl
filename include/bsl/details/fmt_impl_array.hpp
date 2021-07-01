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

#ifndef BSL_DETAILS_FMT_IMPL_ARRAY_HPP
#define BSL_DETAILS_FMT_IMPL_ARRAY_HPP

#include "../array.hpp"
#include "../is_constant_evaluated.hpp"
#include "../safe_integral.hpp"
#include "out.hpp"

namespace bsl
{
    /// <!-- description -->
    ///   @brief Outputs the provided bsl::array to the provided
    ///     output type.
    ///   @related bsl::array
    ///   @include array/example_array_ostream.hpp
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T1 the type of outputter provided
    ///   @tparam T2 the type of element being encapsulated.
    ///   @tparam N the total number of elements in the array. Cannot be 0
    ///   @param o the instance of the outputter used to output the value.
    ///   @param val the array to output
    ///   @return return o
    ///
    template<typename T1, typename T2, bsl::uintmax N>
    [[maybe_unused]] constexpr auto
    operator<<(out<T1> const o, bsl::array<T2, N> const &val) noexcept -> out<T1>
    {
        if (is_constant_evaluated()) {
            return o;
        }

        if constexpr (!o) {
            return o;
        }

        for (safe_uintmax mut_i{}; mut_i < val.size(); ++mut_i) {
            if (mut_i.is_zero()) {
                o << "[" << *val.at_if(mut_i);
            }
            else {
                o << ", " << *val.at_if(mut_i);
            }
        }

        return o << ']';
    }
}

#endif
