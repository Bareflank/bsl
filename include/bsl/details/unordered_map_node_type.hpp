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

#ifndef BSL_DETAILS_UNORDERED_MAP_NODE_TYPE_HPP
#define BSL_DETAILS_UNORDERED_MAP_NODE_TYPE_HPP

namespace bsl::details
{
    /// @class bsl::details::unordered_map_node_type
    ///
    /// <!-- description -->
    ///   @brief Used by the bsl::unordered_map to implement it's
    ///     internal linked list.
    ///
    /// <!-- template parameters -->
    ///   @tparam KEY_TYPE the type of key to use
    ///   @tparam T the type of value to use
    ///
    template<typename KEY_TYPE, typename T>
    struct unordered_map_node_type final
    {
        /// @brief stores the key for each node in the map
        KEY_TYPE key;
        /// @brief stores the data for each node in the map
        T val;
        /// @brief stores the next node in the list
        unordered_map_node_type *next;
    };
}

#endif
