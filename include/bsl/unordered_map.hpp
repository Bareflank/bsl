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

#ifndef BSL_UNORDERED_MAP_HPP
#define BSL_UNORDERED_MAP_HPP

#include "details/unordered_map_node_type.hpp"
#include "is_copy_constructible.hpp"
#include "is_default_constructible.hpp"
#include "safe_integral.hpp"
#include "touch.hpp"

namespace bsl
{
    /// @class bsl::unordered_map
    ///
    /// <!-- description -->
    ///   @brief Implements a small subset of the std::unordered_map APIs,
    ///     specifically to support unit testing with a couple key differences:
    ///     - The bsl::unordered_map is really just a linked list.
    ///       The std::unordered_map is a hash table, which uses linked lists
    ///       when collisions occur (usually), but in this case, we implement
    ///       the hash table as if everything hashes to the same entry, and
    ///       therefore everything must be added to a linked list and searched
    ///       for. This means that the bsl::unordered_map is slow and should
    ///       only be used for unit testing
    ///     - Unlike std::unordered_map, bsl::unordered_map is a
    ///       "constexpr everything" structure, meaning it can be used in a
    ///       constexpr.
    ///     - The unordered map is not copyable or movable. Again, this is
    ///       only intended for use with unit tests and creating mocks.
    ///     - The at function can get/set values which std::unordered_map
    ///       does not support. This is intended to keep the APIs simple, but
    ///       it also means that the bsl::unordered_map is not compatible with
    ///       std::unordered_map. Normally you would use the []operator, but
    ///       that is not allowed with AUTOSAR or the C++ Core Guidelines, so
    ///       the at() function is the better option with the mod that we
    ///       ensure that at() functions like the []operator, with the
    ///       exception that like at() from std::unordered_map, there is a
    ///       const and non-const version. If you attempt to read a value
    ///       from the map that doesn't exist, the map will return a reference
    ///       to a default value, so taking the address of the reference is
    ///       undefined as the resulting address depends on map's state.
    ///     - We also don't support overlapping keys, meaning each key that
    ///       is added must be unique. If you attempt to set the value of a
    ///       key more than once, it will overwrite the existing value.
    ///
    /// <!-- template parameters -->
    ///   @tparam KEY_TYPE the type of key to use
    ///   @tparam T the type of value to use
    ///
    template<typename KEY_TYPE, typename T>
    class unordered_map final
    {
        static_assert(is_copy_constructible<KEY_TYPE>::value);
        static_assert(is_default_constructible<T>::value);

        /// @brief stores a default T when we have nothing else to return
        T m_default{};
        /// @brief stores the head of the linked list.
        details::unordered_map_node_type<KEY_TYPE, T> *m_head{};
        /// @brief stores the size of the map
        safe_uintmax m_size{};

    public:
        /// <!-- description -->
        ///   @brief Creates a default constructed bsl::unordered_map
        ///
        constexpr unordered_map() noexcept = default;

        /// <!-- description -->
        ///   @brief Destroyes a previously created bsl::unordered_map, calling
        ///     the provided function if ignore() was never called
        ///
        constexpr ~unordered_map() noexcept
        {
            this->clear();
        }

        /// <!-- description -->
        ///   @brief copy constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///
        constexpr unordered_map(unordered_map const &o) noexcept = delete;

        /// <!-- description -->
        ///   @brief move constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being moved
        ///
        constexpr unordered_map(unordered_map &&o) noexcept = delete;

        /// <!-- description -->
        ///   @brief copy assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr auto operator=(unordered_map const &o) &noexcept
            -> unordered_map & = delete;

        /// <!-- description -->
        ///   @brief move assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being moved
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr auto operator=(unordered_map &&o) &noexcept
            -> unordered_map & = delete;

        /// <!-- description -->
        ///   @brief Returns size() == 0
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns size() == 0
        ///
        [[nodiscard]] constexpr auto
        empty() const &noexcept -> bool
        {
            return m_size.is_zero();
        }

        /// <!-- description -->
        ///   @brief Returns the size of the map
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the size of the map
        ///
        [[nodiscard]] constexpr auto
        size() const &noexcept -> safe_uintmax const &
        {
            return m_size;
        }

        /// <!-- description -->
        ///   @brief Clear all entires in the map
        ///
        constexpr void
        clear() noexcept
        {
            auto node{m_head};
            while (nullptr != node) {
                auto next{node->next};

                // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
                delete node;    // GRCOV_EXCLUDE_BR
                node = next;
            }

            m_head = {};
            m_size = {};
        }

        /// <!-- description -->
        ///   @brief Set/get an entry in the map
        ///
        /// <!-- inputs/outputs -->
        ///   @param key the key associated with the value to get/set in the
        ///     map
        ///   @return Returns a reference to the requested value in the map
        ///
        [[nodiscard]] constexpr auto
        at(KEY_TYPE const &key) &noexcept -> T &
        {
            auto node{m_head};
            while (nullptr != node) {
                if (key == node->key) {
                    break;
                }
                node = node->next;
            }

            if (nullptr == node) {
                // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
                node = new details::unordered_map_node_type<KEY_TYPE, T>{key, {}, m_head};
                m_head = node;
                ++m_size;
            }
            else {
                bsl::touch();
            }

            return node->val;
        }

        /// <!-- description -->
        ///   @brief Set/get an entry in the map
        ///
        /// <!-- inputs/outputs -->
        ///   @param key the key associated with the value to get/set in the
        ///     map
        ///   @return Returns a reference to the requested value in the map
        ///
        [[nodiscard]] constexpr auto
        at(KEY_TYPE const &key) const &noexcept -> T const &
        {
            auto node{m_head};
            while (nullptr != node) {
                if (key == node->key) {
                    break;
                }
                node = node->next;
            }

            if (nullptr == node) {
                return m_default;
            }

            return node->val;
        }

        /// <!-- description -->
        ///   @brief Returns true if the map contains the provided key,
        ///     returns false otherwise.
        ///
        /// <!-- inputs/outputs -->
        ///   @param key the key associated with the value to query
        ///   @return Returns true if the map contains the provided key,
        ///     returns false otherwise.
        ///
        [[nodiscard]] constexpr auto
        contains(KEY_TYPE const &key) const &noexcept -> bool
        {
            auto node{m_head};
            while (nullptr != node) {
                if (key == node->key) {
                    return true;
                }
                node = node->next;
            }

            return false;
        }
    };
}

#endif
