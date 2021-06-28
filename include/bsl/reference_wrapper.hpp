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
/// @file reference_wrapper.hpp
///

#ifndef BSL_REFERENCE_WRAPPER_HPP
#define BSL_REFERENCE_WRAPPER_HPP

#include "addressof.hpp"
#include "details/out.hpp"
#include "forward.hpp"
#include "invoke_result.hpp"

namespace bsl
{
    /// @class bsl::reference_wrapper
    ///
    /// <!-- description -->
    ///   @brief bsl::reference_wrapper is a class template that wraps a
    ///     reference. Unlike the std::reference_wrapper, the implicit
    ///     conversion operator is not supported as that would not be
    ///     compliant with AUTOSAR. We also do not add the assignment
    ///     operator as that would result in needing to define the rule of 5
    ///     which is not needed (there is no harm in allowing moves as
    ///     they result in the same thing as a copy).
    ///   @include example_reference_wrapper_overview.hpp
    ///
    /// <!-- template parameters -->
    ///   @tparam T the type of reference to wrap
    ///
    template<typename T>
    class reference_wrapper final
    {
        /// @brief stores the address of the wrapped reference
        T *m_ptr;

    public:
        /// @brief alias for: T
        using type = T;

        /// <!-- description -->
        ///   @brief Used to initialize a reference_wrapper by getting an
        ///     address to the provided "val" and storing the address for
        ///     use later.
        ///   @include reference_wrapper/example_reference_wrapper_constructor.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param val the thing to get the address of and store.
        ///
        explicit constexpr reference_wrapper(T &val) noexcept    // --
            : m_ptr{addressof(val)}
        {}

        /// <!-- description -->
        ///   @brief Returns a reference to the thing that is wrapped. This is
        ///     done by taking the stored address and returning a reference
        ///     instead of an address.
        ///   @include reference_wrapper/example_reference_wrapper_get.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a reference to the wrapped thing
        ///
        [[nodiscard]] constexpr auto
        get() const noexcept -> T &
        {
            return *m_ptr;
        }

        /// <!-- description -->
        ///   @brief Invokes the reference_wrapper as if it were a function.
        ///   @include reference_wrapper/example_reference_wrapper_functor.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam ARGS the types of arguments to pass to the wrapped
        ///     function.
        ///   @param a the arguments to pass to the wrapped function.
        ///   @return Returns the result of the wrapped function given the
        ///     provided arguments.
        ///
        /// <!-- exceptions -->
        ///   @throw throws if the wrapped function throws
        ///
        template<typename... ARGS>
        [[nodiscard]] constexpr auto
        operator()(ARGS &&...a) const -> invoke_result_t<T &, ARGS...>
        {
            return invoke(this->get(), bsl::forward<ARGS>(a)...);
        }
    };

    /// <!-- description -->
    ///   @brief Helper function that returns a reference_wrapper
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of reference to wrap
    ///   @param val the thing to get the address of and store.
    ///   @return Returns bsl::reference_wrapper<T>(val)
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    ref(T &val) noexcept -> reference_wrapper<T>
    {
        return reference_wrapper<T>(val);
    }

    /// <!-- description -->
    ///   @brief Helper function that returns a reference_wrapper
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of reference to wrap
    ///   @param val the thing to get the address of and store.
    ///   @return Returns bsl::ref(val.get());
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    ref(reference_wrapper<T> val) noexcept -> reference_wrapper<T>
    {
        return ref(val.get());
    }

    /// <!-- description -->
    ///   @brief Deletes the rvalue version of bsl::ref
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of reference to wrap
    ///   @param val the thing to get the address of and store.
    ///
    template<typename T>
    void ref(const T &&val) = delete;

    /// <!-- description -->
    ///   @brief Helper function that returns a reference_wrapper
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of reference to wrap
    ///   @param val the thing to get the address of and store.
    ///   @return Returns bsl::reference_wrapper<const T>(val)
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    cref(const T &val) noexcept -> reference_wrapper<const T>
    {
        return reference_wrapper<const T>(val);
    }

    /// <!-- description -->
    ///   @brief Helper function that returns a reference_wrapper
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of reference to wrap
    ///   @param val the thing to get the address of and store.
    ///   @return Returns bsl::cref(val.get());
    ///
    template<typename T>
    [[nodiscard]] constexpr auto
    cref(reference_wrapper<T> val) noexcept -> reference_wrapper<const T>
    {
        return cref(val.get());
    }

    /// <!-- description -->
    ///   @brief Deletes the rvalue version of bsl::cref
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of reference to wrap
    ///   @param val the thing to get the address of and store.
    ///
    template<typename T>
    void cref(const T &&val) = delete;

    /// <!-- description -->
    ///   @brief Outputs the provided bsl::reference_wrapper to the provided
    ///     output type.
    ///   @related bsl::reference_wrapper
    ///   @include reference_wrapper/example_reference_wrapper_ostream.hpp
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T1 the type of outputter provided
    ///   @tparam T2 the type of element being encapsulated.
    ///   @param o the instance of the outputter used to output the value.
    ///   @param val the reference_wrapper to output
    ///   @return return o
    ///
    template<typename T1, typename T2>
    [[maybe_unused]] constexpr auto
    operator<<(out<T1> const o, bsl::reference_wrapper<T2> const &val) noexcept -> out<T1>
    {
        if constexpr (!o) {
            return o;
        }

        return o << val.get();
    }
}

#endif
