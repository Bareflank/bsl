![Bareflank](https://github.com/Bareflank/bsl/raw/master/.github/images/bsl_logo.png)

## **Description**

The Bareflank Support Library (BSL) is a C++20, AUTOSAR and C++ Core Guideline
compliant header-only library intended to support the development of critical
systems applications on Windows and Linux using the Clang/LLVM compiler.
Although the BSL does not adhere to the C++ Standard Library specification, it
attempts to where possible, to ensure most of the APIs are as familiar as
possible. Since a number of critical systems applications do not support
dynamic memory or C++ exceptions, the BSL uses neither, but is capable of
supporting both if exceptions are used.

To ensure compliance with AUTOSAR and the C++ Core Guidelines, the development
of the BSL makes heavy use of our own, custom version of
[Clang Tidy](https://github.com/Bareflank/llvm-project). It should be noted
that our implementation of Clang Tidy used to verify compliance with the
AUTOSAR and C++ Core Guideline specifications is more restrictive than required
and as such, you may find some of the rules implemented by our version of Clang
Tidy more restrictive than is needed for your application. Furthermore,
some of the rules in AUTOSAR and the C++ Core Guidelines are OBE due to the
lack of dynamic memory, exceptions, and the required use of classes like
bsl::safe_integral, which prevent implicit conversions, overflows, underflows, wrapping errors and ensure certain operations are not possible (like using the
shift operators on signed integers). Other rules like the use of auto and
braced initialization are also OBE thanks to C++17.

With respect to testing, the BSL provides full
[MC/DC](https://en.wikipedia.org/wiki/Modified_condition/decision_coverage) unit testing with 100% code coverage. To simplify this task, the BSL is
written without the use of &&, ||, >= or <=, and all if statements follow a
strict "if", "else if", "else" policy designed to ensure simple line coverage
tools can be used to prove all MC/DC paths are taken during testing. Futhermore,
the entire BSL is written as a "constexpr", meaning most (minus the bsl::ifmap and bsl::ioctl) APIs are unit tested both at compile-time and run-time (meaning most of the unit tests are actually executed from a static_assert).
This allows us to ensure that the compiler's rules for constexpr and undefined
behavior are leveraged to prove the BSL does not invoke UB at runtime. Unit
tests are still executed at runtime after compilation so that we can use code
coverage tools like CodeCov to ensure 100% coverage. Finally, we use GitHub
Actions to verify compiler compatibility, as well as perform additional static/
dynamic analysis tasks such as running the BSL unit tests with the Address and
UB sanitizers enabled.

## **Quick start**

![GitHub release (latest by date)](https://img.shields.io/github/v/release/bareflank/bsl?color=brightgreen)

Get the latest version of the BSL from GitHub:

``` bash
git clone https://github.com/bareflank/bsl
mkdir bsl/build && cd bsl/build
cmake -GNinja -DCMAKE_CXX_COMPILER="clang++" ..
ninja
```

Enjoy:

``` c++
#include <bsl/arguments.hpp>
#include <bsl/array.hpp>
#include <bsl/as_const.hpp>
#include <bsl/cstr_type.hpp>
#include <bsl/convert.hpp>
#include <bsl/debug.hpp>
#include <bsl/exit_code.hpp>
#include <bsl/fmt.hpp>
#include <bsl/safe_integral.hpp>

[[nodiscard]] auto
main(bsl::int32 const argc, bsl::cstr_type const argv[]) noexcept -> bsl::exit_code
{
    constexpr auto num_expected_args{bsl::to_umax(2)};
    bsl::arguments const args{argc, argv};

    if (args.size() < num_expected_args) {
        bsl::error() << "This application expected 2 arguments\n";
        return bsl::exit_failure;
    }

    constexpr auto size_of_arr{bsl::to_umax(42)};
    bsl::array<bsl::safe_int32, size_of_arr.get()> arr{};

    constexpr auto index_of_arg{bsl::to_umax(1)};
    auto const val{args.at<bsl::safe_int32>(index_of_arg)};

    if (!val) {
        bsl::error() << "Invalid argument\n";
        return bsl::exit_failure;
    }

    for (auto const elem : arr) {
        if (nullptr != elem.data) {
            *elem.data = val;
        }
        else {
            bsl::error() << "Impossible when using ranged loops.\n";
            return bsl::exit_failure;
        }
    }

    for (auto const elem : bsl::as_const(arr)) {
        bsl::print() << elem.index
                     << " = "
                     << bsl::fmt("#010x", *elem.data)
                     << bsl::endl;
    }

    return bsl::exit_success;
}
```

## **Build Requirements**
Currently, the BSL only supports the Clang/LLVM 10+ compiler. This, however, ensures the BSL can be natively compiled on Windows including support for cross-compiling. Support for other C++20 compilers can be added if needed, just let us know if that is something you need.

### **Windows**
To compile the BSL on Windows, you must first install the following:
- [Visual Studio](https://visualstudio.microsoft.com/thank-you-downloading-visual-studio/?sku=Community&rel=16) (Enable "Desktop development with C++")
- [LLVM 10+](https://github.com/llvm/llvm-project/releases)
- [CMake 3.13+](https://cmake.org/download/)
- [Ninja](https://github.com/ninja-build/ninja/releases)

Visual Studio is needed as it contains Windows specific libraries that are needed during compilation. Instead of using the Clang/LLVM project that natively ships with Visual Studio, we use the standard Clang/LLVM binaries provided by the LLVM project which ensures we get all of the tools including LLD, Clang Tidy and Clang Format. Also note that you must put Ninja somewhere
in your path (we usually drop into CMake's bin folder).

To compile the BSL, use the following:
``` bash
git clone https://github.com/bareflank/bsl
mkdir bsl/build && cd bsl/build
cmake -GNinja -DCMAKE_CXX_COMPILER="clang++" -DBUILD_EXAMPLES=ON -DBUILD_TESTS=ON ..
ninja info
ninja
```

### **Ubuntu Linux**
To compile the BSL on Ubuntu, you must install the following:
- [LLVM 10+](https://apt.llvm.org/)
- [CMake 3.13+](https://cmake.org/download/)

Once you have the above setup, you can install all dependencies using the following command
```bash
sudo apt-get install -y clang-10 build-essential git
```

You might also have to update your build environment to point to the new version of LLVM as follows:
```
sudo update-alternatives --remove-all clang++
sudo update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-10 100
```

To compile the BSL, use the following:
``` bash
git clone https://github.com/bareflank/bsl
mkdir bsl/build && cd bsl/build
cmake -DCMAKE_CXX_COMPILER="clang++" -DBUILD_EXAMPLES=ON -DBUILD_TESTS=ON ..
make info
make -j<number of cores>
```

## **Resources**

[![Join the chat](https://img.shields.io/badge/chat-on%20Slack-brightgreen.svg)](https://bareflank.herokuapp.com/)

The Bareflank Support Library provides a ton of useful resources to learn how to use the library including:

-   **Documentation**: <https://bareflank.github.io/bsl/>
-   **Examples**: <https://github.com/Bareflank/bsl/tree/master/examples>
-   **Unit Tests**: <https://github.com/Bareflank/bsl/tree/master/tests>

If you have any questions, bugs, or feature requests, please feel free to ask on any of the following:

-   **Slack**: <https://bareflank.herokuapp.com/>
-   **Issue Tracker**: <https://github.com/Bareflank/bsl/issues>

And as always, we are always looking for more help:

-   **Pull Requests**: <https://github.com/Bareflank/bsl/pulls>
-   **Contributing Guidelines**: <https://github.com/Bareflank/bsl/blob/master/contributing.md>

## **Testing**
[![Build Status](https://img.shields.io/endpoint.svg?url=https%3A%2F%2Factions-badge.atrox.dev%2Fbareflank%2Fbsl%2Fbadge&style=flat)](https://actions-badge.atrox.dev/bareflank/bsl/goto)
[![codecov](https://codecov.io/gh/Bareflank/bsl/branch/master/graph/badge.svg)](https://codecov.io/gh/Bareflank/bsl)

The Bareflank Support Library leverages the following tools to ensure the highest possible code quality. Each pull request undergoes the following rigorous testing and review:

-   **Static Analysis:** [Clang Tidy](https://github.com/Bareflank/llvm-project)
-   **Dynamic Analysis:** Google's ASAN and UBSAN
-   **Code Coverage:** Code Coverage with CodeCov
-   **Coding Standards**: [AUTOSAR C++14](https://www.autosar.org/fileadmin/user_upload/standards/adaptive/17-03/AUTOSAR_RS_CPP14Guidelines.pdf) and [C++ Core Guidelines](https://github.com/isocpp/CppCoreGuidelines/blob/master/CppCoreGuidelines.md)
-   **Style**: Clang Format
-   **Documentation**: Doxygen

## **The Future**
The initial version of the BSL is designed to support the needs of the
Bareflank project. This includes:
- All of the "type_traits" APIs
- All of the "limits" APIs
- Some utilities like bsl::move, bsl::forward, bsl::swap, etc...
- bsl::arguments
- bsl::array
- bsl::byte
- bsl::debug
- bsl::fmt
- bsl::for_each
- bsl::from_chars
- bsl::ifmap
- bsl::ioctl
- bsl::invoke
- bsl::reference_wrapper
- bsl::result
- bsl::safe_integral
- bsl::source_location
- bsl::string_view

The next version of this library will include (near the end of 2020):
- All of the atomic APIs
- Some of the thread APIs (minus futures)
- Some sort of Date/Time APIs
- Support for bsl::deque

In the future, we would like to add the following APIs, but we don't have a
specific time frame for when these would be added:
- All of the concept APIs
- All of the algorithms APIs
- Most of the remaining utility APIs
- Support for more data structures

Most of the C++ APIs that include floating point numbers, dynamic memory
and exceptions are purposely being avoided at the moment. If a need for
these features is expressed, we can certainly add these as needed, we just
need to ensure the BSL can continue to function without these where
needed.
