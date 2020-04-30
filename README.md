![Bareflank](https://github.com/Bareflank/bsl/raw/master/.github/images/bsl_logo.png)

## **Description**

The Bareflank Support Library (BSL) is a header-only C++20 library that provides an API that is similar to the C++ Standard Library that is AUTOSAR and C++ Core Guideline compliant. To achieve this, the BSL does not adhere to the C++ Standard Library specification, but attempts to where possible (as the C++ Standard Library specification in its current form is not compliant with either set of guidelines). Since a number of critical systems applications do not support dynamic memory or C++ exceptions, the BSL uses neither, but is capable of supporting both if your environment supports them.

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
#include <bsl/array.hpp>
#include <bsl/convert.hpp>
#include <bsl/debug.hpp>
#include <bsl/for_each.hpp>
#include <bsl/main.hpp>
#include <bsl/safe_integral.hpp>

bsl::exit_code
main() noexcept
{
    constexpr bsl::safe_uintmax size{bsl::to_umax(42)};
    bsl::array<bsl::safe_int32, size.get()> arr{};

    bsl::for_each(arr, [](auto &elem, auto const &index) noexcept {
        elem = bsl::to_i32(index);
    });

    bsl::for_each(arr, [](auto const &elem) noexcept {
        bsl::print() << elem << bsl::endl;
    });

    bsl::print() << bsl::endl;
    return bsl::exit_success;
}
```

## **Build Requirements**
Currently, the BSL only supports the Clang/LLVM 10+ compiler. This, however, ensures the BSL can be natively compiled on Windows including support for cross-compiling. Support for other compilers that support C++20 can be added if needed, just let us know if that is something you need. 

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
cmake -GNinja -DCMAKE_CXX_COMPILER="clang++" ..
ninja info
ninja
```

### **Ubuntu Linux**
To compile the BSL on Ubuntu, you must install the following:
- [LLVM 10+](https://apt.llvm.org/)
- [CMake 3.13+](https://cmake.org/download/)

Once you have the above setup, you can install all dependencies using the following command
```bash
sudo apt-get install -y clang-10 clang-tidy-10 clang-format-10 ninja-build doxygen
```

You might also have to update your build environment to point to the new version of LLVM as follows:
```
sudo update-alternatives --remove-all clang
sudo update-alternatives --remove-all clang++
sudo update-alternatives --remove-all clang-format
sudo update-alternatives --install /usr/bin/clang clang /usr/bin/clang-10 100
sudo update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-10 100
sudo update-alternatives --install /usr/bin/clang-tidy clang-tidy /usr/bin/clang-tidy-10 100
sudo update-alternatives --install /usr/bin/clang-format clang-format /usr/bin/clang-format-10 100
```

To compile the BSL, use the following:
``` bash
git clone https://github.com/bareflank/bsl
mkdir bsl/build && cd bsl/build
cmake -GNinja -DCMAKE_CXX_COMPILER="clang++" ..
ninja info
ninja
```

## **Resources**

[![Join the chat](https://img.shields.io/badge/chat-on%20Slack-brightgreen.svg)](https://bareflank.herokuapp.com/)

The Bareflank Support Library provides a ton of useful resources to learn how to use the library including:

-   **Documentation**: <https://bareflank.github.io/bsl/>
-   **Examples**: <https://github.com/Bareflank/bsl/tree/master/examples>
-   **Unit Tests**: <https://github.com/Bareflank/bsl/tree/master/tests>

If you have any questions, bugs, or feature requests, please feel free to ask on any of the following:

-   **Issue Tracker**: <https://github.com/Bareflank/bsl/issues>

And as always, we are always looking for more help:

-   **Pull Requests**: <https://github.com/Bareflank/bsl/pulls>
-   **Contributing Guidelines**: <https://github.com/Bareflank/bsl/blob/master/contributing.md>

## **Testing**
[![Build Status](https://img.shields.io/endpoint.svg?url=https%3A%2F%2Factions-badge.atrox.dev%2Fbareflank%2Fbsl%2Fbadge&style=flat)](https://actions-badge.atrox.dev/bareflank/bsl/goto)
[![codecov](https://codecov.io/gh/Bareflank/bsl/branch/master/graph/badge.svg)](https://codecov.io/gh/Bareflank/bsl)

The Bareflank Support Library leverages the following tools to ensure the highest possible code quality. Each pull request undergoes the following rigorous testing and review:

-   **Static Analysis:** Clang Tidy, Perforce Helix QAC
-   **Dynamic Analysis:** Google's ASAN and UBSAN
-   **Code Coverage:** LLVM Code Coverage with CodeCov
-   **Coding Standards**: [AUTOSAR C++14](https://www.autosar.org/fileadmin/user_upload/standards/adaptive/17-03/AUTOSAR_RS_CPP14Guidelines.pdf)
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
- All of the bit APIs
- Most of the thread APIs (minus futures)
- Some sort of Date/Time APIs
- Some of the algorithms APIs (like copy, etc...)

In the future, we would like to add the following APIs, but we don't have a 
specific time frame for when these would be added:
- All of the concept APIs
- All of the algorithms APIs
- Most of the remaining utility APIs
- Non-allocating versions of a queue and stack

Most of the C++ APIs that include floating point numbers, dynamic memory 
and exceptions are purposely being avoided at the moment. If a need for 
these features is expressed, we can certainly add these as needed, we just 
need to ensure the BSL can continue to function without these where 
needed. 
