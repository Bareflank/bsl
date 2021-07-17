![Bareflank](https://github.com/Bareflank/bsl/raw/master/.github/images/bsl_logo.png)

## **Description**
The Bareflank Support Library (BSL) is a C++20, "constexpr everything", AUTOSAR and C++ Core Guideline compliant header-only library intended to support the development of critical systems applications using the Clang/LLVM compiler. Although the BSL does not adhere to the C++ Standard Library specification, it attempts to where possible, to ensure most of the APIs are as familiar as possible. Since a number of critical systems applications do not support dynamic memory or C++ exceptions, the BSL uses neither, but is capable of supporting both if desired.

To ensure compliance with AUTOSAR and the C++ Core Guidelines, the development of the BSL makes heavy use of our own, custom version of [Clang Tidy](https://github.com/Bareflank/llvm-project). It should be noted that our implementation of Clang Tidy used to verify compliance with the AUTOSAR and C++ Core Guideline specifications is more restrictive than required and as such, you may find some of the rules implemented by our version of Clang Tidy more restrictive than is needed for your application. Furthermore, some of the rules in AUTOSAR and the C++ Core Guidelines are OBE due to the lack of dynamic memory, exceptions, and the required use of classes like bsl::safe_integral, which prevent implicit conversions, overflows, underflows, wrapping errors and ensure certain operations are not possible (like using the shift operators on signed integers). Other rules like the use of auto and braced initialization are also OBE thanks to C++17.

With respect to testing, the BSL provides full
[MC/DC](https://en.wikipedia.org/wiki/Modified_condition/decision_coverage) unit testing with 100% code coverage. To simplify this task, the BSL is written without the use of the binary operators "&&" and "||". In addition, all if statements follow a strict "if", "else if", "else" policy designed to ensure simple line coverage tools can be used to prove all possible branches are taken during testing. Futhermore, the entire BSL is written as a "constexpr", meaning APIs are unit tested both at compile-time and run-time. This allows us to ensure that the compiler's rules for constexpr and undefined behavior are leveraged to prove the BSL does not invoke UB at runtime. Unit tests are still executed at runtime after compilation so that we can use code coverage tools like CodeCov to ensure 100% coverage. 

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
#include <bsl/unlikely.hpp>

[[nodiscard]] auto
main(bsl::int32 const argc, bsl::cstr_type const argv[]) noexcept -> bsl::exit_code
{
    constexpr auto num_expected_args{2_umax};
    bsl::arguments const args{argc, argv};

    if (args.size() < num_expected_args) {
        bsl::error() << "This application expected 2 arguments\n";
        return bsl::exit_failure;
    }

    constexpr auto size_of_arr{42_umax};
    bsl::array<bsl::safe_int32, size_of_arr.get()> arr{};

    constexpr auto index_of_arg{1_umax};
    auto const val{args.at<bsl::safe_int32>(index_of_arg)};

    if (bsl::unlikely(!val)) {
        bsl::error() << "Invalid argument\n";
        return bsl::exit_failure;
    }

    for (auto const elem : arr) {
        if (bsl::unlikely(nullptr == elem.data)) {
            bsl::error() << "Impossible when using ranged loops.\n";
            return bsl::exit_failure;
        }

        *elem.data = val;
    }

    for (auto const elem : bsl::as_const(arr)) {
        bsl::print() << elem.index
                     << " = "
                     << bsl::fmt{"#010x", *elem.data}
                     << bsl::endl;
    }

    return bsl::exit_success;
}
```

## Interested In Working For AIS?
  Check out our [Can You Hack It?®](https://www.canyouhackit.com) challenge
  and test your skills! Submit your score to show us what you’ve got. We have
  offices across the country and offer  competitive pay and outstanding
  benefits. Join a team that is not only committed to the future of cyberspace,
  but to our employee’s success as well.

<p align="center">
  <a href="https://www.ainfosec.com/">
    <img src="https://github.com/Bareflank/bsl/raw/master/.github/images/ais.png" alt="ais" height="100" />
  </a>
</p>

## **Build Requirements**
Currently, the BSL only supports the Clang/LLVM 11+ compiler. This, however, ensures the BSL can be natively compiled on Windows including support for cross-compiling. Support for other C++20 compilers can be added if needed, just let us know if that is something you need.

### **Windows**
To compile the BSL on Windows, you must first install the following:
- [Visual Studio](https://visualstudio.microsoft.com/thank-you-downloading-visual-studio/?sku=Community&rel=16) (Enable "Desktop development with C++")
- [LLVM 10+](https://github.com/llvm/llvm-project/releases)
- [CMake 3.13+](https://cmake.org/download/)
- [Ninja](https://github.com/ninja-build/ninja/releases)

Visual Studio is needed as it contains Windows specific libraries that are needed during compilation. Instead of using the Clang/LLVM project that natively ships with Visual Studio, we use the standard Clang/LLVM binaries provided by the LLVM project which ensures we get all of the tools including LLD, Clang Tidy and Clang Format. Also note that you must put Ninja somewhere in your path (we usually drop into CMake's bin folder).

To compile the BSL, use the following:
``` bash
git clone https://github.com/bareflank/bsl
mkdir bsl/build && cd bsl/build
cmake -GNinja -DCMAKE_CXX_COMPILER="clang++" -DBUILD_EXAMPLES=ON -DBUILD_TESTS=ON ..
ninja info
ninja
```

### **Ubuntu Linux**
To compile the BSL on Ubuntu (20.04 or higher) you must first install the following dependencies:
```bash
sudo apt-get install -y clang cmake
```

To compile the BSL, use the following:
``` bash
git clone https://github.com/bareflank/bsl
mkdir bsl/build && cd bsl/build
cmake -DCMAKE_CXX_COMPILER="clang++" -DBUILD_EXAMPLES=ON -DBUILD_TESTS=ON ..
make info
make
```

### **Why 'constexpr everything'**
The BSL implements everything as a "constexpr". Beyond the usual reasons for compile-time code, the BSL enables unit tests to be executed at compile-time. Although C++20 added an enormous amount of additional support for "constexpr", there are a number of things that are still not allowed in a "constexpr", and this is a good thing, especially if critical systems compliance is important to your use case. This includes:
- No support for Undefined Behavior (UB)
- No support for casts from a void* to something else, or any other attempts to change an object's type without proper lifetime management.
- No support for memory leaks and any other memory related issues like out-of-bounds array accesses, etc.
- No support for reinterpret_cast, goto, etc.
- No support for the use of uninitialized variables
- No support for global or static local variables
- And much more

In other words, the constexpr validation checker in the compiler is in a way, the ultimate dynamic analysis tool. Tools like ASAN, UBSAN and Clang-Tidy are helpful, and should still be used, but if you ensure 100% code coverage at compile-time, most of the hard to find bugs related to undefined behavior will be eliminated. To perform compile-time unit testing, consider the following test:

``` c++
[[nodiscard]] constexpr auto
tests() noexcept -> bsl::exit_code
{
    bsl::ut_scenario{"verify += adds correctly"} = []() noexcept {
        bsl::ut_given{} = []() noexcept {
            constexpr auto data1{42_umax};
            bsl::safe_uintmax data2{};
            bsl::ut_when{} = [&]() noexcept {
                data2 += data1;
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(data2 == data1);
                };
            };
        };
    };

    return bsl::ut_success();
}
```

To execute this test at compile-time, simply do the following:

``` c++
[[nodiscard]] auto
main() noexcept -> bsl::exit_code
{
    static_assert(tests() == bsl::ut_success());
    return tests();
}
```

Using this pattern, all unit tests will be executed at both compile-time and at runtime, allowing you to use things like code coverage tools to ensure complete coverage of your unit tests.

If you think this is impossible in any real-world example, take a look at the [Bareflank Hypervisor](https://github.com/Bareflank/hypervisor). This is not a simple "Hello World" application, but instead is a hypervisor microkernel, complete with paging, ASM logic, etc. With a couple small exceptions (like virtual address to physical address conversions), all of the C++ code in this repro is tested at compile-time.

## **AUTOSAR Compliance**
The BSL is mostly compliant with AUTOSAR, and in a lot of ways far exceeds the AUTOSAR rules. This means the BSL is one of the few, if not the only partial C++ libraries that is AUTOSAR compliant in open source. There are some rules that are not adhered to:
- The BSL uses C++20. Without C++20, constexpr unit testing would not be possible. AUTOSAR requires the use of C++14. The advantages of "constexpr everything" for safety far out-weight the disadvantages of needing an exception to this rule. To ensure as much compliance as possible, the BSL avoids most of the new features added with C++17 and C++20  and will wait until a new AUTOSAR/MISRA specification is available to provide proper guidance.
- Since C++14 is not used, issues with things like `auto i{};` are fixed and therefor allowed. Two's compliment as well. This does not mean that all uses of `auto` are allowed as a number of rules still exist around `auto` that have nothing to do with the ambiguity issues with `auto i{};` in C++14.
- Some user-defined literals are provided for initializing fixed-width integrals. How this is done to ensure there are no issues with initializing variables can be found in the [convert.hpp](https://github.com/Bareflank/bsl/blob/master/include/bsl/convert.hpp#L900) header file, but the short story is, it is absolutely possible to create safe user-defined literals if raw literals are used (instead of their cooked counterparts). Raw literals require the code to manually parse the literal's tokens and thanks to C++20's extensive support for constexpr, this is all possible at compile-time.
- In some rare situations the BSL does not use an explicit single argument constructor to ensure compatibility with the C++ standard library where it makes sense. In these cases, a deleted single argument template function is provided which ensures that implicit conversions are still not possible, mitigating this issue. In fact, implicit conversions of any kind are not allowed by our custom version of the Clang-Tidy static analysis engine, including implicit conversions of integral types.
- There are some rules that simply cannot be adhered to when implementing the C++ standard library features. For example, the BSL must perform pointer arithmetic using the subscript operator when implementing bsl::array. It must also include some non-C++ headers like stdint.h to implement cstdint.hpp as required by the spec.
- C++ exceptions are not used by the BSL, but they are supported (meaning you can use C++ exceptions with the BSL if you choose). This is due to the fact that a lot of embedded, IoT and kernel/hypervisor applications for the BSL cannot support C++ exceptions due to the need for an unwinder, which is only really provided for Windows, Linux and macOS.

## **Resources**
[![Join the chat](https://img.shields.io/badge/chat-on%20Slack-brightgreen.svg)](https://bareflank.herokuapp.com/)

The Bareflank Support Library provides a ton of useful resources to learn how to use the library including:
-   **Documentation**: <https://bareflank.github.io/bsl/>
-   **Examples**: <https://github.com/Bareflank/bsl/tree/master/examples>
-   **Unit Tests**: <https://github.com/Bareflank/bsl/tree/master/tests>

If you have any questions, bugs, or feature requests, please feel free to ask on any of the following:
-   **Slack**: <https://bareflank.herokuapp.com/>
-   **Issue Tracker**: <https://github.com/Bareflank/bsl/issues>

If you would like to help:
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
