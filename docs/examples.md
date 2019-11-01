# **Examples**

The Bareflank Support Library provides some simple examples to demonstrate how to use the library. For a more complete understanding, please read the APIs documentation or take a look at the project's unit tests.

## **Dynamic Array**

The BSL provides a new container type called the Dynamic Array or `#!c++ bsl::dynarray`. The dynarray is the combination of a `#!c++ std::unique_ptr<[]>` array type, a `#!c++ std::array`, and a`#!c++ gsl::span`. The goal of this type to provide an array type that owns the memory associated with the array, while at the same time, providing a C++ Core Guideline compliant interface for working with the array, something that `#!c++ std::unique_ptr` does not provide currently.

For example:

``` c++
#define BSL_CORE_GUIDELINE_COMPLIANT
#define BSL_THROW_ON_CONTRACT_VIOLATION
#include <bsl.h>

auto
main() -> int
{
    try {
        auto da = bsl::make_dynarray<int>(5);
        da[0] = 4;
        da[1] = 8;
        da[2] = 15;
        da[3] = 16;
        da[4] = 23;
        da[5] = 42;    // <-- throws
    }
    catch (const std::exception &e) {
        std::cout << "error: " << e.what() << '\n';
    }
}
```

The two `#!c++ #define` statements tells the BSL to ensure the BSL is guideline compliant (as this support can be disabled to improve performance if guideline compliance is not a concern), as well as to throw an exception if a contract violation occurs. By default, contract violations are ignored, but you can also configure them to terminate if desired.

The `#!c++ bsl::make_dynarray()` function behaves the same as `#!c++ std::make_unique()` without the addition of `#!c++ []`, creating a `#!c++ bsl::dynarray` of a given size. Once a `#!c++ bsl::dynarray` is created, you can access it using the same APIs that a `#!c++ std::array` and `#!c++ gsl::span` provide. Since guideline compliance is enabled and told to throw on violations, the attempt to set the 6th element in the array generates an exception.

## **Input File Array**

The `#!c++ bsl::ifarray` is a `#!c++ bsl::dynarray` that maps a file given a file name. Like the `#!c++ std::ifstream`, the `#!c++ bsl::ifarray` unmaps the file once it loses scope.

``` c++
#include <bsl.h>

auto
main() -> int
{
    for (const auto &c : bsl::ifarray<char>(FILENAME)) {
        std::cout << c;
    }

    std::cout << '\n';
}
```

Since the `#!c++ bsl::dynarray` provides a full implementation of a random access iterator, ranged for loops can be used to safely traverse the array as shown above.
