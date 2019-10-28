# **Bareflank Support Library**

## **A different view on Core Guideline Compliance**
The Bareflank Support Library (BSL) is a simple, header-only library that provides support for C++ Core Guideline Compliance. Similar to the goals of the Guideline Support Library (GSL) by Microsoft, the BSL aims to provide the facilities needed to ensure guideline compliance, while minimizing the need for verbosity.

<br>

[![Material for MkDocs](images/example.png)](images/example.png)

## **Quick start**
Get the latest version of the BSL from GitHub:

``` bash
git clone https://github.com/bareflank/bsl
```

Enjoy:

``` c++
#include "path/bsl.h"

auto
main() -> int
{
    auto da = bsl::make_dynarray<int>(42);
}
```
