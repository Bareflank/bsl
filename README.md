# **Bareflank Support Library**

[![Build Status](https://dev.azure.com/bareflank/bsl/_apis/build/status/Bareflank.bsl?branchName=master)](https://dev.azure.com/bareflank/bsl/_build/latest?definitionId=2&branchName=master)
[![Board Status](https://dev.azure.com/bareflank/0e2ee159-02d3-456c-908e-b6684055bb6c/183e6af6-db8f-4e28-910e-33ffd32d94a9/_apis/work/boardbadge/2e44e3c9-beea-457e-9786-4af440d91aa8?columnOptions=1)](https://dev.azure.com/bareflank/0e2ee159-02d3-456c-908e-b6684055bb6c/_boards/board/t/183e6af6-db8f-4e28-910e-33ffd32d94a9/Microsoft.RequirementCategory/)
[![Join the chat](https://img.shields.io/badge/chat-on%20Slack-brightgreen.svg)](https://app.slack.com/client/TPN7LQKRP/CPJLF1RV1)

## **A different view on Core Guideline Compliance**
The Bareflank Support Library (BSL) is a simple, header-only library that provides support for C++ Core Guideline Compliance. Similar to the goals of the Guideline Support Library (GSL) by Microsoft, the BSL aims to provide the facilities needed to ensure guideline compliance, while minimizing the need for verbosity.

<br>

[![Material for MkDocs](docs/images/example.png)](images/example.png)

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

## **Documentation**

For detailed instructions, visit <https://bareflank.github.io/bsl/>

## **Testing**

The Bareflank Support Library leverages the following tools to ensure the highest possible code quality. Each pull request undergoes the follwoing rigurous testing and review:

  - **Static Analysis:** Clang Tidy, CppCheck, Codacy, CodeFactor, and LGTM
  - **Dynamic Analysis:** Google's ASAN and UBSAN, Valgrind
  - **Code Coverage:** LCOV Code Coverage with CodeCov
  - **Coding Standards**: C++ Core Guidelines with SEI CERT C++ and High Integrity C++
  - **Style**: Clang Format and Git Check
  - **Documentation**: MkDocs and Doxygen
