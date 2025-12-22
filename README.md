# secure_hash

Simple implementation of the Secure Hash family algorithms. For now there are implemented 5 hashing functions:

- **SHA1**
- **SHA224**
- **SHA256**
- **SHA384**
- **SHA512**

## Building

It's just one source file `secure_hash.cpp` and it's header `secure_hash.hpp`.
You can build it however you want, you can add the two files to your project and compile
all together. Or simply use the `build.sh` script.

In the `build` directory you can build the project running `make`.
After compiling, the library file will be in the root of the `build` directory.

## Usage

The usage is pretty straightforward (e.g. with sha1 and sha256):

```cpp
#include <iostream>

#include "secure_hash.hpp"

int main()
{
    std::cout << "Sha1: " << sha::HashFile("some_file", sha::Algorithm::Sha1) << std::endl;
    std::cout << "Sha256: " << sha::HashString("Hello World!", sha::Algorithm::Sha256) << std::endl;
    return 0;
}
```

## Dependencies

- [cmake](https://cmake.org/) for the building script.
