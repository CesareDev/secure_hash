#include "secure_hash.hpp"

#include <iostream>

int main()
{
    std::cout << "Hashing function on the string \"Hello, World!\":\n" << std::endl;

    std::cout << "Sha1:   " << sha::HashString("Hello, World!", sha::Algorithm::Sha1) << std::endl;
    std::cout << "Sha224: " << sha::HashString("Hello, World!", sha::Algorithm::Sha224) << std::endl;
    std::cout << "Sha256: " << sha::HashString("Hello, World!", sha::Algorithm::Sha256) << std::endl;
    std::cout << "Sha384: " << sha::HashString("Hello, World!", sha::Algorithm::Sha384) << std::endl;
    std::cout << "Sha512: " << sha::HashString("Hello, World!", sha::Algorithm::Sha512) << std::endl;

    std::cout << "\nIf you wanna check the result use the sha*sum command as:\necho -n \"Hello, World!\" | sha*sum" << std::endl;
    return 0;
}
