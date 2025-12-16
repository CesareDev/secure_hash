#pragma once

#include <string>

namespace sha
{
    enum class Algorithm
    {
        Sha1,
        Sha224,
        Sha256,
        Sha384,
        Sha512
    };

    std::string HashString(const std::string& msg, Algorithm algorithm);
    std::string HashFile(const std::string& filename, Algorithm algorithm);
}
