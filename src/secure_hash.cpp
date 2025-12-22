#include "secure_hash.hpp"

#include <cstdint>
#include <iomanip>
#include <vector>
#include <sstream>
#include <fstream>

static uint32_t left_rotate(uint32_t value, uint32_t bits)
{
    return (value << bits) | (value >> (sizeof(uint32_t) * 8 - bits));
}

static uint32_t right_rotate(uint32_t value, uint32_t bits)
{
    return (value >> bits) | (value << (sizeof(uint32_t) * 8 - bits));
}

static uint64_t right_rotate(uint64_t value, uint64_t bits)
{
    return (value >> bits) | (value << (sizeof(uint64_t) * 8 - bits));
}

static std::string hash1(const std::string& input)
{
    // Constant
    uint32_t h0 { 0x67452301 };
    uint32_t h1 { 0xEFCDAB89 };
    uint32_t h2 { 0x98BADCFE };
    uint32_t h3 { 0x10325476 };
    uint32_t h4 { 0xC3D2E1F0 };

    std::vector<uint8_t> pre_proc(input.begin(), input.end());
    uint64_t original_len { pre_proc.size() * 8 };

    // Append '1' bit
    pre_proc.push_back(0x80);
    
    // Append k '0' bit
    while ((pre_proc.size() * 8) % 512 != 448)
        pre_proc.push_back(0x00);
    
    // Append original size
    for (int8_t i { 7 }; i >= 0; --i)
        pre_proc.push_back((original_len >> (i * 8)) & 0xFF);

    // Dividing in chunk
    for (uint64_t chunk {}; chunk < pre_proc.size(); chunk += 64)
    {
        uint32_t w[80] {};
        
        for (uint8_t i {}; i < 16; ++i)
        {
            w[i] = 
                pre_proc[chunk + i * 4] << 24 | 
                pre_proc[chunk + i * 4 + 1] << 16 | 
                pre_proc[chunk + i * 4 + 2] << 8 | 
                pre_proc[chunk + i * 4 + 3];
        }

        for (uint8_t i { 16 }; i < 80; ++i)
            w[i] = left_rotate(w[i - 3] ^ w[i - 8] ^ w[i -  14]  ^ w[i - 16], 1);

        uint32_t a { h0 };
        uint32_t b { h1 };
        uint32_t c { h2 };
        uint32_t d { h3 };
        uint32_t e { h4 };

        for (uint8_t i {}; i < 80; ++i)
        {
            uint32_t f {}, k {};

            if (i < 20)
            {
                f = (b & c) | (~b & d);
                k = 0x5A827999;
            }
            else if (i < 40)
            {
                f = b ^ c ^ d;
                k = 0x6ED9EBA1;
            }
            else if (i < 60)
            {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDC;
            }
            else
            {
                f = b ^ c ^ d;
                k = 0xCA62C1D6;
            }

            uint32_t temp { left_rotate(a, 5) + f + e + k + w[i] };
            e = d;
            d = c;
            c = left_rotate(b, 30);
            b = a;
            a = temp;
        }

        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
        h4 += e;
    }
    
    std::ostringstream res;
    res << std::hex << std::setfill('0')
        << std::setw(8) << h0
        << std::setw(8) << h1
        << std::setw(8) << h2
        << std::setw(8) << h3
        << std::setw(8) << h4;

    return res.str();
}

static std::string hash224(const std::string& input)
{
    // Constant
    uint32_t h0 { 0xc1059ed8 };
    uint32_t h1 { 0x367cd507 };
    uint32_t h2 { 0x3070dd17 };
    uint32_t h3 { 0xf70e5939 };
    uint32_t h4 { 0xffc00b31 };
    uint32_t h5 { 0x68581511 };
    uint32_t h6 { 0x64f98fa7 };
    uint32_t h7 { 0xbefa4fa4 };
    
    uint32_t k[64]
    {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    std::vector<uint8_t> pre_proc(input.begin(), input.end());
    uint64_t original_len { pre_proc.size() * 8 };

    // Append '1' bit
    pre_proc.push_back(0x80);
    
    // Append k '0' bit
    while ((pre_proc.size() * 8) % 512 != 448)
        pre_proc.push_back(0x00);
    
    // Append original size
    for (int8_t i { 7 }; i >= 0; --i)
        pre_proc.push_back((original_len >> (i * 8)) & 0xFF);

    // Dividing in chunk
    for (uint64_t chunk {}; chunk < pre_proc.size(); chunk += 64)
    {
        uint32_t w[64] {};
        
        for (uint8_t i {}; i < 16; ++i)
        {
            w[i] = 
                pre_proc[chunk + i * 4] << 24 | 
                pre_proc[chunk + i * 4 + 1] << 16 | 
                pre_proc[chunk + i * 4 + 2] << 8 | 
                pre_proc[chunk + i * 4 + 3];
        }

        for (uint8_t i { 16 }; i < 64; ++i)
        {
            uint32_t s0 { right_rotate(w[i - 15], 7) ^ right_rotate(w[i - 15], 18) ^ (w[i - 15] >> 3) };
            uint32_t s1 { right_rotate(w[i - 2], 17) ^ right_rotate(w[i - 2], 19) ^ (w[i - 2] >> 10) };
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        uint32_t a { h0 };
        uint32_t b { h1 };
        uint32_t c { h2 };
        uint32_t d { h3 };
        uint32_t e { h4 };
        uint32_t f { h5 };
        uint32_t g { h6 };
        uint32_t h { h7 };

        for (uint8_t i {}; i < 64; ++i)
        {
            uint32_t s0 { right_rotate(a, 2) ^ right_rotate(a, 13) ^ right_rotate(a, 22) };
            uint32_t maj { (a & b) ^ (a & c) ^ (b & c) };
            uint32_t t2 { s0 + maj };
            uint32_t s1 { right_rotate(e, 6) ^ right_rotate(e, 11) ^ right_rotate(e, 25) };
            uint32_t ch { (e & f) ^ (~e & g) };
            uint32_t t1 { h + s1 + ch + k[i] + w[i] };

            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }

        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
        h4 += e;
        h5 += f;
        h6 += g;
        h7 += h;
    }
    
    std::ostringstream res;
    res << std::hex << std::setfill('0') 
        << std::setw(8) << h0 
        << std::setw(8) << h1
        << std::setw(8) << h2
        << std::setw(8) << h3
        << std::setw(8) << h4
        << std::setw(8) << h5
        << std::setw(8) << h6;

    return res.str();
}

static std::string hash256(const std::string& input)
{
    // Constant
    uint32_t h0 = { 0x6a09e667 };
    uint32_t h1 = { 0xbb67ae85 };
    uint32_t h2 = { 0x3c6ef372 };
    uint32_t h3 = { 0xa54ff53a };
    uint32_t h4 = { 0x510e527f };
    uint32_t h5 = { 0x9b05688c };
    uint32_t h6 = { 0x1f83d9ab };
    uint32_t h7 = { 0x5be0cd19 };

    uint32_t k[64]
    {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    std::vector<uint8_t> pre_proc(input.begin(), input.end());
    uint64_t original_len { pre_proc.size() * 8 };

    // Append '1' bit
    pre_proc.push_back(0x80);
    
    // Append k '0' bit
    while ((pre_proc.size() * 8) % 512 != 448)
        pre_proc.push_back(0x00);
    
    // Append original size
    for (int8_t i { 7 }; i >= 0; --i)
        pre_proc.push_back((original_len >> (i * 8)) & 0xFF);

    // Dividing in chunk
    for (uint64_t chunk {}; chunk < pre_proc.size(); chunk += 64)
    {
        uint32_t w[64] {};
        
        for (uint8_t i {}; i < 16; ++i)
        {
            w[i] = 
                pre_proc[chunk + i * 4] << 24 | 
                pre_proc[chunk + i * 4 + 1] << 16 | 
                pre_proc[chunk + i * 4 + 2] << 8 | 
                pre_proc[chunk + i * 4 + 3];
        }

        for (uint8_t i { 16 }; i < 64; ++i)
        {
            uint32_t s0 { right_rotate(w[i - 15], 7) ^ right_rotate(w[i - 15], 18) ^ (w[i - 15] >> 3) };
            uint32_t s1 { right_rotate(w[i - 2], 17) ^ right_rotate(w[i - 2], 19) ^ (w[i - 2] >> 10) };
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        uint32_t a { h0 };
        uint32_t b { h1 };
        uint32_t c { h2 };
        uint32_t d { h3 };
        uint32_t e { h4 };
        uint32_t f { h5 };
        uint32_t g { h6 };
        uint32_t h { h7 };

        for (uint8_t i {}; i < 64; ++i)
        {
            uint32_t s0 { right_rotate(a, 2) ^ right_rotate(a, 13) ^ right_rotate(a, 22) };
            uint32_t maj { (a & b) ^ (a & c) ^ (b & c) };
            uint32_t t2 { s0 + maj };
            uint32_t s1 { right_rotate(e, 6) ^ right_rotate(e, 11) ^ right_rotate(e, 25) };
            uint32_t ch { (e & f) ^ (~e & g) };
            uint32_t t1 { h + s1 + ch + k[i] + w[i] };

            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }

        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
        h4 += e;
        h5 += f;
        h6 += g;
        h7 += h;
    }
    
    std::ostringstream res;
    res << std::hex << std::setfill('0') 
        << std::setw(8) << h0
        << std::setw(8) << h1
        << std::setw(8) << h2
        << std::setw(8) << h3
        << std::setw(8) << h4
        << std::setw(8) << h5
        << std::setw(8) << h6
        << std::setw(8) << h7;

    return res.str();
}

static std::string hash512(const std::string& input)
{
    uint64_t h0 = { 0x6a09e667f3bcc908 };
    uint64_t h1 = { 0xbb67ae8584caa73b };
    uint64_t h2 = { 0x3c6ef372fe94f82b };
    uint64_t h3 = { 0xa54ff53a5f1d36f1 };
    uint64_t h4 = { 0x510e527fade682d1 };
    uint64_t h5 = { 0x9b05688c2b3e6c1f };
    uint64_t h6 = { 0x1f83d9abfb41bd6b };
    uint64_t h7 = { 0x5be0cd19137e2179 };

    uint64_t k[80]
    { 
        0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538, 
        0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe, 
        0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 
        0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 
        0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab, 
        0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725, 
        0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 
        0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b, 
        0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218, 
        0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 
        0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 
        0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec, 
        0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c, 
        0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6, 
        0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 
        0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
    };

    std::vector<uint8_t> pre_proc(input.begin(), input.end());
    uint64_t original_len { pre_proc.size() * 8 };

    // Append '1' bit
    pre_proc.push_back(0x80);
    
    // Append k '0' bit
    while ((pre_proc.size() * 8) % 1024 != 896)
        pre_proc.push_back(0x00);
    
    // Append original size as 128 bit
    for (int8_t i { 7 }; i >= 0; --i)
        pre_proc.push_back(0x00);

    for (int8_t i { 7 }; i >= 0; --i)
        pre_proc.push_back((original_len >> (i * 8)) & 0xFF);
    
    // Dividing in chunk
    for (uint64_t chunk {}; chunk < pre_proc.size(); chunk += 128)
    {
        uint64_t w[80] {};
        
        for (uint8_t i {}; i < 16; ++i)
        {
            w[i] = 
                static_cast<uint64_t>(pre_proc[chunk + i * 8]) << 56 |
                static_cast<uint64_t>(pre_proc[chunk + i * 8 + 1]) << 48 |
                static_cast<uint64_t>(pre_proc[chunk + i * 8 + 2]) << 40 |
                static_cast<uint64_t>(pre_proc[chunk + i * 8 + 3]) << 32 |
                static_cast<uint64_t>(pre_proc[chunk + i * 8 + 4]) << 24 |
                static_cast<uint64_t>(pre_proc[chunk + i * 8 + 5]) << 16 |
                static_cast<uint64_t>(pre_proc[chunk + i * 8 + 6]) << 8 |
                static_cast<uint64_t>(pre_proc[chunk + i * 8 + 7]);
        }

        for (uint8_t i { 16 }; i < 80; ++i)
        {
            uint64_t s0 { right_rotate(w[i - 15], 1) ^ right_rotate(w[i - 15], 8) ^ (w[i - 15] >> 7) };
            uint64_t s1 { right_rotate(w[i - 2], 19) ^ right_rotate(w[i - 2], 61) ^ (w[i - 2] >> 6) };
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        uint64_t a { h0 };
        uint64_t b { h1 };
        uint64_t c { h2 };
        uint64_t d { h3 };
        uint64_t e { h4 };
        uint64_t f { h5 };
        uint64_t g { h6 };
        uint64_t h { h7 };

        for (uint8_t i {}; i < 80; ++i)
        {
            uint64_t s0 { right_rotate(a, 28) ^ right_rotate(a, 34) ^ right_rotate(a, 39) };
            uint64_t maj { (a & b) ^ (a & c) ^ (b & c) };
            uint64_t t2 { s0 + maj };
            uint64_t s1 { right_rotate(e, 14) ^ right_rotate(e, 18) ^ right_rotate(e, 41) };
            uint64_t ch { (e & f) ^ (~e & g) };
            uint64_t t1 { h + s1 + ch + k[i] + w[i] };

            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }

        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
        h4 += e;
        h5 += f;
        h6 += g;
        h7 += h;
    }
    
    std::ostringstream res;
    res << std::hex << std::setfill('0') 
        << std::setw(16) << h0 
        << std::setw(16) << h1
        << std::setw(16) << h2
        << std::setw(16) << h3
        << std::setw(16) << h4
        << std::setw(16) << h5
        << std::setw(16) << h6
        << std::setw(16) << h7;

    return res.str();
}

static std::string hash384(const std::string& input)
{
    uint64_t h0 { 0xcbbb9d5dc1059ed8 };
    uint64_t h1 { 0x629a292a367cd507 };
    uint64_t h2 { 0x9159015a3070dd17 };
    uint64_t h3 { 0x152fecd8f70e5939 };
    uint64_t h4 { 0x67332667ffc00b31 };
    uint64_t h5 { 0x8eb44a8768581511 };
    uint64_t h6 { 0xdb0c2e0d64f98fa7 };
    uint64_t h7 { 0x47b5481dbefa4fa4 };

    uint64_t k[80]
    { 
        0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538, 
        0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe, 
        0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 
        0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 
        0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab, 
        0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725, 
        0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 
        0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b, 
        0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218, 
        0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 
        0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 
        0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec, 
        0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c, 
        0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6, 
        0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 
        0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
    };

    std::vector<uint8_t> pre_proc(input.begin(), input.end());
    uint64_t original_len { pre_proc.size() * 8 };

    // Append '1' bit
    pre_proc.push_back(0x80);
    
    // Append k '0' bit
    while ((pre_proc.size() * 8) % 1024 != 896)
        pre_proc.push_back(0x00);
    
    // Append original size as 128 bit
    for (int8_t i { 7 }; i >= 0; --i)
        pre_proc.push_back(0x00);

    for (int8_t i { 7 }; i >= 0; --i)
        pre_proc.push_back((original_len >> (i * 8)) & 0xFF);
    
    // Dividing in chunk
    for (uint64_t chunk {}; chunk < pre_proc.size(); chunk += 128)
    {
        uint64_t w[80] {};
        
        for (uint8_t i {}; i < 16; ++i)
        {
            w[i] = 
                static_cast<uint64_t>(pre_proc[chunk + i * 8]) << 56 |
                static_cast<uint64_t>(pre_proc[chunk + i * 8 + 1]) << 48 |
                static_cast<uint64_t>(pre_proc[chunk + i * 8 + 2]) << 40 |
                static_cast<uint64_t>(pre_proc[chunk + i * 8 + 3]) << 32 |
                static_cast<uint64_t>(pre_proc[chunk + i * 8 + 4]) << 24 |
                static_cast<uint64_t>(pre_proc[chunk + i * 8 + 5]) << 16 |
                static_cast<uint64_t>(pre_proc[chunk + i * 8 + 6]) << 8 |
                static_cast<uint64_t>(pre_proc[chunk + i * 8 + 7]);
        }

        for (uint8_t i { 16 }; i < 80; ++i)
        {
            uint64_t s0 { right_rotate(w[i - 15], 1) ^ right_rotate(w[i - 15], 8) ^ (w[i - 15] >> 7) };
            uint64_t s1 { right_rotate(w[i - 2], 19) ^ right_rotate(w[i - 2], 61) ^ (w[i - 2] >> 6) };
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        uint64_t a { h0 };
        uint64_t b { h1 };
        uint64_t c { h2 };
        uint64_t d { h3 };
        uint64_t e { h4 };
        uint64_t f { h5 };
        uint64_t g { h6 };
        uint64_t h { h7 };

        for (uint8_t i {}; i < 80; ++i)
        {
            uint64_t s0 { right_rotate(a, 28) ^ right_rotate(a, 34) ^ right_rotate(a, 39) };
            uint64_t maj { (a & b) ^ (a & c) ^ (b & c) };
            uint64_t t2 { s0 + maj };
            uint64_t s1 { right_rotate(e, 14) ^ right_rotate(e, 18) ^ right_rotate(e, 41) };
            uint64_t ch { (e & f) ^ (~e & g) };
            uint64_t t1 { h + s1 + ch + k[i] + w[i] };

            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }

        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
        h4 += e;
        h5 += f;
        h6 += g;
        h7 += h;
    }
    
    std::ostringstream res;
    res << std::hex << std::setfill('0') 
        << std::setw(16) << h0 
        << std::setw(16) << h1
        << std::setw(16) << h2
        << std::setw(16) << h3
        << std::setw(16) << h4
        << std::setw(16) << h5;

    return res.str();
}

std::string sha::HashString(const std::string& msg, sha::Algorithm algorithm)
{
    switch (algorithm)
    {
        case sha::Algorithm::Sha1:
            return hash1(msg);
        case sha::Algorithm::Sha224:
            return hash224(msg);
        case sha::Algorithm::Sha256:
            return hash256(msg);
        case sha::Algorithm::Sha384:
            return hash384(msg);
        case sha::Algorithm::Sha512:
            return hash512(msg);
        default:
            return hash1(msg);
    }
}

std::string sha::HashFile(const std::string& filename, sha::Algorithm algorithm)
{
    std::ifstream file_stream(filename, std::ios::binary | std::ios::ate);

    if (!file_stream.is_open())
        return "";

    uint64_t file_size = file_stream.tellg();
    file_stream.seekg(std::ios::beg);

    std::string input {};
    input.resize(file_size);
    if (!file_stream.read(input.data(), file_size).good())
        return "";

    switch (algorithm)
    {
        case sha::Algorithm::Sha1:
            return hash1(input);
        case sha::Algorithm::Sha224:
            return hash224(input);
        case sha::Algorithm::Sha256:
            return hash256(input);
        case sha::Algorithm::Sha384:
            return hash384(input);
        case sha::Algorithm::Sha512:
            return hash512(input);
        default:
            return hash1(input);
    }
}
