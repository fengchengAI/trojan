//
// Created by root on 2020/10/16.
//

#include "icmp.hpp"

//
// Created by root on 2020/9/25.
//


#include <algorithm>
#include <string>
#include <cstring>

// ICMP header for both IPv4 and IPv6.
//
// The wire format of an ICMP header is:
//
// 0               8               16                             31
// +---------------+---------------+------------------------------+      ---
// |               |               |                              |       ^
// |     type      |     code      |          checksum            |       |
// |               |               |                              |       |
// +---------------+---------------+------------------------------+    8 bytes
// |                               |                              |       |
// |          identifier           |       sequence number        |       |
// |                               |                              |       v
// +-------------------------------+------------------------------+      ---


icmp_header::icmp_header() {
    std::fill(rep_, rep_ + sizeof(rep_), 0);
}
icmp_header::icmp_header(const unsigned char* data) {
    memcpy(rep_, data, 8);
}
std::string icmp_header::data(){
    return std::string(reinterpret_cast<char *>(rep_),8);
}
unsigned char icmp_header::type() const { return rep_[0]; }
unsigned char icmp_header::code() const { return rep_[1]; }
unsigned short icmp_header::checksum() const { return decode(2, 3); }
unsigned short icmp_header::identifier() const { return decode(4, 5); }
unsigned short icmp_header::sequence_number() const { return decode(6, 7); }

void icmp_header::type(unsigned char n) { rep_[0] = n; }
void icmp_header::code(unsigned char n) { rep_[1] = n; }
void icmp_header::checksum(unsigned short n) { encode(2, 3, n); }
void icmp_header::identifier(unsigned short n) { encode(4, 5, n); }
void icmp_header::sequence_number(unsigned short n) { encode(6, 7, n); }


unsigned short icmp_header::decode(int a, int b) const
{ return (rep_[a] << 8) + rep_[b]; }

void icmp_header::encode(int a, int b, unsigned short n)
{
    rep_[a] = static_cast<unsigned char>(n >> 8);
    rep_[b] = static_cast<unsigned char>(n & 0xFF);
}



void icmp_header::compute_checksum(char const* body_begin, char const* body_end)
{
    unsigned int sum = (type() << 8) + code() + identifier() + sequence_number();

    char const * body_iter = body_begin;
    while (body_iter != body_end)
    {
        sum += (static_cast<unsigned char>(*body_iter++) << 8);
        if (body_iter != body_end)
            sum += static_cast<unsigned char>(*body_iter++);
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    checksum(static_cast<unsigned short>(~sum));
}

