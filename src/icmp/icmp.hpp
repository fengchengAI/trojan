//
// Created by root on 2020/9/25.
//

#ifndef TEST_ICMP_H
#define TEST_ICMP_H

#include <iostream>
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

class icmp_header
{
public:
    enum { echo_reply = 0, destination_unreachable = 3, source_quench = 4,
        redirect = 5, echo_request = 8, time_exceeded = 11, parameter_problem = 12,
        timestamp_request = 13, timestamp_reply = 14, info_request = 15,
        info_reply = 16, address_request = 17, address_reply = 18 };

    icmp_header() ;
    icmp_header(const unsigned char* data);
    std::string data();
    unsigned char type() const ;
    unsigned char code() const ;
    unsigned short checksum() const ;
    unsigned short identifier() const ;
    unsigned short sequence_number() const;

    void type(unsigned char n) ;
    void code(unsigned char n) ;
    void checksum(unsigned short n) ;
    void identifier(unsigned short n) ;
    void sequence_number(unsigned short n) ;

    void compute_checksum(char const * body_begin, char const * body_end);
private:
    unsigned short decode(int a, int b) const;

    void encode(int a, int b, unsigned short n);
    unsigned char rep_[8];
};

#endif // ICMP_HEADER_HPP