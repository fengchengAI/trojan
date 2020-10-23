
#ifndef IPV4_HEADER_HPP
#define IPV4_HEADER_HPP

#include <algorithm>
#include <cstring>
#include <boost/asio/ip/address_v4.hpp>

// Packet header for IPv4.
//
// The wire format of an IPv4 header is:
//
// 0               8               16                             31
// +-------+-------+---------------+------------------------------+      ---
// |       |       |               |                              |       ^
// |version|header |    type of    |    total length in bytes     |       |
// |  (4)  | length|    service    |                              |       |
// +-------+-------+---------------+-+-+-+------------------------+       |
// |                               | | | |                        |       |
// |        identification         |0|D|M|    fragment offset     |       |
// |                               | |F|F|                        |       |
// +---------------+---------------+-+-+-+------------------------+       |
// |               |               |                              |       |
// | time to live  |   protocol    |       header checksum        |   20 bytes
// |               |               |                              |       |
// +---------------+---------------+------------------------------+       |
// |                                                              |       |
// |                      source IPv4 address                     |       |
// |                                                              |       |
// +--------------------------------------------------------------+       |
// |                                                              |       |
// |                   destination IPv4 address                   |       |
// |                                                              |       v
// +--------------------------------------------------------------+      ---
// |                                                              |       ^
// |                                                              |       |
// /                        options (if any)                      /    0 - 40
// /                                                              /     bytes
// |                                                              |       |
// |                                                              |       v
// +--------------------------------------------------------------+      ---

class ipv4_header
{
public:
    ipv4_header() ;
    ipv4_header(const unsigned char* data);

    unsigned char version() const ;
    unsigned short header_length() const ;
    unsigned char type_of_service() const ;
    unsigned short total_length() const ;
    unsigned short identification() const;
    bool dont_fragment() const ;
    bool more_fragments() const ;
    unsigned short fragment_offset() const ;
    unsigned int time_to_live() const ;
    unsigned char protocol() const ;
    unsigned short header_checksum() const ;

    boost::asio::ip::address_v4 source_address() const;

    boost::asio::ip::address_v4 destination_address() const;

private:
    unsigned short decode(int a, int b) const;

    unsigned char rep_[60];
};

#endif // IPV4_HEADER_HPP