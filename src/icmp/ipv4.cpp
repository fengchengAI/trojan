
#include "ipv4.hpp"

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


ipv4_header::ipv4_header() { std::fill(rep_, rep_ + sizeof(rep_), 0); }
ipv4_header::ipv4_header(const unsigned char* data): ipv4_header::ipv4_header(){
    memcpy(rep_, data, (data[0] & 0xF) * 4);
}

unsigned char ipv4_header::version() const { return (rep_[0] >> 4) & 0xF; }
unsigned short ipv4_header::header_length() const { return (rep_[0] & 0xF) * 4; }
unsigned char ipv4_header::type_of_service() const { return rep_[1]; }
unsigned short ipv4_header::total_length() const { return decode(2, 3); }
unsigned short ipv4_header::identification() const { return decode(4, 5); }
bool ipv4_header::dont_fragment() const { return (rep_[6] & 0x40) != 0; }
bool ipv4_header::more_fragments() const { return (rep_[6] & 0x20) != 0; }
unsigned short ipv4_header::fragment_offset() const { return decode(6, 7) & 0x1FFF; }
unsigned int ipv4_header::time_to_live() const { return rep_[8]; }
unsigned char ipv4_header::protocol() const { return rep_[9]; }
unsigned short ipv4_header::header_checksum() const { return decode(10, 11); }

boost::asio::ip::address_v4 ipv4_header::source_address() const
{
    boost::asio::ip::address_v4::bytes_type bytes
            = { { rep_[12], rep_[13], rep_[14], rep_[15] } };
    return boost::asio::ip::address_v4(bytes);
}

boost::asio::ip::address_v4 ipv4_header::destination_address() const
{
    boost::asio::ip::address_v4::bytes_type bytes
            = { { rep_[16], rep_[17], rep_[18], rep_[19] } };
    return boost::asio::ip::address_v4(bytes);
}

unsigned short ipv4_header::decode(int a, int b) const
{ return (rep_[a] << 8) + rep_[b]; }
