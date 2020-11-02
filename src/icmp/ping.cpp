//
// Created by root on 2020/10/16.
//

#include <string>
#include <chrono>

#include "icmp.hpp"
#include "ipv4.hpp"
#include "ping.hpp"
using namespace std;


pinger::pinger(boost::asio::io_context& io_context, const Config &config_, time_data *tdp)
        : resolver_(io_context), socket_(io_context, boost::asio::ip::icmp::v4()),
          timer_(io_context), sequence_number_(0), config(config_),tdp(tdp)
{
    start_send();
    start_receive();
}

void pinger::start_send()
{

    std::string body("\"Hello!\" from Asio ping.");
    icmp_header echo_request;
    echo_request.type(icmp_header::echo_request);
    echo_request.code(0);
    echo_request.sequence_number(sequence_number_);
    int identifier = 0;
    for (auto str : config.icmp.multi_web){

        destination_ = *resolver_.resolve(boost::asio::ip::icmp::v4(), str, "").cbegin();
        echo_request.identifier(identifier);
        echo_request.compute_checksum(body.c_str(), body.c_str()+body.size());

        data[identifier].first = std::chrono::steady_clock::now();
        data[identifier].second =std::chrono::steady_clock::now() + std::chrono::milliseconds(config.icmp.time_out);

        socket_.send_to(boost::asio::buffer(echo_request.data()+body), destination_);
        identifier++;
    }
    sequence_number_++;

    timer_.expires_after(std::chrono::milliseconds (config.icmp.sent_time));
    timer_.async_wait([this](boost::system::error_code){
        set_data();
        start_send();
    });

}
void pinger::set_data(){
    for(auto i : data){
        tdp->set(i.first, config.icmp.multi_web[i.first], std::chrono::duration_cast<chrono::milliseconds>(i.second.second-i.second.first).count());
    }
    tdp->sort();
}
void pinger::start_receive()
{
    socket_.async_receive(boost::asio::buffer(receive,1024),
                          [this ](boost::system::error_code ec, std::size_t size){

                              if (ec) std::cout<<ec.message()<<std::endl;
                              else handle_receive(size);
                          });

}

void pinger::handle_receive(std::size_t length)
{
    // The actual number of bytes received is committed to the buffer so that we
    // can extract it using a std::istream object.
    //reply_buffer_.commit(length);

    // Decode the reply packet.
    ipv4_header ipv4_hdr(receive);
    icmp_header icmp_hdr(receive+ipv4_hdr.header_length());
    // We can receive all ICMP packets received by the host, so we need to
    // filter out only the echo replies that match the our identifier and
    // expected sequence number.
    if (length>0 && icmp_hdr.type() == icmp_header::echo_reply &&
        data.count(icmp_hdr.identifier()) && icmp_hdr.sequence_number() ==sequence_number_-1 )
    {
        data[icmp_hdr.identifier()].second =  std::chrono::steady_clock::now();
        // Print out some information about the reply packet.
        std::chrono::steady_clock::duration elapsed = data[icmp_hdr.identifier()].second - data[icmp_hdr.identifier()].first;

        /*
        std::cout << length - ipv4_hdr.header_length()

                  << " bytes from " << ipv4_hdr.source_address()
                  << ": icmp_seq=" << icmp_hdr.sequence_number()
                  << ", identifier= " << icmp_hdr.identifier()
                  << ", ttl=" << ipv4_hdr.time_to_live()
                  << ", time="
                  << chrono::duration_cast<chrono::milliseconds>(elapsed).count()
                  << std::endl;
        */
    }
    start_receive();
}