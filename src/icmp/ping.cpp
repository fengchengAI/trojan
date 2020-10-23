//
// Created by root on 2020/10/16.
//

#include <string>
#include <chrono>

#include "icmp.hpp"
#include "ipv4.hpp"
#include "ping.hpp"
using namespace std;

pinger::pinger(boost::asio::io_context& io_context, const std::string &address, unsigned identifier_num)
        : resolver_(io_context), socket_(io_context), address_(address),
          timer_(io_context), timer_sent_(io_context), identifier_num_(identifier_num), sequence_num_(0)
{
    icmp_header_.type(icmp_header::echo_request);
    icmp_header_.code(0);
    icmp_header_.identifier(identifier_num_);

    destination_ = *resolver_.resolve(boost::asio::ip::icmp::v4(), address_, "").cbegin();
    socket_.async_connect(destination_, [this](boost::system::error_code ec){
        if (ec) std::cout<<ec.message()<<std::endl;
        start_send();
    });
}

void pinger::start_send()
{
    icmp_header_.sequence_number(++sequence_num_);

    icmp_header_.compute_checksum(body.c_str(), body.c_str()+body.size());

    time_sent_ = std::chrono::steady_clock::now();
    socket_.async_send(boost::asio::buffer(icmp_header_.data()+body), [this](boost::system::error_code ec, std::size_t /*length*/){
        if (ec) std::cout<<ec.message()<<std::endl;
        start_receive();
    });
    num_replies_ = 0;

    timer_.expires_at(time_sent_ + std::chrono::seconds(TIME_OUT_WAIT));
    timer_.async_wait([this](boost::system::error_code){
        handle_timeout();
    });

    timer_sent_.expires_at( time_sent_ + std::chrono::seconds(SENT_RATE));
    timer_sent_.async_wait([this](boost::system::error_code){
        handle_sent();
    });
}

void pinger::handle_timeout()
{
    if (num_replies_ == 0){
        //std::cout << address_ <<" Request timed out" << std::endl;
        td->set(identifier_num_,std::make_pair(address_, time_data::TIME_OUT));
        if (++receive_num==num){
            //std::cout<<"td->sort();"<<std::endl;
            td->sort();
            flag_sent = true;
            receive_num = 0;
            sent_num = 0;
        }
        socket_.cancel();
    }
}

void pinger::handle_sent() {
    if(flag_sent){

        start_send();
    }
    else {
        timer_sent_.expires_after(std::chrono::seconds(CHECK_RATE));
        timer_sent_.async_wait([this](boost::system::error_code){
            handle_sent();
        });
    }
}

void pinger::start_receive()
{
    //std::cout<<"sent_num :"<<sent_num<<std::endl;
    if (++sent_num==num) flag_sent = false;
    socket_.async_receive(boost::asio::buffer(receive,1024),
                          [this ](boost::system::error_code ec, std::size_t size){

                              if (ec) std::cout<<ec.message()<<std::endl;
                              else handle_receive(size);
                          });
}

void pinger::handle_receive(std::size_t length)
{

    ipv4_header ipv4_hdr(receive);
    icmp_header icmp_hdr(receive+ipv4_hdr.header_length());

    if (length>0 && icmp_hdr.type() == icmp_header::echo_reply
        && icmp_hdr.identifier() == identifier_num_
        && icmp_hdr.sequence_number() == sequence_num_)
    {

        if (num_replies_++ == 0){

            timer_.cancel();
            std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now();
            std::chrono::steady_clock::duration elapsed = now - time_sent_;
            /*
            std::cout << length - ipv4_hdr.header_length()
                      << " destination " << address_
                      << " bytes from " << ipv4_hdr.source_address()
                      << ": icmp_seq=" << icmp_hdr.sequence_number()
                      << ", ttl=" << ipv4_hdr.time_to_live()
                      << ", time="
                      << std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count()
                      << std::endl;
            */

            td->set(identifier_num_,std::make_pair(address_,std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count()));
            //std::cout<<"receive_num :"<<receive_num<<std::endl;

            if (++receive_num==num) {
                td->sort();
                flag_sent = true;
                receive_num = 0;
                sent_num = 0;
            }
        }
    }
}

