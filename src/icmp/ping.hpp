#ifndef TEST_PING_H
#define TEST_PING_H

#include <boost/asio.hpp>
#include <chrono>
#include <vector>
#include <map>
#include "icmp.hpp"
#include "ipv4.hpp"
#include "core/config.h"
#include "time_data.hpp"


class pinger
{
public:

    pinger(boost::asio::io_context&, const Config &config, time_data *);
    void start();
    // 这里就是全局的，因为每个节点对应一个pinger对象，但是所有节点只有一个time_data对象
    void start_send();
    void flush();
    void start_receive();
    void handle_receive(std::size_t length);

private:

    /*
    每一个节点发送一次就sent_num++，当sent_num等于num，说明所有的pinger都已经发送了，
    此时flag_sent设置为false,对比receive_num类似，当receive_num等于num说明所有的应答都收到
    此时flag_sent设置为true，然后将sent_num和我·receive_num置零，等待再次发送
    */


    boost::asio::ip::icmp::resolver resolver_;
    boost::asio::ip::icmp::endpoint destination_;
    boost::asio::ip::icmp::socket socket_;
    boost::asio::steady_timer timer_;
    unsigned short sequence_number_;
    const Config &config;
    unsigned char receive[1024];
    time_data *tdp;
    std::map<int, std::pair<std::chrono::steady_clock::time_point, std::chrono::steady_clock::time_point> > data;  // record ping start time
};

#endif
