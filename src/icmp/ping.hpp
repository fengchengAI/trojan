#ifndef TEST_PING_H
#define TEST_PING_H

#include <boost/asio.hpp>
#include <chrono>

#include "icmp.hpp"
#include "ipv4.hpp"
#include "time_data.hpp"

static std::string body("\"Hello!\" from Asio ping.");


class pinger
{
public:

    pinger(boost::asio::io_context&, const std::string &, unsigned );
    static time_data *td;  
    // 这里就是全局的，因为每个节点对应一个pinger对象，但是所有节点只有一个time_data对象

    static int num;// 记录节点总数
    static int TIME_OUT_WAIT;// 当发送的icmp在经过TIME_OUT秒后还没有收到TIME_OUT应答，则判断超时
    static int SENT_RATE;// 每当收到icmp应答后，进等待SENT_RATE再准备发送
    static int CHECK_RATE;
    // 当收到icmp的应答后，也经过了SENT_RATE秒，但是目前并不是所有节点都处理完成
    // 即从发送到接受或者延迟，再到等待十秒），
    // 就每隔CHECK_RATE去判断flag_sent标志。
private:
    static int sent_num;
    static int receive_num;
    static bool flag_sent;
    /*
    每一个节点发送一次就sent_num++，当sent_num等于num，说明所有的pinger都已经发送了，
    此时flag_sent设置为false,对比receive_num类似，当receive_num等于num说明所有的应答都收到
    此时flag_sent设置为true，然后将sent_num和我·receive_num置零，等待再次发送
    */
    void start_send();

    void handle_timeout();
    void handle_sent();

    void start_receive();
    void handle_receive(std::size_t length);

    std::string address_;
    boost::asio::ip::icmp::resolver resolver_;
    boost::asio::ip::icmp::endpoint destination_;
    boost::asio::ip::icmp::socket socket_;
    boost::asio::steady_timer timer_; //处理icmp的应答超时
    boost::asio::steady_timer timer_sent_; //处理icmp什么时候发送，即判断flag_sent标志位
    unsigned char receive[1024];

    std::chrono::steady_clock::time_point time_sent_;
    unsigned short sequence_num_;
    std::size_t num_replies_;
    icmp_header icmp_header_;
    unsigned identifier_num_;

};

#endif
