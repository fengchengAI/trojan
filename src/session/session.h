/*
 * This file is part of the trojan project.
 * Trojan is an unidentifiable mechanism that helps you bypass GFW.
 * Copyright (C) 2017-2020  The Trojan Authors.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _SESSION_H_
#define _SESSION_H_

#include <ctime>
#include <memory>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/steady_timer.hpp>
#include "core/config.h"

#define MAX_LENGTH  8192
#define SSL_SHUTDOWN_TIMEOUT  60


// 这里假设所有的网页都是基于tcp(http2)的，而不是udp(http3)，所以删除了大量的udp代码
class Session : public std::enable_shared_from_this<Session> {
protected:

    const Config &config;
    char in_read_buf[MAX_LENGTH]{};
    char out_read_buf[MAX_LENGTH]{};
    uint64_t recv_len;    //对应udp_data_buf长度
    uint64_t sent_len;   //对应out_write_buf长度
    time_t start_time{};
    std::string out_write_buf;
    //client： 这是从本地读取的数据，并加上了trojan头的一个数据，会被用来写出去
    // service： 这是服务器读取到的client数据，此时存的数据去掉了trojan头信息，这个会被用来访问真正的地址信息

    //std::string udp_data_buf;
    boost::asio::ip::tcp::resolver resolver;
    boost::asio::ip::tcp::endpoint in_endpoint;
    // 和本socket关联的远程address：port
    // client 为127.0.0.1：port
    // service 为客户端的address：port


    boost::asio::steady_timer ssl_shutdown_timer;
    boost::asio::steady_timer basesocket_shutdown_timer;

public:
    Session(const Config &config, boost::asio::io_context &io_context);
    virtual boost::asio::ip::tcp::socket& accept_socket() = 0;
    virtual void start() = 0;
    virtual ~Session();
};

#endif // _SESSION_H_
