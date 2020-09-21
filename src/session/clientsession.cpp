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

#include "clientsession.h"
#include "proto/trojanrequest.h"
#include "ssl/sslsession.h"
#include <iostream>
using namespace std;
using namespace boost::asio::ip;
using namespace boost::asio::ssl;

ClientSession::ClientSession(const Config &config, boost::asio::io_context &io_context, context &ssl_context) :
    Session(config, io_context),
    status(HANDSHAKE),
    in_socket(io_context),
    // in_socket 和本地浏览器之间的连接，实际上在service中的socket_acceptor.async_accept（）中的socket就是这个
    // 也就是说这个in_socket表示的是浏览器某一个请求和本地监听端口的一个链接

    out_socket(io_context, ssl_context) {}  //out_socket 和远程服务器之间的链接

tcp::socket& ClientSession::accept_socket() {
    return in_socket;
}

void ClientSession::start() {
    boost::system::error_code ec;
    start_time = time(nullptr);
    in_endpoint = in_socket.remote_endpoint(ec);  // 本地浏览器的请求：127.0.0.1:[PORT]
    if (ec) {
        destroy();
        return;
    }
    auto ssl = out_socket.native_handle();
    if (!config.ssl.sni.empty()) {
        SSL_set_tlsext_host_name(ssl, config.ssl.sni.c_str());
    }
    if (config.ssl.reuse_session) {
        SSL_SESSION *session = SSLSession::get_session();
        if (session) {
            SSL_set_session(ssl, session);
        }
    }
    in_async_read();
}

void ClientSession::in_async_read() {
    in_socket.async_read_some(boost::asio::buffer(in_read_buf, MAX_LENGTH), [this, self= shared_from_this()](const boost::system::error_code error, size_t length) {
        if (error == boost::asio::error::operation_aborted) {
            return;
        }
        if (error) {
            destroy();
            return;
        }
        in_recv(string(in_read_buf, length));
    });
}

void ClientSession::in_async_write(const string &data) {
    // auto data_copy = make_shared<string>(data);  // 作者在这里将data包装成一个智能指针，为的是怕data在异构中失效，
    // 但是事实上data传入到这里是不会失效的，这个data会被这个函数调用时立即发送出去。
    boost::asio::async_write(in_socket, boost::asio::buffer(data), [this, self= shared_from_this()](const boost::system::error_code error, size_t) {
        if (error) {
            destroy();
            return;
        }
        in_sent();
    });
}

void ClientSession::out_async_read() {
    out_socket.async_read_some(boost::asio::buffer(out_read_buf, MAX_LENGTH), [this, self= shared_from_this()](const boost::system::error_code error, size_t length) {
        if (error) {
            destroy();
            return;
        }
        out_recv(string(out_read_buf, length));
    });
}

void ClientSession::out_async_write(const string &data) {
    boost::asio::async_write(out_socket, boost::asio::buffer(data), [this, self= shared_from_this()](const boost::system::error_code error, size_t) {
        if (error) {
            destroy();
            return;
        }
        out_sent();
    });
}

void ClientSession::in_recv(const string &data) {
    switch (status) {

        case HANDSHAKE: {

            // 这里是ASCII为510,即将data的每个元素转化为int是510
            if (data.length() < 2 || data[0] != 5 || data.length() != (unsigned int)(unsigned char)data[1] + 2) {
                Log::log_with_endpoint(in_endpoint, "unknown protocol", Log::ERROR);
                destroy();
                return;
            }
            bool has_method = false;
            for (int i = 2; i < data[1] + 2; ++i) {
                if (data[i] == 0) {
                    has_method = true;
                    break;
                }
            }
            if (!has_method) {
                Log::log_with_endpoint(in_endpoint, "unsupported auth method", Log::ERROR);
                in_async_write(string("\x05\xff", 2));
                status = INVALID;
                return;
            }
            in_async_write(string("\x05\x00", 2));
            break;
        }
        case REQUEST: {
            // 此时的data包含以域名为请求的一系列数据，如：500www.google.cn���...
            // � 是不可显示的符号

            if (data.length() < 7 || data[0] != 5 || data[2] != 0) {
                Log::log_with_endpoint(in_endpoint, "bad request", Log::ERROR);
                destroy();
                return;
            }
            out_write_buf = config.password.cbegin()->first + "\r\n" + data[1] + data.substr(3) + "\r\n";
            TrojanRequest req;
            if (req.parse(out_write_buf) == -1) {
                Log::log_with_endpoint(in_endpoint, "unsupported command", Log::ERROR);
                in_async_write(string("\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00", 10));
                status = INVALID;
                return;
            }

             Log::log_with_endpoint(in_endpoint, "requested connection to " + req.address.address + ':' + to_string(req.address.port), Log::INFO);
             //eg: [2020-09-15 19:20:22] [INFO] 127.0.0.1:58862 requested connection to www.youtube.com:443
            in_async_write(string("\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00", 10));

            break;
        }
        case CONNECT: {
            // 将读取的信息，添加到包含trojan头信息的out_write_buf中
            sent_len += data.length();
            out_write_buf += data;
            break;
        }
        case FORWARD: {  //在这里直接写入了data是因为,trojan头在connect状态就有了，这里就
            sent_len += data.length();
            out_async_write(data);
            break;
        }

        default: break;
    }
}

void ClientSession::in_sent() {
    switch (status) {
        case HANDSHAKE: {
            status = REQUEST;

            in_async_read();
            break;
        }
        case REQUEST: {
            status = CONNECT;

            in_async_read();  // 这次读入的是有trojan头信息的数据

            // 这里解析的是vps上的地址
            resolver.async_resolve(config.remote_addr, to_string(config.remote_port), [this, self = shared_from_this()](const boost::system::error_code error, const tcp::resolver::results_type& results) {
                if (error || results.empty()) {
                    // 如果把域名改为1trojan.cfeng.space这里会报错
                    Log::log_with_endpoint(in_endpoint, "cannot resolve remote server hostname " + config.remote_addr + ": " + error.message(), Log::ERROR);
                    destroy();
                    return;
                }
                auto iterator = results.cbegin();
                Log::log_with_endpoint(in_endpoint, config.remote_addr + " is resolved to " + iterator->endpoint().address().to_string(), Log::ALL);
                boost::system::error_code ec;
                out_socket.next_layer().open(iterator->endpoint().protocol(), ec);
                if (ec) {
                    destroy();
                    return;
                }
                if (config.tcp.no_delay) {
                        out_socket.next_layer().set_option(tcp::no_delay(true));
                }
                if (config.tcp.keep_alive) {
                    out_socket.next_layer().set_option(boost::asio::socket_base::keep_alive(true));
                }
#ifdef TCP_FASTOPEN_CONNECT  // Default 0
                if (config.tcp.fast_open) {
                    using fastopen_connect = boost::asio::detail::socket_option::boolean<IPPROTO_TCP, TCP_FASTOPEN_CONNECT>;
                    boost::system::error_code ec;
                    out_socket.next_layer().set_option(fastopen_connect(true), ec);
                }
#endif // TCP_FASTOPEN_CONNECT
                out_socket.next_layer().async_connect(*iterator, [this, self = shared_from_this()](const boost::system::error_code error) {
                    if (error) {
                        Log::log_with_endpoint(in_endpoint, "cannot establish connection to remote server " + config.remote_addr + ':' + to_string(config.remote_port) + ": " + error.message(), Log::ERROR);
                        destroy();
                        return;
                    }
                    out_socket.async_handshake(stream_base::client, [this, self = shared_from_this()](const boost::system::error_code error) {
                        if (error) {
                            Log::log_with_endpoint(in_endpoint, "SSL handshake failed with " + config.remote_addr + ':' + to_string(config.remote_port) + ": " + error.message(), Log::ERROR);
                            destroy();
                            return;
                        }
                        Log::log_with_endpoint(in_endpoint, "tunnel established");
                        if (config.ssl.reuse_session) {
                            auto ssl = out_socket.native_handle();
                            if (!SSL_session_reused(ssl)) {
                                Log::log_with_endpoint(in_endpoint, "SSL session not reused");
                            } else {
                                Log::log_with_endpoint(in_endpoint, "SSL session reused");
                            }
                        }

                        status = FORWARD;
                        out_async_read();
                        out_async_write(out_write_buf);
                    });
                });
            });
            break;
        }
        case FORWARD: {
            out_async_read();
            break;
        }
        case INVALID: {
            destroy();
            break;
        }
        default: break;
    }
}

void ClientSession::out_recv(const string &data) {

        recv_len += data.length();
        in_async_write(data);

}

void ClientSession::out_sent() {

        in_async_read();  // 这里应该是最后一层
}

void ClientSession::destroy() {
    // TODO
    // 表面上看这个程序正常情况下是不会出错的，也就不会被销毁，不会被析构掉，
    // 但是事实上，程序一直检查error状态，在访问http时，事实上当接受方读取完发送方的所有数据时就会收到boost::asio::error::eof的错误代码
    // 但是在作者的程序中一收到eof就会立即关闭in_socket，
    // 试想： in_socket刚读完最后一条请求，然后用out_soket发送出去，因为是异步,in_socket又继续收到eof，就立即关闭in_socket
    // 那么上一条的请求得到的反馈如何被in_socket接受。
    // 所有我自己对in_socket也加了延迟关闭
    // 这里的前提是假设所有的出错是因为eof,但是事实上如果收到其他错误是否应该直接断开，并没有考虑
    if (status == DESTROY) {
        return;
    }
    status = DESTROY;
    Log::log_with_endpoint(in_endpoint, "disconnected, " + to_string(recv_len) + " bytes received, " + to_string(sent_len) + " bytes sent, lasted for " + to_string(time(nullptr) - start_time) + " seconds", Log::INFO);
    resolver.cancel();
    if (in_socket.is_open()) {

        auto basesocket_shutdown_cb = [this, self = shared_from_this()](const boost::system::error_code error) {
            if (error == boost::asio::error::operation_aborted) {
                return;
            }
            boost::system::error_code ec;
            in_socket.cancel(ec);
            in_socket.shutdown(tcp::socket::shutdown_both, ec);
            in_socket.close(ec);
        };

        basesocket_shutdown_timer.expires_after(chrono::seconds(SSL_SHUTDOWN_TIMEOUT));
        basesocket_shutdown_timer.async_wait(basesocket_shutdown_cb);
    }
    if (out_socket.next_layer().is_open()) {
        auto ssl_shutdown_cb = [this, self = shared_from_this()](const boost::system::error_code error) {
            if (error == boost::asio::error::operation_aborted) {
                return;
            }
            boost::system::error_code ec;
            ssl_shutdown_timer.cancel();
            out_socket.next_layer().cancel(ec);
            out_socket.next_layer().shutdown(tcp::socket::shutdown_both, ec);
            out_socket.next_layer().close(ec);
        };

        ssl_shutdown_timer.expires_after(chrono::seconds(SSL_SHUTDOWN_TIMEOUT));
        ssl_shutdown_timer.async_wait(ssl_shutdown_cb);
    }
}
