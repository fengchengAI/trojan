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

#include "serversession.h"
#include "proto/trojanrequest.h"
using namespace std;
using namespace boost::asio::ip;
using namespace boost::asio::ssl;

//boost::asio::ssl::stream<T>的next_layer（）返回的是的引用
//boost::asio::ssl::stream<boost::asio::ip::tcp::socket>的next_layer（）返回的是boost::asio::ip::tcp::socket的引用

ServerSession::ServerSession(const Config &config, boost::asio::io_context &io_context, context &ssl_context, const string &plain_http_response) :
    Session(config, io_context),
    status(HANDSHAKE),
    in_socket(io_context, ssl_context),
    out_socket(io_context),
    plain_http_response(plain_http_response) {}

tcp::socket& ServerSession::accept_socket() {
    return (tcp::socket&)in_socket.next_layer();
}

void ServerSession::start(const std::string &str) {
    boost::system::error_code ec;
    start_time = time(nullptr);
    in_endpoint = in_socket.next_layer().remote_endpoint(ec);  // 链接client
    if (ec) {
        destroy();
        return;
    }
    in_socket.async_handshake(stream_base::server, [this, self = shared_from_this()](const boost::system::error_code error) {
        if (error) {
            Log::log_with_endpoint(in_endpoint, "SSL handshake failed: " + error.message(), Log::ERROR);
            if (error.message() == "http request" && !plain_http_response.empty()) {
                recv_len += plain_http_response.length();
                boost::asio::async_write(accept_socket(), boost::asio::buffer(plain_http_response), [this, self = shared_from_this()](const boost::system::error_code, size_t) {
                    destroy();
                });
                return;
            }
            destroy();
            return;
        }
        in_async_read();
    });
}

void ServerSession::in_async_read() {
    in_socket.async_read_some(boost::asio::buffer(in_read_buf, MAX_LENGTH), [this, self = shared_from_this()](const boost::system::error_code error, size_t length) {
        if (error) {
            destroy();
            return;
        }
        in_recv(string(in_read_buf, length));
    });
}

void ServerSession::in_async_write(const string &data) {

    boost::asio::async_write(in_socket, boost::asio::buffer(data), [this, self = shared_from_this()](const boost::system::error_code error, size_t) {
        if (error) {
            destroy();
            return;
        }
        in_sent();
    });
}

void ServerSession::out_async_read() {
    out_socket.async_read_some(boost::asio::buffer(out_read_buf, MAX_LENGTH), [this, self = shared_from_this()](const boost::system::error_code error, size_t length) {
        if (error) {
            destroy();
            return;
        }
        out_recv(string(out_read_buf, length));
    });
}

void ServerSession::out_async_write(const string &data) {

    boost::asio::async_write(out_socket, boost::asio::buffer(data), [this, self = shared_from_this()](const boost::system::error_code error, size_t) {
        if (error) {
            destroy();
            return;
        }
        out_sent();
    });
}

void ServerSession::in_recv(const string &data) {
    if (status == HANDSHAKE) {
        TrojanRequest req;
        // data数据是一个带有trojan头的数据。
        bool valid = req.parse(data) != -1;
        // data中的query_addr和query_port是真实访问的地址如：www.youtube.com:443
        if (valid) {
            auto password_iterator = config.password.find(req.password);
            if (password_iterator == config.password.end()) {
                valid = false;

            } else {
                Log::log_with_endpoint(in_endpoint, "authenticated as " + password_iterator->second, Log::INFO);
            }
            if (!valid)
                Log::log_with_endpoint(in_endpoint, "valid trojan request structure but possibly incorrect password (" + req.password + ')', Log::WARN);

        }
        // 如果验证为真，则query_addr和query_port就是在data中包含的真实值（data是包含trojan头信息的数据）
        // 如果为假，则是域名和443
        string query_addr = valid ? req.address.address : config.remote_addr;
        string query_port = to_string([&]() {
            if (valid) {
                return req.address.port;
            }
            const unsigned char *alpn_out;
            unsigned int alpn_len;
            SSL_get0_alpn_selected(in_socket.native_handle(), &alpn_out, &alpn_len);
            if (alpn_out == nullptr) {
                return config.remote_port;
            }
            auto it = config.ssl.alpn_port_override.find(string(alpn_out, alpn_out + alpn_len));
            return it == config.ssl.alpn_port_override.end() ? config.remote_port : it->second;
        }());
        if (valid) {
            out_write_buf = req.payload;

            Log::log_with_endpoint(in_endpoint, "requested connection to " + req.address.address + ':' + to_string(req.address.port), Log::INFO);

        } else {
            Log::log_with_endpoint(in_endpoint, "not trojan request, connecting to " + query_addr + ':' + query_port, Log::WARN);
            out_write_buf = data;
        }
        sent_len += out_write_buf.length();
        resolver.async_resolve(query_addr, query_port, [this, self = shared_from_this(), query_addr, query_port](const boost::system::error_code error, const tcp::resolver::results_type& results) {
            //去解析真实访问地址 如：www.youtube.com:443
            if (error || results.empty()) {
                Log::log_with_endpoint(in_endpoint, "cannot resolve remote server hostname " + query_addr + ": " + error.message(), Log::ERROR);
                destroy();
                return;
            }
            auto iterator = results.cbegin();
            if (config.tcp.prefer_ipv4) {
                for (auto it = results.cbegin(); it != results.cend(); ++it) {
                    const auto &addr = it->endpoint().address();
                    if (addr.is_v4()) {
                        iterator = it;
                        break;
                    }
                }
            }
            Log::log_with_endpoint(in_endpoint, query_addr + " is resolved to " + iterator->endpoint().address().to_string(), Log::ALL);
            boost::system::error_code ec;
            out_socket.open(iterator->endpoint().protocol(), ec);
            if (ec) {
                destroy();
                return;
            }
            if (config.tcp.no_delay) {
                out_socket.set_option(tcp::no_delay(true));
            }
            if (config.tcp.keep_alive) {
                out_socket.set_option(boost::asio::socket_base::keep_alive(true));
            }
#ifdef TCP_FASTOPEN_CONNECT
            if (config.tcp.fast_open) {
                using fastopen_connect = boost::asio::detail::socket_option::boolean<IPPROTO_TCP, TCP_FASTOPEN_CONNECT>;
                boost::system::error_code ec;
                out_socket.set_option(fastopen_connect(true), ec);
            }
#endif // TCP_FASTOPEN_CONNECT
            out_socket.async_connect(*iterator, [this, self = shared_from_this(), query_addr, query_port](const boost::system::error_code error) {
                if (error) {
                    Log::log_with_endpoint(in_endpoint, "cannot establish connection to remote server " + query_addr + ':' + query_port + ": " + error.message(), Log::ERROR);
                    destroy();
                    return;
                }
                Log::log_with_endpoint(in_endpoint, "tunnel established");
                status = FORWARD;
                out_async_read(); //这里为什么直接read了，因为解析的时候就是用了域名，所以直接可以读取了
                // 这里out_async_read会读取out_socket的内容然后直接写如in_socket中，
                // TODO 那么问题是为什么还要下面的out_async_write？
                // 有可能上面读取到的只是一个头信息，真正请求是下面，且上面的read只是读取刚解析后的内容，并不是请求的内容
                if (!out_write_buf.empty()) {
                    out_async_write(out_write_buf);
                } else {
                    in_async_read();
                }
            });
        });
    } else if (status == FORWARD) {
        sent_len += data.length();
        out_async_write(data);
    }
}

void ServerSession::in_sent() {
    if (status == FORWARD) {
        out_async_read();
    }
}

void ServerSession::out_recv(const string &data) {
    if (status == FORWARD) {
        recv_len += data.length();

        in_async_write(data);
    }
}

void ServerSession::out_sent() {
    if (status == FORWARD) {
        in_async_read();
    }
}

void ServerSession::destroy() {
    if (status == DESTROY) {
        return;
    }
    status = DESTROY;
    Log::log_with_endpoint(in_endpoint, "disconnected, " + to_string(recv_len) + " bytes received, " + to_string(sent_len) + " bytes sent, lasted for " + to_string(time(nullptr) - start_time) + " seconds", Log::INFO);

    boost::system::error_code ec;
    resolver.cancel();

    if (out_socket.is_open()) {

        auto basesocket_shutdown_cb = [this, self = shared_from_this()](const boost::system::error_code error) {
            if (error == boost::asio::error::operation_aborted) {
                return;
            }
            boost::system::error_code ec;
            out_socket.cancel(ec);
            out_socket.shutdown(tcp::socket::shutdown_both, ec);
            out_socket.close(ec);
        };

        basesocket_shutdown_timer.expires_after(chrono::seconds(SSL_SHUTDOWN_TIMEOUT));
        basesocket_shutdown_timer.async_wait(basesocket_shutdown_cb);
    }


    if (out_socket.is_open()) {
        out_socket.cancel(ec);
        out_socket.shutdown(tcp::socket::shutdown_both, ec);
        out_socket.close(ec);
    }

    if (in_socket.next_layer().is_open()) {

        auto ssl_shutdown_cb = [this, self = shared_from_this()](const boost::system::error_code error) {
            if (error == boost::asio::error::operation_aborted) {
                return;
            }
            boost::system::error_code ec;
            ssl_shutdown_timer.cancel();
            in_socket.next_layer().cancel(ec);
            in_socket.next_layer().shutdown(tcp::socket::shutdown_both, ec);
            in_socket.next_layer().close(ec);
        };

        ssl_shutdown_timer.expires_after(chrono::seconds(SSL_SHUTDOWN_TIMEOUT));
        ssl_shutdown_timer.async_wait(ssl_shutdown_cb);
    }
}
