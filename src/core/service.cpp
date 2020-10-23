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

#include "service.h"
#include <cstring>
#include <cerrno>
#include <iostream>
#include <thread>
#include <stdexcept>
#include "session/serversession.h"
#include "session/clientsession.h"
#include "ssl/ssldefaults.h"
#include "ssl/sslsession.h"
#include "icmp/ping.hpp"
#include "icmp/time_data.hpp"
using namespace std;
using namespace boost::asio::ip;
using namespace boost::asio::ssl;

#ifdef ENABLE_REUSE_PORT
typedef boost::asio::detail::socket_option::boolean<SOL_SOCKET, SO_REUSEPORT> reuse_port;
#endif // ENABLE_REUSE_PORT

int time_data::TIME_OUT = 400;  //如果超时，time_data中记录为time_data::time_out
int time_data::MAX_NUM = 3;  // 选择ping前time_data::max_nums的域名
int pinger::sent_num = 0;
int pinger::receive_num = 0;
bool pinger::flag_sent = true;
int pinger::num = 35;
int pinger::TIME_OUT_WAIT = 5;
int pinger::SENT_RATE = 10;
int pinger::CHECK_RATE = 1;
time_data* pinger::td (nullptr);


void Service::pre_static_data(){
    time_data::TIME_OUT = config.icmp.TIME_OUT;
    time_data::MAX_NUM =  config.icmp.MAX_NUM;
    pinger::num =  config.icmp.multi_web.size();
    std::cout<<config.icmp.multi_web.size()<<std::endl;
    pinger::TIME_OUT_WAIT =  config.icmp.TIME_OUT_WAIT;
    pinger::SENT_RATE = config.icmp.SENT_RATE;
    pinger::CHECK_RATE = config.icmp.CHECK_RATE;
}

Service::Service(Config &config, bool test):
    //这里只要是处理ssl配置
    config(config),
    socket_acceptor(io_context),
    ssl_context(context::sslv23),
    timer_(io_context,std::chrono::seconds(10))
    //timer_(io_context,std::chrono::seconds(5))
    {

        if (config.icmp.enable_mutil_host){
            pre_static_data();
            timer_.async_wait([this](boost::system::error_code){
                        hand_flash();
                    });
                    //time_data glob;
                    //glob.set_nums(config.multi_web.size());
            td = new time_data();  
            td->set_nums(config.icmp.multi_web.size());
            pinger::td = td;
        }else
        {
            timer_.cancel();
        }
        
     
    if (!test) {
        tcp::resolver resolver(io_context);
        tcp::endpoint listen_endpoint = *resolver.resolve(config.local_addr, to_string(config.local_port)).begin();
        socket_acceptor.open(listen_endpoint.protocol());
        socket_acceptor.set_option(tcp::acceptor::reuse_address(true));

        if (config.tcp.reuse_port) {
#ifdef ENABLE_REUSE_PORT
            socket_acceptor.set_option(reuse_port(true));
#else  // ENABLE_REUSE_PORT
            Log::log_with_date_time("SO_REUSEPORT is not supported", Log::WARN);
#endif // ENABLE_REUSE_PORT
        }

        socket_acceptor.bind(listen_endpoint);
        // client 127.0.0.1：1080
        // service 0.0.0.0:443

        socket_acceptor.listen();

    }
    Log::level = config.log_level;
    auto native_context = ssl_context.native_handle();
    ssl_context.set_options(context::default_workarounds | context::no_sslv2 | context::no_sslv3 | context::single_dh_use);
    if (!config.ssl.curves.empty()) {
        SSL_CTX_set1_curves_list(native_context, config.ssl.curves.c_str());
    }
    if (config.run_type == Config::SERVER) {
        ssl_context.use_certificate_chain_file(config.ssl.cert);
        ssl_context.set_password_callback([this](size_t, context_base::password_purpose) {
            return this->config.ssl.key_password;
        });
        ssl_context.use_private_key_file(config.ssl.key, context::pem);
        if (config.ssl.prefer_server_cipher) {
            SSL_CTX_set_options(native_context, SSL_OP_CIPHER_SERVER_PREFERENCE);
        }
        if (!config.ssl.alpn.empty()) {
            SSL_CTX_set_alpn_select_cb(native_context, [](SSL*, const unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void *config) -> int {
                if (SSL_select_next_proto((unsigned char**)out, outlen, (unsigned char*)(((Config*)config)->ssl.alpn.c_str()), ((Config*)config)->ssl.alpn.length(), in, inlen) != OPENSSL_NPN_NEGOTIATED) {
                    return SSL_TLSEXT_ERR_NOACK;
                }
                return SSL_TLSEXT_ERR_OK;
            }, &config);
        }
        if (config.ssl.reuse_session) {
            SSL_CTX_set_timeout(native_context, config.ssl.session_timeout);
            if (!config.ssl.session_ticket) {
                SSL_CTX_set_options(native_context, SSL_OP_NO_TICKET);
            }
        } else {
            SSL_CTX_set_session_cache_mode(native_context, SSL_SESS_CACHE_OFF);
            SSL_CTX_set_options(native_context, SSL_OP_NO_TICKET);
        }
        if (!config.ssl.plain_http_response.empty()) {
            ifstream ifs(config.ssl.plain_http_response, ios::binary);
            if (!ifs.is_open()) {
                throw runtime_error(config.ssl.plain_http_response + ": " + strerror(errno));
            }
            plain_http_response = string(istreambuf_iterator<char>(ifs), istreambuf_iterator<char>());
        }
        if (config.ssl.dhparam.empty()) {
            ssl_context.use_tmp_dh(boost::asio::const_buffer(SSLDefaults::g_dh2048_sz, SSLDefaults::g_dh2048_sz_size));
        } else {
            ssl_context.use_tmp_dh_file(config.ssl.dhparam);
        }

    } else {
        if (config.ssl.sni.empty()) {
            config.ssl.sni = config.remote_addr;
        }
        if (config.ssl.verify) {
            ssl_context.set_verify_mode(verify_peer);
            if (config.ssl.cert.empty()) {
                ssl_context.set_default_verify_paths();

            } else {
                ssl_context.load_verify_file(config.ssl.cert);
            }
            if (config.ssl.verify_hostname) {
#if BOOST_VERSION >= 107300
                ssl_context.set_verify_callback(host_name_verification(config.ssl.sni));
#else
                ssl_context.set_verify_callback(rfc2818_verification(config.ssl.sni));
#endif
            }
            X509_VERIFY_PARAM *param = X509_VERIFY_PARAM_new();
            X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_PARTIAL_CHAIN);
            SSL_CTX_set1_param(native_context, param);
            X509_VERIFY_PARAM_free(param);
        } else {
            ssl_context.set_verify_mode(verify_none);
        }
        if (!config.ssl.alpn.empty()) {
            SSL_CTX_set_alpn_protos(native_context, (unsigned char*)(config.ssl.alpn.c_str()), config.ssl.alpn.length());
        }
        if (config.ssl.reuse_session) {
            SSL_CTX_set_session_cache_mode(native_context, SSL_SESS_CACHE_CLIENT);
            SSLSession::set_callback(native_context);
            if (!config.ssl.session_ticket) {
                SSL_CTX_set_options(native_context, SSL_OP_NO_TICKET);
            }
        } else {
            SSL_CTX_set_options(native_context, SSL_OP_NO_TICKET);
        }
    }
    if (!config.ssl.cipher.empty()) {
        SSL_CTX_set_cipher_list(native_context, config.ssl.cipher.c_str());
    }
    if (!config.ssl.cipher_tls13.empty()) {
#ifdef ENABLE_TLS13_CIPHERSUITES
        SSL_CTX_set_ciphersuites(native_context, config.ssl.cipher_tls13.c_str());
#else  // ENABLE_TLS13_CIPHERSUITES
        Log::log_with_date_time("TLS1.3 ciphersuites are not supported", Log::WARN);
#endif // ENABLE_TLS13_CIPHERSUITES
    }

    if (!test) {
        if (config.tcp.no_delay) {
            socket_acceptor.set_option(tcp::no_delay(true));
        }
        if (config.tcp.keep_alive) {
            socket_acceptor.set_option(boost::asio::socket_base::keep_alive(true));
        }
        if (config.tcp.fast_open) {
#ifdef TCP_FASTOPEN
            using fastopen = boost::asio::detail::socket_option::integer<IPPROTO_TCP, TCP_FASTOPEN>;
            boost::system::error_code ec;
            socket_acceptor.set_option(fastopen(config.tcp.fast_open_qlen), ec);
#else // TCP_FASTOPEN
            Log::log_with_date_time("TCP_FASTOPEN is not supported", Log::WARN);
#endif // TCP_FASTOPEN
#ifndef TCP_FASTOPEN_CONNECT
            Log::log_with_date_time("TCP_FASTOPEN_CONNECT is not supported", Log::WARN);
#endif // TCP_FASTOPEN_CONNECT
        }
    }
    if (Log::keylogOpen()) {
#ifdef ENABLE_SSL_KEYLOG
        SSL_CTX_set_keylog_callback(native_context, [](const SSL*, const char *line) {
            std::cout<<"***"<<std::endl;
            Log::keylog(string(line));
        });
#else // ENABLE_SSL_KEYLOG
        Log::log_with_date_time("SSL KeyLog is not supported", Log::WARN);
#endif // ENABLE_SSL_KEYLOG
    }
}

void Service::hand_flash(){
    //std::cout<<"Service::hand_flash()"<<std::endl;
    std::string tmp = td->get_best();

    if(!tmp.empty()){
        if(!td->is_better(last)){
            last = tmp;
        }
    }
    timer_.expires_after(std::chrono::seconds(10));
    timer_.async_wait([this](boost::system::error_code){
        hand_flash();
    });
}


void  Service::start_icmp(std::vector<std::shared_ptr<pinger>> &services, boost::asio::io_context &io_context_){
    int identifier_num = 0;
    for (std::string str : config.icmp.multi_web) {
        std::shared_ptr <pinger> service = std::make_shared<pinger>(io_context_, str, identifier_num++);
        services.push_back(service);
    }
    io_context_.run();
}
void Service::run() {

    last =  config.remote_addr;
    if (config.icmp.enable_mutil_host){

        std::vector <std::shared_ptr<pinger>> services;
        boost::asio::io_context io_context_local;

        t = std::thread([&services,this,&io_context_local](){
            start_icmp(services,io_context_local);
        });
    }

    async_accept();

    tcp::endpoint local_endpoint = socket_acceptor.local_endpoint();
    string rt;
    if (config.run_type == Config::SERVER) {
        rt = "server";
    }
    else {
        rt = "client";
    }

    Log::log_with_date_time(string("trojan service (") + rt + ") started at " + local_endpoint.address().to_string() + ':' + to_string(local_endpoint.port()), Log::WARN);

    io_context.run();
    if (config.icmp.enable_mutil_host) t.join();

    Log::log_with_date_time("trojan service stopped", Log::WARN);
}

void Service::stop() {
    boost::system::error_code ec;
    socket_acceptor.cancel(ec);
    std::cout<<"exit0"<<std::endl;
    io_context.stop();
    exit(0);
}

void Service::async_accept() {

    shared_ptr<Session>session(nullptr);
    if (config.run_type == Config::SERVER) {
        session = make_shared<ServerSession>(config, io_context, ssl_context, plain_http_response);
    }
    else {
        session = make_shared<ClientSession>(config, io_context, ssl_context);
    }

    // socket_acceptor 绑定监听的是config中的local_addr和local_port
    // client为127.0.0.1：port， service为0.0.0.0：43
    socket_acceptor.async_accept(session->accept_socket(), [this, session](const boost::system::error_code error) {
        if (error == boost::asio::error::operation_aborted) {
            // got cancel signal, stop calling myself
            return;
        }
        if (!error) {
            boost::system::error_code ec;
            auto endpoint = session->accept_socket().remote_endpoint(ec);
            // client 时
            // endpoint是系统（浏览器）发送的请求，当有一个本地浏览器请求时，会进入该async_accept回调函数中
            // endpoint的值为127.0.0.1：[PORT]
            // 每个端口的请求都会调用一个session
            
            if (!ec) {

                Log::log_with_endpoint(endpoint, "incoming connection",Log::ALL);
                session->start(last);
                std::cout<<"                       *"<<last<<std::endl;
            }
        }
        async_accept();
    });
}


boost::asio::io_context &Service::service() {
    return io_context;
}

void Service::reload_cert() {
    if (config.run_type == Config::SERVER) {
        Log::log_with_date_time("reloading certificate and private key. . . ", Log::WARN);
        ssl_context.use_certificate_chain_file(config.ssl.cert);
        ssl_context.use_private_key_file(config.ssl.key, context::pem);
        boost::system::error_code ec;
        socket_acceptor.cancel(ec);
        async_accept();
        Log::log_with_date_time("certificate and private key reloaded", Log::WARN);
    } else {
        Log::log_with_date_time("cannot reload certificate and private key: wrong run_type", Log::ERROR);
    }
}
