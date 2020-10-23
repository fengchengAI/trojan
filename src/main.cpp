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

#include <cstdlib>
#include <unistd.h>  // 路径转化
#include <iostream>
#include <string>
#include <boost/asio/signal_set.hpp>
#include <boost/program_options.hpp>
#include <boost/version.hpp>
#include <openssl/opensslv.h>
#include <nlohmann/json.hpp>

#include "core/service.h"
#include "core/version.h"

using namespace std;
using namespace boost::asio;
namespace po = boost::program_options;
using json = nlohmann::json;


#ifndef DEFAULT_CONFIG
#define DEFAULT_CONFIG "config.json"
#endif // DEFAULT_CONFIG
// 这里是系统信号函数的处理，如当系统执行ctrl+c时，会触发相应的信号处理

string getAbsolutePath(string &parm){ // 这里主要是处理相对路径
    string root(getcwd(nullptr,0));
    if (parm.substr(0,2)=="./"){
        parm = parm.substr(2);
    }
    while(parm.find("../")!=string::npos && root.rfind('/')!=string::npos){
        parm.replace(0,3,"");

        auto it = root.rfind('/');
        root.replace(root.cbegin()+it,root.cend(),"");

    }
    return root+"/"+parm;

}

void signal_async_wait(signal_set &sig, Service &service, bool &restart) {
    sig.async_wait([&](const boost::system::error_code error, int signum) {
        if (error) {
            return;
        }
        Log::log_with_date_time("got signal: " + to_string(signum), Log::WARN);
        switch (signum) {
            case SIGINT:
                exit(0);
            case SIGTERM:
                service.stop();
                break;
            case SIGHUP:
                restart = true;
                service.stop();
                break;
            case SIGUSR1:
                service.reload_cert();
                signal_async_wait(sig, service, restart);
                break;
        }
    });
}

int main(int argc, const char *argv[]) {
    try {
        Log::log("Welcome to trojan " + Version::get_version(), Log::FATAL);
        string config_file;
        string log_file;
        string keylog_file;
        bool test;
        
        //选项描述器,其参数为该描述器的名字,描述当前的程序定义了哪些选项
        po::options_description desc("options");
        desc.add_options()
            ("config,c", po::value<string>(&config_file)->value_name("CONFIG"), "specify config file")
            ("help,h", "print help message")
            ("keylog,k", po::value<string>(&keylog_file)->value_name("KEYLOG"), "specify keylog file location (OpenSSL >= 1.1.1)")
            ("log,l", po::value<string>(&log_file)->value_name("LOG"), "specify log file location")
            ("test,t", po::bool_switch(&test), "test config file")
            ("version,v", "print version and build info")
        ;


        po::variables_map vm;   //容器,用于存储解析后的选项
        po::store(po::parse_command_line(argc, argv, desc), vm);
        po::notify(vm);
        if (vm.count("help")) {
            Log::log(string("usage: ") + argv[0] + " [-htv] [-l LOG] [-k KEYLOG] [[-c] CONFIG]", Log::FATAL);
            cerr << desc;
            exit(EXIT_SUCCESS);
        }
        if (vm.count("version")) {
            Log::log(string("Boost ") + BOOST_LIB_VERSION + ", " + OpenSSL_version(OPENSSL_VERSION), Log::FATAL);

#ifdef TCP_FASTOPEN
            Log::log(" [Enabled] TCP_FASTOPEN Support", Log::FATAL);
#else // TCP_FASTOPEN
            Log::log("[Disabled] TCP_FASTOPEN Support", Log::FATAL);
#endif // TCP_FASTOPEN
#ifdef TCP_FASTOPEN_CONNECT
            Log::log(" [Enabled] TCP_FASTOPEN_CONNECT Support", Log::FATAL);
#else // TCP_FASTOPEN_CONNECT
            Log::log("[Disabled] TCP_FASTOPEN_CONNECT Support", Log::FATAL);
#endif // TCP_FASTOPEN_CONNECT
#if ENABLE_SSL_KEYLOG
            Log::log(" [Enabled] SSL KeyLog Support", Log::FATAL);
#else // ENABLE_SSL_KEYLOG
            Log::log("[Disabled] SSL KeyLog Support", Log::FATAL);
#endif // ENABLE_SSL_KEYLOG

#ifdef ENABLE_TLS13_CIPHERSUITES
            Log::log(" [Enabled] TLS1.3 Ciphersuites Support", Log::FATAL);
#else // ENABLE_TLS13_CIPHERSUITES
            Log::log("[Disabled] TLS1.3 Ciphersuites Support", Log::FATAL);
#endif // ENABLE_TLS13_CIPHERSUITES
#ifdef ENABLE_REUSE_PORT
            Log::log(" [Enabled] TCP Port Reuse Support", Log::FATAL);
#else // ENABLE_REUSE_PORT
            Log::log("[Disabled] TCP Port Reuse Support", Log::FATAL);
#endif // ENABLE_REUSE_PORT
            Log::log("OpenSSL Information", Log::FATAL);
            if (OpenSSL_version_num() != OPENSSL_VERSION_NUMBER) {
                Log::log(string("\tCompile-time Version: ") + OPENSSL_VERSION_TEXT, Log::FATAL);
            }
            Log::log(string("\tBuild Flags: ") + OpenSSL_version(OPENSSL_CFLAGS), Log::FATAL);
            exit(EXIT_SUCCESS);
        }
        if (vm.count("log")) {
            log_file = getAbsolutePath(log_file);
            Log::redirect(log_file);
        }
        if (vm.count("keylog")) {
            Log::redirect_keylog(keylog_file);
        }
        
        bool restart;
        Config config;

        /*
        std::ifstream i("/home/feng/Github/CLionProjects/Test_ICMP/gui-config.json");
        json j;
        i >> j;

        for (auto site : j["configs"]){
            config.multi_web.push_back(site["server"]);
        }
        */
        do {
            restart = false;
            if (config.sip003()) { //SIP003 是SS的一个配置或者协议
                Log::log_with_date_time("SIP003 is loaded", Log::WARN);
            } else {
                if (vm.count("config")){
                    config.load(getAbsolutePath(config_file));
                }
                 else{
                    config.load(DEFAULT_CONFIG);
                 }
            }
            Service service(config, test);
            // 如果test为真，事实上并没有做什么，仅仅是测试程序没有报错
            // 生产中应该false

            if (test) {
                Log::log("The config file looks good.", Log::OFF);
                exit(EXIT_SUCCESS);
            }
            signal_set sig(service.service());
            sig.add(SIGINT);
            sig.add(SIGTERM);
            sig.add(SIGHUP);
            sig.add(SIGUSR1);
            signal_async_wait(sig, service, restart);
            service.run();
            if (restart) {
                Log::log_with_date_time("trojan service restarting. . . ", Log::WARN);
            }
        } while (restart);
        Log::stop();
        exit(EXIT_SUCCESS);
    } catch (const exception &e) {
        Log::log_with_date_time(string("fatal: ") + e.what(), Log::FATAL);
        Log::log_with_date_time("exiting. . . ", Log::FATAL);
        Log::stop();
        exit(EXIT_FAILURE);
    }
}
