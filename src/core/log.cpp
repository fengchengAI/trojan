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

#include "log.h"
#include <cstring>
#include <cerrno>
#include <stdexcept>
#include <iostream>
#include <string>
#include <boost/date_time/posix_time/posix_time_io.hpp>
using namespace std;
using namespace boost::posix_time;
using namespace boost::asio::ip;

#ifndef DEFAULT_LOG_PATH
#define DEFAULT_LOG_PATH "log/trojan.log"
#endif

Log::Level Log::level(INFO);


static const array<string,6> name = {"ALL","INFO","WARN","ERROR","FATAL","OFF"};
ofstream Log::output(DEFAULT_LOG_PATH,ios_base::out|ios_base::app);
ofstream Log::keyoutput;

void Log::log(const string &message, Level level) {
    #ifdef ENABLE_LOG
        if (level >= Log::level) {
            cout<<message<<endl;
            if (output.is_open())
                output<<message<<endl;
            else cout<<"Open log file failed"<<endl;
        }
    #endif
}

void Log::keylog(const string &message) {
#ifdef ENABLE_SSL_KEYLOG

    if (keyoutput.is_open())
            keyoutput<<message<<endl;
        else keyoutput<<"Open log file failed"<<endl;

#endif
}

void Log::log_with_date_time(const string &message, Level level) {

    #ifdef ENABLE_LOG
        time_t t = time(nullptr);
	    char ch[64] = {0};
	    strftime(ch, sizeof(ch) - 1, "%Y-%m-%d %H:%M:%S", localtime(&t));
        string level_string = "[" + name[level] + "] ";
        string tmp_data = string(ch);
        log(tmp_data + level_string + message, level);
    #endif

}

void Log::log_with_endpoint(const tcp::endpoint &endpoint, const string &message, Level level) {

    #ifdef ENABLE_LOG
        log_with_date_time(endpoint.address().to_string() + ':' + to_string(endpoint.port()) + ' ' + message, level);
    #endif

}

void Log::stop(){
    if (output.is_open()) {
        output.close();
    }
    if (keyoutput.is_open()) {
        keyoutput.close();
    }
}

void Log::redirect(const string &filename) {

    ofstream tmp(filename,ios_base::out|ios_base::app);
    if (!tmp.is_open()) {
        throw runtime_error(filename + ": " + strerror(errno));
    }
    if (output.is_open()) {
        output.close();
    }
    output = move(tmp);
}

void Log::redirect_keylog(const string &filename) {

#ifdef ENABLE_SSL_KEYLOG

    ofstream tmp(filename,ios_base::out|ios_base::app);
    if (!tmp.is_open()) {
        throw runtime_error(filename + ": " + strerror(errno));
    }
    if (keyoutput.is_open()) {
        keyoutput.close();
    }
    keyoutput = move(tmp);
#endif
}
bool Log::keylogOpen(){
    return keyoutput.is_open();
}
