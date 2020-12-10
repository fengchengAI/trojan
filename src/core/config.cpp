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

#include "config.h"
#include <cstdlib>
#include <stdexcept>
#include <boost/property_tree/json_parser.hpp>
#include <openssl/evp.h>
using namespace std;
using namespace boost::property_tree;

void Config::load(const string &filename) {
    ptree tree;
    read_json(filename, tree);
    populate(tree);
}

void Config::populate(const string &JSON) {
    istringstream s(JSON);
    ptree tree;
    read_json(s, tree);
    populate(tree);
}

void Config::populate(const ptree &tree) {
    string rt = tree.get("run_type", string("client"));
    if (rt == "server") {
        run_type = SERVER;
    } else if (rt == "client") {
        run_type = CLIENT;
    } else {
        throw runtime_error("wrong run_type in config file");
    }
    local_addr = tree.get("local_addr", string());
    local_port = tree.get("local_port", uint16_t());
    remote_addr = tree.get("remote_addr", string());
    remote_port = tree.get("remote_port", uint16_t());


    map<string, string>().swap(password);  // 密文，明文
    if (tree.get_child_optional("password")) {
        for (auto& item: tree.get_child("password")) {
            string p = item.second.get_value<string>();
            password[SHA224(p)] = p;
        }
    }
    log_level = static_cast<Log::Level>(tree.get("log_level", 1));
    ssl.verify = tree.get("ssl.verify", true);
    ssl.verify_hostname = tree.get("ssl.verify_hostname", true);
    ssl.cert = tree.get("ssl.cert", string());
    ssl.key = tree.get("ssl.key", string());
    ssl.key_password = tree.get("ssl.key_password", string());
    ssl.cipher = tree.get("ssl.cipher", string());
    ssl.cipher_tls13 = tree.get("ssl.cipher_tls13", string());
    ssl.prefer_server_cipher = tree.get("ssl.prefer_server_cipher", true);
    ssl.sni = tree.get("ssl.sni", string());
    ssl.alpn = "";
    if (tree.get_child_optional("ssl.alpn")) {
        for (auto& item: tree.get_child("ssl.alpn")) {
            string proto = item.second.get_value<string>();
            ssl.alpn += (char)((unsigned char)(proto.length()));
            ssl.alpn += proto;
        }
    }
    map<string, uint16_t>().swap(ssl.alpn_port_override);
    if (tree.get_child_optional("ssl.alpn_port_override")) {
        for (auto& item: tree.get_child("ssl.alpn_port_override")) {
            ssl.alpn_port_override[item.first] = item.second.get_value<uint16_t>();
        }
    }
    ssl.reuse_session = tree.get("ssl.reuse_session", true);
    ssl.session_ticket = tree.get("ssl.session_ticket", false);
    ssl.session_timeout = tree.get("ssl.session_timeout", long(600));
    ssl.plain_http_response = tree.get("ssl.plain_http_response", string());
    ssl.curves = tree.get("ssl.curves", string());
    ssl.dhparam = tree.get("ssl.dhparam", string());
    tcp.prefer_ipv4 = tree.get("tcp.prefer_ipv4", false);
    tcp.no_delay = tree.get("tcp.no_delay", true);
    tcp.keep_alive = tree.get("tcp.keep_alive", true);
    tcp.reuse_port = tree.get("tcp.reuse_port", false);
    tcp.fast_open = tree.get("tcp.fast_open", false);
    tcp.fast_open_qlen = tree.get("tcp.fast_open_qlen", 20);

    icmp.enable_mutil_host = tree.get("icmp.enable_mutil_host",false);
    icmp.good_num = tree.get("icmp.MAX_NUM",3);
    icmp.sent_time = tree.get("icmp.SENT_RATE",5);
    icmp.time_out = tree.get("icmp.TIME_OUT",400);

    //这里是比作者多的，假设会有多个节点信息，就写在这里
    if (tree.get_child_optional("icmp.multi_web")) {
        for (auto& item: tree.get_child("icmp.multi_web")) {
            icmp.multi_web.push_back(item.second.get_value<string>());
        }
    }
    std::sort(icmp.multi_web.begin(),icmp.multi_web.end());
}

bool Config::sip003() {
    char *JSON = getenv("SS_PLUGIN_OPTIONS");
    if (JSON == nullptr) {
        return false;
    }
    populate(JSON);
    switch (run_type) {
        case SERVER:
            local_addr = getenv("SS_REMOTE_HOST");
            local_port = atoi(getenv("SS_REMOTE_PORT"));
            break;
        case CLIENT:
            break;
    }
    return true;
}

string Config::SHA224(const string &message) {  // 对密码进行加密
    uint8_t digest[EVP_MAX_MD_SIZE];
    char mdString[(EVP_MAX_MD_SIZE << 1) + 1];
    unsigned int digest_len;
    EVP_MD_CTX *ctx;
    if ((ctx = EVP_MD_CTX_new()) == nullptr) {
        throw runtime_error("could not create hash context");
    }
    if (!EVP_DigestInit_ex(ctx, EVP_sha224(), nullptr)) {
        EVP_MD_CTX_free(ctx);
        throw runtime_error("could not initialize hash context");
    }
    if (!EVP_DigestUpdate(ctx, message.c_str(), message.length())) {
        EVP_MD_CTX_free(ctx);
        throw runtime_error("could not update hash");
    }
    if (!EVP_DigestFinal_ex(ctx, digest, &digest_len)) {
        EVP_MD_CTX_free(ctx);
        throw runtime_error("could not output hash");
    }

    for (unsigned int i = 0; i < digest_len; ++i) {
        sprintf(mdString + (i << 1), "%02x", (unsigned int)digest[i]);
    }
    mdString[digest_len << 1] = '\0';
    EVP_MD_CTX_free(ctx);
    return string(mdString);
}
