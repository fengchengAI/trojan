//
// Created by root on 2020/10/21.
//

#ifndef TEST_TIME_DATA_HPP
#define TEST_TIME_DATA_HPP
class Service;

#include <string>
#include <vector>
#include <array>
class time_data{
// 保存最好的服务器名字，会在getMax被赋值
public:
    time_data(Service *service, int good_num, int data_size);

    void set(int, std::string, long);  // 提供给pinger修改data的接口
    void sort();
    bool is_better(std::string str);
    // 判断一个域名是否是ping最低前几的，icmp并不是选择ping值最小的，而是在前n个选择，比如前3个
    // 当上一次的域名在，在经过一次ping后，如果还是前3名，则不进行域名切换，

private:
    int good_num;
    Service *service;
    std::vector<std::pair<std::string, long> > data; // 记录所有节点的延迟信息，string对应域名，long对应ping值
};


#endif //TEST_TIME_DATA_HPP
