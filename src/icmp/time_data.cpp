//
// Created by root on 2020/10/21.
//
#include <algorithm>
#include "time_data.hpp"
#include <iostream>
#include "core/service.h"
time_data::time_data(Service *service_, int good_num_, int data_size): good_num(good_num_),service(service_){
    data.resize(data_size);
}

void time_data::sort()
{
    std::sort(data.begin(),data.end(),[](std::pair<std::string, long> a, std::pair<std::string, long> b){
        return a.second<b.second;
    });

    if(!is_better(service->get_web())){
        service->update(data.front().first);
    }
}


void time_data::set(int index, std::string str, long time) {
    data.at(index) = std::make_pair(str,time);
}
bool time_data::is_better(std::string str){
    for(int i = 0; i < good_num; i++){
        if (str==data.at(i).first)
            return true;
    }
    return false;
}