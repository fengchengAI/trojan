//
// Created by root on 2020/10/21.
//
#include <algorithm>
#include <mutex>
#include "time_data.hpp"
#include <iostream>
std::mutex mu;


void time_data::sort() {
    std::sort(data.begin(),data.end(),[](std::pair<std::string, long> a, std::pair<std::string, long> b){
        return a.second<b.second;
    });
    best_service = data.front().first;
}
void time_data::init(int nums){
    data.resize(nums);
}
std::string time_data::get_best(){
    //std::lock_guard<std::mutex> guard(mu);
    return best_service;
}
void time_data::set(int index, std::string str, long  time) {
    data[index] = std::make_pair(str,time);
}
bool time_data::is_better(std::string str){
    for(int i = 0; i < good_num; i++){
        if (str==data.at(i).first)
            return true;
    }
    return false;
}