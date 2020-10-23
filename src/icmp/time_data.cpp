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
void time_data::set_nums(int nums){
    data.resize(nums);
}
std::string time_data::get_best(){
    std::lock_guard<std::mutex> guard(mu);

    return best_service;
}
void time_data::set(int index, std::pair<std::string, long> data_) {
    data[index] = data_;
}
bool time_data::is_better(std::string str){
    for(int i = 0; i < MAX_NUM; i++){
        if (str==data.at(i).first)
            return true;
    }
    return false;
}