package com.qf.service;


import com.qf.pojo.User;

public interface UserService {

    User login(User user);

    int register(User user);

    String getPassword(String username);

}
