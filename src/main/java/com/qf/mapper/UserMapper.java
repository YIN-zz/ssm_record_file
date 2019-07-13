package com.qf.mapper;


import com.qf.pojo.User;

public interface UserMapper {

    User getUser(User user);

    int addUser(User user);

    String getUsername(String username);

    String getPassword(String username);
}