package com.qf.service.impl;

import com.qf.mapper.UserMapper;
import com.qf.pojo.User;
import com.qf.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 * 2019/6/2817:20
 */
@Service
public class UserServiceImpl implements UserService {

    @Autowired
    private UserMapper userMapper;

    final int SUCCESS = 0;
    final int FAIL = -1;


    @Override
    public User login(User user) {

       return userMapper.getUser(user);

    }

    @Override
    public int register(User user) {

        if(userMapper.getUser(user) == null && userMapper.getUsername(user.getUsername()) == null){
            if(userMapper.addUser(user) != FAIL){
                return SUCCESS;
            }else{
                return FAIL;
            }
        }else{
            return FAIL;
        }

    }

    @Override
    public String getPassword(String username) {
        return userMapper.getPassword(username);
    }

}
