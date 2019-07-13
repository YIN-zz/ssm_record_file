package com.qf.service.impl;

import com.qf.mapper.ProfileMapper;
import com.qf.pojo.Profile;
import com.qf.service.IndexService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * 2019/6/2820:52
 */
@Service
public class IndexServiceImpl implements IndexService {

    final int SUCCESS = 0;
    final int FAIL = -1;

    @Autowired
    private ProfileMapper profileMapper;

    @Override
    public List<Profile> getProfileList() {

        List<Profile> profiles = profileMapper.getProfileList();
        return profiles;
    }

    @Override
    public Profile getProfileById(int id) {
        return profileMapper.getProfileById(id);
    }

    @Override
    public boolean updateProfileById(Profile profile) {
        boolean flag;

        if(profileMapper.updateProfileById(profile) != FAIL){
            flag = true;
            return flag;
        }else{
            flag = false;
            return flag;
        }


    }

    @Override
    public boolean delProfileById(int id) {
        boolean flag;
        if(profileMapper.delProfileById(id) != FAIL){
            flag = true;
            return flag;
        }else{
            flag = false;
            return flag;
        }
    }

    @Override
    public boolean addProfile(Profile profile) {
        boolean flag;
        if(profileMapper.addProfile(profile) != FAIL){
            flag = true;
            return flag;
        }else{
            flag = false;
            return flag;
        }
    }
}
