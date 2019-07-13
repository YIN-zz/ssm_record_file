package com.qf.mapper;


import com.qf.pojo.Profile;

import java.util.List;

public interface ProfileMapper {

    List<Profile> getProfileList();

    Profile getProfileById(int id);

    int updateProfileById(Profile profile);

    int delProfileById(int id);

    int addProfile(Profile profile);



}