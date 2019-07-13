package com.qf.service;

import com.qf.pojo.Profile;

import java.util.List;

public interface IndexService {

    List<Profile> getProfileList();

    Profile getProfileById(int id);

    boolean updateProfileById(Profile profile);

    boolean delProfileById(int id);

    boolean addProfile(Profile profile);
}
