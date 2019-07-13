package com.qf.service;


import com.qf.pojo.Leave;

import java.util.List;

public interface LeaveService {


    public int addLeave(Leave leave);
    //老师登录获取需要审批的请假条列表
    public List<Leave> leaveList(String username);

    //改变请假条状态
    public int updateLeave(int lid);

}
