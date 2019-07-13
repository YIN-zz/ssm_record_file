package com.qf.mapper;


import com.qf.pojo.Leave;
import com.qf.pojo.Profile;

import java.util.List;

public interface LeaveMapper {

    public int addLeave(Leave leave);
    //老师登录获取需要审批的请假条列表
    public List<Leave> leaveList(List<String> idList);

    //改变请假条状态
    public int updateLeave(int lid);


}