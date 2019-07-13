package com.qf.controller;

import com.qf.pojo.Leave;
import com.qf.pojo.User;
import com.qf.service.LeaveService;
import com.qf.service.UserService;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.HttpSession;
import java.util.List;

/**
 * 2019/6/2817:32
 */
@Controller
public class LeaveController {
    @Autowired
    private LeaveService leaveService;

    @RequiresPermissions(value = "user:add")
    @RequestMapping("/leave")
    public String leave(){

        return "leave";
    }
    @RequestMapping("/addLeave")
    public String addLeave(Leave leave,HttpSession session){
        User user = (User) session.getAttribute("user");
        leave.setUser(user);
        int i = leaveService.addLeave(leave);
        return "redirect:index";
    }

    @RequestMapping("/leaveList")
    public String leaveList(Model model,HttpSession session){
        User user = (User) session.getAttribute("user");
        String username = user.getUsername();
        List<Leave> leaveList = leaveService.leaveList(username);
        model.addAttribute("leaveList",leaveList);
        return "leave_list";
    }
    @RequestMapping("/updateLeave")
    @ResponseBody
    public String updateLeave(int lid){
        leaveService.updateLeave(lid);
        return "success";
    }

}
