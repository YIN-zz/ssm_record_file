package com.qf.controller;

import com.qf.pojo.User;
import com.qf.service.UserService;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.Subject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import javax.servlet.http.HttpSession;

/**
 * 2019/6/2817:32
 */
@Controller
public class UserController {

    final String USERNAMEEXP = "[a-zA-Z0-9_]{4,20}";
    final String PASSWORDEXP = "\\w{5,20}";
    final int FAIL = -1;

    @Autowired
    private UserService userService;
    @Autowired
    private SecurityManager securityManager;


    @RequestMapping(value = "loginPage")
    public String loginPage(){
        return "login";
    }
    @RequestMapping(value = "unauthorize")
    public String unauthorize(){
        return "unauthorize";
    }


  /*  @RequestMapping(value = "login", method = RequestMethod.POST)
    public String login(User user, HttpSession session){

        if(!user.getUsername().matches(USERNAMEEXP) && !user.getPassword().matches(PASSWORDEXP)){
            return "login";
        }

        if(user.getUsername() != "" && user.getPassword() != ""){
            if(userService.login(user) != null){
                session.setAttribute("user", userService.login(user));
                return "redirect:index";
            }else{
                return "login";
            }
        }else{
            return "login";
        }
    }*/
@RequestMapping(value = "'login",method = RequestMethod.POST)
  public  String login(User user,HttpSession session){
    SecurityUtils.setSecurityManager(securityManager);
    Subject subject = SecurityUtils.getSubject();
    UsernamePasswordToken usernamePasswordToken = new UsernamePasswordToken(user.getUsername(),user.getPassword());
    try{
        subject.login(usernamePasswordToken);
        if (subject.isAuthenticated()){
            session.setAttribute("user",user);
            return "redirect:index";
        }
    }catch (AuthenticationException e){
        System.out.println("登录失败");
    }

    return "login";
}

    @RequestMapping(value = "registerPage")
    public String registerPage(){
        return "register";
    }


    @RequestMapping(value = "register", method = RequestMethod.POST)
    public String register(User user){

        if(!user.getUsername().matches(USERNAMEEXP) && !user.getPassword().matches(PASSWORDEXP)){
            return "register";
        }

        if(userService.register(user) != FAIL){
            return "login";
        }else{
            return "register";
        }
    }





}
