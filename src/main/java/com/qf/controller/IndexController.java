package com.qf.controller;

import com.github.pagehelper.PageHelper;
import com.github.pagehelper.PageInfo;
import com.qf.pojo.Profile;
import com.qf.service.IndexService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * 2019/6/2820:30
 */

@Controller
public class IndexController {

    final int PAGE_SIZE = 2;

    @Autowired
    private IndexService indexService;

    @RequestMapping(value = "index")
    public String index(Model model, @RequestParam(defaultValue = "1")int pageNum, HttpSession session){

        if(session.getAttribute("user") == null){
            return "redirect:loginPage";
        }

        PageHelper.startPage(pageNum,PAGE_SIZE);

        List<Profile> profileList = indexService.getProfileList();

        PageInfo pageInfo = new PageInfo(profileList);


        model.addAttribute("pageInfo", pageInfo);


        return "index";

    }

    @RequestMapping(value = "detail")
    public ModelAndView detail(int id, HttpSession session){

        ModelAndView modelAndView = new ModelAndView();

        if(session.getAttribute("user") == null){

            modelAndView.setViewName("redirect:loginPage");

            return modelAndView;

        }else{
            Profile profile = indexService.getProfileById(id);


            modelAndView.setViewName("detail");


            modelAndView.addObject("profile", profile);

            return modelAndView;
        }

    }

    @RequestMapping(value = "alterPage")
    public String alterPage(Map<String,Object> map, int id, HttpSession session){

        if(session.getAttribute("user") == null){
            return "redirect:loginPage";
        }

        Profile profile = indexService.getProfileById(id);
        map.put("profile", profile);
        return "alter";
    }

    final String PNG = "image/png";
    final String GIF = "image/gif";
    final String JPG = "image/jpg";
    final String JPEG = "image/jpeg";

    @RequestMapping(value = "alter", method = RequestMethod.POST)
    public String alter(MultipartFile file, Profile profile,
                        HttpServletRequest request,
                        HttpSession session) throws IOException {

        if(session.getAttribute("user") == null){
            return "redirect:loginPage";
        }

        if(!file.getOriginalFilename().equals("")){

            if(file.getContentType().equals(PNG) ||
                    file.getContentType().equals(GIF) ||
                    file.getContentType().equals(JPG) ||
                    file.getContentType().equals(JPEG)){

                String filename = file.getOriginalFilename();

                String realPath =
                        request.getSession().getServletContext().getRealPath("/img/" + profile.getId());

                File newFile = new File(realPath);

                if(!newFile.exists()){
                    newFile.mkdirs();
                }

                File downFile = new File(newFile, filename);

                file.transferTo(downFile);

                profile.setPicture("/img/" + profile.getId() + "/" + filename);
            }else{

                return "forward:alterPage?id=" + profile.getId();

            }
        }

        if(indexService.updateProfileById(profile)){
            return "redirect:index";
        }else{
            return "forward:alterPage?id=" + profile.getId();
        }

    }

    @RequestMapping(value = "exit")
    public String exit(HttpSession session){
        session.removeAttribute("user");
        return "redirect:loginPage";
    }

    @RequestMapping(value = "del/{id}", produces = "application/json;charset=utf-8",
            method = RequestMethod.DELETE)
    @ResponseBody
    public String del(@PathVariable int id){
        indexService.delProfileById(id);
        List<String> list = new ArrayList<String>();
        list.add("success");
        list.add("qianfeng");
        return "success";
    }



    /*@RequestMapping(value = "add", method = RequestMethod.POST)
    public String addProfile(Profile profile){
        if(indexService.addProfile(profile)){
            return "redirect:index";
        }else{
            return "add";
        }
    }*/
}











