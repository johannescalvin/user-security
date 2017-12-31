package user.security.web.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import user.security.domain.SysUser;
import user.security.service.SysUserService;

import javax.annotation.Resource;

@Controller
@RequestMapping("/signup")
public class UserSignupController {
    @Resource
    private SysUserService userService;

    @PostMapping
    public String signupByUserName(
            @RequestParam(value = "username", required = true) String username,
            @RequestParam(value = "password", required = true) String password){

        SysUser user = userService.create(username,password);

        if(user == null){
            return "error";
        }
        return "login"; // 由于创建用户之后可能涉及到根据用户角色进行跳转, 故而交给登录逻辑进行处理
    }
}
