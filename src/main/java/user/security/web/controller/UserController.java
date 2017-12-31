package user.security.web.controller;

import org.springframework.security.access.annotation.Secured;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class UserController {

    @GetMapping("/user")
    @Secured("ROLE_USER")
    public String userPage(){
        return "user";
    }

    @GetMapping("/admin")
    @Secured("ROLE_ADMIN")
    public String adminPage(){
        return "admin";
    }

}
