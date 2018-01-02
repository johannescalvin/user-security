package user.security;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import user.security.service.SysRoleService;
import user.security.service.SysUserService;

import javax.annotation.PostConstruct;
import javax.annotation.Resource;

@Configuration
// @Profile(value = "dev")
public class DevProfieConfig {
    @Resource
    private SysRoleService roleService;
    @Resource
    private SysUserService userService;
    @PostConstruct
    public void setup(){
        // 默认创建具有ROLE_USER权限的用户
        userService.create("user","password","user@exmaple.com");
        userService.create("admin","password","admin@example.com",roleService.admin());
    }
}
