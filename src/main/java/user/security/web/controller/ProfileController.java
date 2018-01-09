package user.security.web.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import user.security.annotation.AccessWithLoginUsername;
import user.security.annotation.HorizontalAuthority;
import user.security.domain.SysUser;
import user.security.repository.SysUserRepository;
import user.security.vo.SysUserVO;

import javax.annotation.Resource;

@RestController
@RequestMapping("/profile")
public class ProfileController {
    @Resource
    private SysUserRepository userRepository;

    @GetMapping("/{username}")
    @HorizontalAuthority
    public SysUserVO get(@PathVariable @AccessWithLoginUsername String username){
        return new SysUserVO(userRepository.findByName(username));
    }
}
