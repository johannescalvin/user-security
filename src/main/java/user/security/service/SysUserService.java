package user.security.service;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import user.security.domain.SysRole;
import user.security.domain.SysUser;
import user.security.repository.SysUserRepository;

import javax.annotation.Resource;
import javax.validation.constraints.NotNull;
import java.util.Date;
import java.util.HashSet;

@Service
public class SysUserService {
    @Resource
    private SysUserRepository sysUserRepository;
    @Resource
    private BCryptPasswordEncoder bCryptPasswordEncoder;
    @Resource
    private SysRoleService sysRoleService;

    public SysUser create(@NotNull String username, @NotNull String password){
       return create(username,password,null,sysRoleService.user());
    }

    public SysUser create(@NotNull String username,@NotNull String password,SysRole role){
        if(role == null || role.getId() == null){
            role = sysRoleService.user();
        }
        return create(username,password,null,role);
    }

    public SysUser create(@NotNull String username,@NotNull String password,String email,SysRole... roles){
        SysUser exist = sysUserRepository.findByName(username);
        if (exist != null){
            return null;
        }

        if (email != null) {
            exist = sysUserRepository.findByEmail(email);
            if (exist != null){
                return null;
            }
        }

        SysUser user = new SysUser();
        user.setName(username);
        user.setPassword(bCryptPasswordEncoder.encode(password));
        user.setEmail(email);
        user.setCreatedTime(new Date());

        // 默认注册为普通用户
        HashSet<SysRole> roleSet = new HashSet<SysRole>();
        if(roles == null){
            roles = new SysRole[1];
            roles[1] = sysRoleService.admin();
        }

        for (SysRole role : roles){
            if(role == null || role.getId() == null){
                continue;
            }
            roleSet.add(role);
        }

        user.setSysRoles(roleSet);

        sysUserRepository.save(user);

        return user;
    }

    public SysUser create(@NotNull String username,@NotNull String password, String email){
        return create(username,password,email,sysRoleService.user());
    }
}
