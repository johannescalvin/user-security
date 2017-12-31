package user.security.service;

import org.springframework.stereotype.Service;
import user.security.domain.SysRole;
import user.security.repository.SysRoleRepository;

import javax.annotation.PostConstruct;
import javax.annotation.Resource;
import javax.validation.constraints.NotNull;

@Service
public class SysRoleService {
    @Resource
    private SysRoleRepository sysRoleRepository;
    private SysRole user_role;
    private SysRole admin_role;

    @PostConstruct
    public void setup(){
        user_role = sysRoleRepository.findByName("ROLE_USER");
        admin_role = sysRoleRepository.findByName("ROLE_ADMIN");

        if (user_role == null){
            user_role = new SysRole();
            user_role.setName("ROLE_USER");

            sysRoleRepository.save(user_role);
        }

        if (admin_role == null) {
            admin_role = new SysRole();
            admin_role.setName("ROLE_ADMIN");

            sysRoleRepository.save(admin_role);
        }
    }

    public SysRole create(@NotNull String roleName){
        SysRole role = new SysRole();
        role.setName(roleName);
        sysRoleRepository.save(role);
        if (role.getId() != null){
            return role;
        }
        return null;
    }

    public SysRole user(){
        return user_role;
    }

    public SysRole admin(){
        return admin_role;
    }
}
