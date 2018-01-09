package user.security.vo;

import user.security.domain.SysRole;
import user.security.domain.SysUser;

import javax.validation.constraints.NotNull;
import java.util.HashSet;
import java.util.Set;

public class SysUserVO {
    private String name;
    private String email;
    private Set<SysRoleVO> roles;
    public SysUserVO(@NotNull SysUser user){
        name = user.getName();
        email = user.getEmail();
        roles = new HashSet<SysRoleVO>();
        Set<SysRole> roleSet = user.getSysRoles();
        for(SysRole role : roleSet){
            roles.add(new SysRoleVO(role));
        }
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public Set<SysRoleVO> getRoles() {
        return roles;
    }

    public void setRoles(Set<SysRoleVO> roles) {
        this.roles = roles;
    }
}
