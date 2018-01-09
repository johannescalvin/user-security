package user.security.vo;

import user.security.domain.SysRole;

import javax.validation.constraints.NotNull;

public class SysRoleVO {
    private String name;
    public SysRoleVO(@NotNull SysRole role){
        name = role.getName();
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }
}
