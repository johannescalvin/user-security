package user.security.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import user.security.domain.SysRole;

public interface SysRoleRepository  extends JpaRepository<SysRole,Long> {
    public SysRole findByName(String name);
}