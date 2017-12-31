package user.security.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import user.security.domain.SysUser;

public interface SysUserRepository extends JpaRepository<SysUser,Long> {
    public SysUser findById(Long id);
    public SysUser findByName(String name);
    public SysUser findByEmail(String email);
    public SysUser findByNameOrEmail(String name,String email);

}
