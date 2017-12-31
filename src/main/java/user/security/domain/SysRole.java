package user.security.domain;

import org.hibernate.annotations.NotFound;
import org.hibernate.annotations.NotFoundAction;

import java.util.Date;
import java.util.Set;

import javax.persistence.*;

//角色表
@Entity
@Table(name="sys_role")
public class SysRole {
	@Id
	@GeneratedValue(strategy=GenerationType.IDENTITY)
	@Column (name="role_id",length=10)
	private Long id;

	@Column(name="name",length=100)
	private String name;//角色名称

    @ManyToMany(fetch = FetchType.LAZY,mappedBy = "sysRoles")
    @NotFound(action = NotFoundAction.IGNORE)
    // Spring security中最常见的授权操作不会用到 角色下属哪些用户; 故而应该使用懒加载
    // 该字段在调用时,需要特别注意: 某角色下的用户过多, 可能导致性能问题和异常; 调用时需谨慎鉴别
    private Set<SysUser> sysUsers;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }
	public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
	}

    public Set<SysUser> getSysUsers() {
        return sysUsers;
    }

    public void setSysUsers(Set<SysUser> sysUsers) {
        this.sysUsers = sysUsers;
    }

    @Override
    public String toString() {
        return "SysRole{" +
                "id=" + id +
                ", name='" + name + '\'' +
                '}';
    }
}