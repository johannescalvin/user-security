package user.security.domain;

import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import javax.persistence.*;

@Entity
@Table(name = "sys_user")
public class SysUser implements java.io.Serializable {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "user_id", unique = true, nullable = false)
    private Long id;
    @Column(name = "name", length = 120)
    private String name; //用户名
    @Column(name = "email", length = 50)
    private String email;//用户邮箱
    @Column(name = "password", length = 120)
    private String password;//用户密码

    @Temporal(TemporalType.DATE)
    @Column(name = "created_time", length = 10)
    private Date createdTime;//时间

    // 将自动创建表 sys_user_role(用户角色表) 来维护SysUser和SysRole之间的多对多联系
    // user_id 和 role_id 分别是 sys_user表 和 sys_role表 的主键
    // CascadeType 定义了级联操作
    // FetchType.EAGER：急加载，加载一个实体时，定义急加载的属性会立即从数据库中加载
    // 在Spring Security授权操作都会用到用户的角色属性,故适用于 急加载
    @ManyToMany(cascade = {CascadeType.MERGE,CascadeType.REFRESH},fetch = FetchType.EAGER)
    @JoinTable(name = "sys_user_role",
            joinColumns = {@JoinColumn(name = "user_id")},
            inverseJoinColumns = {@JoinColumn(name = "role_id")})
    private Set<SysRole> sysRoles = new HashSet<SysRole>(0);// 所对应的角色集合

    public SysUser() {
    }

    public SysUser(String name, String email, String password, Date createdTime, Set<SysRole> sysRoles) {
        this.name = name;
        this.email = email;
        this.password = password;
        this.createdTime = createdTime;
        this.sysRoles = sysRoles;
    }


    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getName() {
        return this.name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getEmail() {
        return this.email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return this.password;
    }

    public void setPassword(String password) {
        this.password = password;
    }


    public Date getCreatedTime() {
        return createdTime;
    }

    public void setCreatedTime(Date createdTime) {
        this.createdTime = createdTime;
    }

    public Set<SysRole> getSysRoles() {
        return this.sysRoles;
    }

    public void setSysRoles(Set<SysRole> sysRoles) {
        this.sysRoles = sysRoles;
    }

    @Override
    public String toString() {
        return "SysUser{" +
                "id=" + id +
                ", name='" + name + '\'' +
                ", email='" + email + '\'' +
                ", password='" + password + '\'' +
                ", createdTime=" + createdTime +
                ", SysRoles= [" +role2String()+ "]"+
                '}';
    }

    private String role2String(){
        if (sysRoles == null || sysRoles.isEmpty()){
            return " ";
        }
        String info = "";
        for (SysRole role : sysRoles){
            info += role.getName()+",";
        }
        info = info.substring(0,info.length()-1);
        return info;
    }
}