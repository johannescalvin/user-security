package user.security.custom;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import user.security.domain.SysUser;
import user.security.repository.SysUserRepository;

import javax.annotation.Resource;

@Component
public class CustomUserDetailsService implements UserDetailsService {
	@Resource  //业务服务类
	private SysUserRepository sysUserRepository;

    public CustomUserDetailsService(){
        super();
        System.out.println("CustomUserDetailsService 初始化成功");
    }



	@Override
	public UserDetails loadUserByUsername(String userName) throws UsernameNotFoundException {

        //SysUser对应数据库中的用户表，是最终存储用户和密码的表，可自定义
        //本例使用SysUser中的name作为用户名:
		SysUser user = sysUserRepository.findByName(userName);
		System.out.println("接收到的用户名 ： " + user);
		if (user == null) {
			throw new UsernameNotFoundException("UserName " + userName + " not found");
		}
		// SecurityUser实现UserDetails并将SysUser的name映射为username
		SecurityUser seu = new SecurityUser(user);
		return  seu;
	}

}