package user.security.custom;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Set;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import user.security.domain.SysRole;
import user.security.domain.SysUser;


public class SecurityUser extends SysUser implements UserDetails {
	private static final long serialVersionUID = 1L;

	public SecurityUser(SysUser suser) {
		if (suser != null) {
			this.setId(suser.getId());
			this.setName(suser.getName());
			this.setEmail(suser.getEmail());
			this.setPassword(suser.getPassword());
			this.setCreatedTime(suser.getCreatedTime());
			this.setSysRoles(suser.getSysRoles());
		}
	}

	@Override
	public String getPassword () {
		return super.getPassword();
	}

	@Override
	public String getUsername () {
		return super.getName();
	}

	@Override
	public boolean isAccountNonExpired () {
		return true;
	}

	@Override
	public boolean isAccountNonLocked () {
		return true;
	}

	@Override
	public boolean isCredentialsNonExpired () {
		return true;
	}

	@Override
	public boolean isEnabled () {
		return true;
	}


	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {

		Collection<GrantedAuthority> authorities = new ArrayList<>();
		Set<SysRole> userRoles = this.getSysRoles();

		if (userRoles != null) {
			for (SysRole role : userRoles) {
				SimpleGrantedAuthority authority = new SimpleGrantedAuthority(role.getName());
				authorities.add(authority);
			}
		}
		return authorities;
	}
}