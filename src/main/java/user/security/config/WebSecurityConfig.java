package user.security.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import user.security.custom.LoginSuccessHandler;

import javax.annotation.Resource;


@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter{

    @Resource
    private LoginSuccessHandler loginSuccessHandler;

    // 定义了哪些URL路径应该被拦截
    @Override
    protected void configure(HttpSecurity http) throws Exception {
       http
               // “/“, “/home”允许所有人访问
               .authorizeRequests()
                    .antMatchers("/","/home").permitAll()
                    .anyRequest().authenticated()
                    .and()
               // ”/login”作为登录入口，也被允许访问
               .formLogin()
                    .loginPage("/login").permitAll()
                     .successHandler(loginSuccessHandler)
                    .and()
               .logout()
                    .permitAll()
                    .and()
               // 先禁止,否则commons-httpclient无法在POST方法中传递参数
               // 使用@RestController的post方法也无法使用@RequestBody注解
               .csrf()
                    .disable()
               // 禁止HTTP Basic认证方式
                .httpBasic().disable();

    }

    // 在内存中配置一个用户，admin/admin分别是用户名和密码，这个用户拥有USER角色
    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth
            .inMemoryAuthentication()
                .withUser("admin").password("password").roles("ADMIN")
                .and()
                .withUser("user").password("password").roles("USER");
    }
}