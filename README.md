# Spring Security练习
## 入门级Demo
### [参考来源](https://www.cnkirito.moe/categories/Spring-Security/)
### maven依赖
```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <groupId>info.johannescalvin</groupId>
    <artifactId>user-security</artifactId>
    <version>1.0-SNAPSHOT</version>

    <description>用户认证和授权(访问控制)</description>
    <packaging>jar</packaging>

    <dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-test</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security</artifactId>
        </dependency>
        <!-- https://mvnrepository.com/artifact/org.springframework.security/spring-security-test -->
        <dependency>
            <groupId>org.springframework.security</groupId>
            <artifactId>spring-security-test</artifactId>
            <scope>test</scope>
        </dependency>

        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-thymeleaf</artifactId>
        </dependency>


    </dependencies>

    <dependencyManagement>

        <dependencies>
            <!--若不引入spring-boot 的依赖管理 并指定版本，启动时 将报错-->
            <!-- https://mvnrepository.com/artifact/org.springframework.boot/spring-boot-dependencies -->
            <dependency>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-dependencies</artifactId>
                <version>1.5.9.RELEASE</version>
                <type>pom</type>
                <scope>import</scope>
            </dependency>



            <!-- https://mvnrepository.com/artifact/org.springframework.cloud/spring-cloud-dependencies -->
            <dependency>
                <groupId>org.springframework.cloud</groupId>
                <artifactId>spring-cloud-dependencies</artifactId>
                <version>Camden.SR7</version>
                <type>pom</type>
                <scope>import</scope>
            </dependency>


        </dependencies>
    </dependencyManagement>

    <build>
        <plugins>
            <!-- 添加 spring boot 的 maven插件支持-->
            <!--
                缺失该插件将导致 执行 mvn spring-boot:run 命令时 报错:的
                No plugin found for prefix 'spring-boot' in the current project and in the plugin groups
            -->
            <plugin>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-maven-plugin</artifactId>
                <!--缺少goal元素的话,mvn package 打包成的jar中将没有主清单属性 -->
                <executions>
                    <execution>
                        <goals>
                            <goal>repackage</goal>
                        </goals>
                    </execution>
                </executions>
            </plugin>

        </plugins>
        <resources>
            <resource>
                <directory>src/main/resources</directory>
                <includes>
                    <include>**/*</include>
                </includes>
            </resource>
        </resources>
    </build>

</project>
```
在src/main/resources/下创建 application.yaml
```yaml
spring:
  application:
    name: user-security-v1
server:
  port: 7005
```
### 前端页面
在src/main/resources/template/分别创建 home.html,login.html和welcome.html

home.html
```html
<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml" xmlns:th="http://www.thymeleaf.org">
<head>
    <title>Home Page</title>
</head>
<body>
<h1>Welcome!</h1>
<p>Click <a th:href="@{/welcome}">here</a> to see a greeting.</p>
</body>
</html>
```
login.html
```html
<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml" xmlns:th="http://www.thymeleaf.org">
<head>
    <title>Login Page </title>
</head>
<body>
<div th:if="${param.error}">
    Invalid username and password.
</div>
<div th:if="${param.logout}">
    You have been logged out.
</div>
<form th:action="@{/login}" method="post">
    <div><label> User Name : <input type="text" name="username"/> </label></div>
    <div><label> Password: <input type="password" name="password"/> </label></div>
    <div><input type="submit" value="Sign In"/></div>
</form>
</body>
</html>
```
welcome.html
```html
<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml" xmlns:th="http://www.thymeleaf.org">
<head>
    <title>Welcome Page</title>
</head>
<body>
<h1 th:inline="text">Hello [[${#httpServletRequest.remoteUser}]]!</h1>
<form th:action="@{/logout}" method="post">
    <input type="submit" value="Sign Out"/>
</form>
</body>
</html>
```

### 定义Controller 和 view 的映射关系,适用于不需要复杂权限控制的页面
在 src/main/java/user/security/config/下创建 MvcConfig.java
```java
package user.security.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

@Configuration
public class MvcConfig extends WebMvcConfigurerAdapter {
    @Override
    public void addViewControllers(ViewControllerRegistry registry) {
        registry.addViewController("/home").setViewName("home");
        registry.addViewController("/").setViewName("home");
        registry.addViewController("/welcome").setViewName("welcome");
        registry.addViewController("/login").setViewName("login");
    }
}
```
### 对Spring Security进行配置
在 src/main/java/user/security/config/下创建 WebSecurityConfig.java
```java
package user.security.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;


@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter{

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
                    .and()
               .logout()
                    .permitAll()
                    .and()
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
```

### 访问控制测试
参考[Spring Security官方手册](https://docs.spring.io/spring-security/site/docs/current/reference/htmlsingle/#test)进行测试用例编写

在src/test/java/user/security/access/下创建AccessTest.java模拟前端请求进行测试;分别针对 用户/密码正确，密码不正确和用户不存在三种情况下访问受限资源进行测试
```java
package user.security.access;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.*;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.*;

@RunWith(SpringJUnit4ClassRunner.class)
@WebAppConfiguration
@SpringBootTest
public class AccessTest {

    @Autowired
    private WebApplicationContext context;

    private MockMvc mockMvc;

    @Before
    public void setup(){

        mockMvc = MockMvcBuilders
                .webAppContextSetup(context)
                .apply(SecurityMockMvcConfigurers.springSecurity())
                .build();
    }

    // 用户/密码正确
    @Test
    public void accessWhenAuthenticated() throws Exception{
        mockMvc
                .perform(formLogin().user("admin").password("password"))
                .andExpect(authenticated());
    }

    // 密码错误
    @Test
    public void accessWithWrongPassword() throws Exception {
        mockMvc
                .perform(formLogin().user("admin").password("wrong_password"))
                .andExpect(unauthenticated());
    }

    // 用户不存在
    @Test
    public void accessWithNonExistUser() throws Exception {
        mockMvc
                .perform(formLogin().user("non_exist_admin").password("wrong_password"))
                .andExpect(unauthenticated());
    }

}

```
### 说明
- 这一部分内容参照[徐靖峰](https://www.cnkirito.moe/2017/09/20/spring-security-2/)给的例子;主要是在其基础上,使用MockMVC添加了测试用例;
- 如果把Spring Security 升级到5.0.0.RELEASE, 那么配置用户名和密码的方式需要改变，否则将报 将 ”Spring-Security升级到5.0.0.RELEASE版本后;采用内存授权模式添加用户;避免 There is no PasswordEncoder mapped for the id null“; 解决方式可以参考[官方例子](https://docs.spring.io/spring-security/site/docs/current/reference/htmlsingle/#jc-authentication-inmemory)

## 角色继承关系的简单实现
管理员用户应当拥有普通用户的权限,通过重写GlobalMethodSecurityConfiguration的accessDecisionManager方法来实现
### [参考来源](https://segmentfault.com/a/1190000012545851)
在src/main/java/user/security/config下创建RoleConfig.java,将角色间的层次关系硬编码进去
```java
package user.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.annotation.Jsr250Voter;
import org.springframework.security.access.expression.method.ExpressionBasedPreInvocationAdvice;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.access.prepost.PreInvocationAuthorizationAdviceVoter;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.access.vote.AuthenticatedVoter;
import org.springframework.security.access.vote.RoleHierarchyVoter;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.GlobalMethodSecurityConfiguration;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.ArrayList;
import java.util.List;

// 重写GlobalMethodSecurityConfiguration的accessDecisionManager方法，
// 给decisionVoters添加roleHierarchyVoter;
// 默认是使用RoleVoter，它不支持继承关系，这里替换为roleHierarchyVoter
// @see {@link https://segmentfault.com/a/1190000012545851}

@EnableGlobalMethodSecurity(
        securedEnabled = true,
        jsr250Enabled = true,
        prePostEnabled = true
)
@Configuration
public class RoleConfig extends GlobalMethodSecurityConfiguration {
    UsernamePasswordAuthenticationFilter usernamePasswordAuthenticationFilter;
    FilterSecurityInterceptor filterSecurityInterceptor;
    @Override
    protected AccessDecisionManager accessDecisionManager() {
        List<AccessDecisionVoter<? extends Object>> decisionVoters
                = new ArrayList<AccessDecisionVoter<? extends Object>>();
        ExpressionBasedPreInvocationAdvice expressionAdvice = new ExpressionBasedPreInvocationAdvice();
        expressionAdvice.setExpressionHandler(getExpressionHandler());
        decisionVoters
                .add(new PreInvocationAuthorizationAdviceVoter(expressionAdvice));
        decisionVoters.add(new Jsr250Voter());
        decisionVoters.add(roleHierarchyVoter());
        decisionVoters.add(new AuthenticatedVoter());
        return new AffirmativeBased(decisionVoters);
    }

    @Bean
    // 角色间的继承关系在授权阶段才会用上
    // 而不是在认证阶段
    public RoleHierarchyVoter roleHierarchyVoter() {
        return new RoleHierarchyVoter(roleHierarchy());
    }

    @Bean
    public RoleHierarchy roleHierarchy(){
        RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
        roleHierarchy.setHierarchy(
                "ROLE_ADMIN > ROLE_USER\n"+
                        " ROLE_USER > ROLE_ANONYMOUS\n"
        );
        return roleHierarchy;
    }
}
```
### 注意: 角色继承关系测试 
RoleHierarchyVoter起作用是在授权阶段，而不是在认证阶段; 即若以admin/password通过认证后，其anthorities中只有ROLE_ADMIN,而不会有继承而来ROLE_USER;
故而,测试代码只能写成这样;
```java_holder_method_tree
@Test
public void adminRoles() throws  Exception {
    mockMvc
            .perform(formLogin().user("admin").password("password"))
            .andExpect(authenticated().withRoles("ADMIN"));
}
```
如果要在此处就能测试角色继承关系，可以在创建内存用户时直接硬编码进去; 或者,不使用RoleHierarchyVoter,而在CustomUserDetails这种认证阶段上去做手脚
