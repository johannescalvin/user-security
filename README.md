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

也可以使用commons-httpclient来模拟请求，从而完成测试。在src/test/java/user/security/access/下创建RoleHierarchyTest.java
```java
package user.security.access;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.NameValuePair;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.httpclient.methods.PostMethod;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class RoleHierarchyTest {
    private String loginUrl;
    private String adminPage;
    private String userPage;
    @Before
    public void setup(){

        // 登陆 Url
        loginUrl = "http://localhost:7005/login";
        // 管理员页面
        adminPage = "http://localhost:7005/admin";
        // 普通用户页面
    }
    // 管理员既可以访问管理员能访问的
    // 也能访问普通用户能访问的
    @Test
    public void admin() throws Exception{
        HttpClient httpClient = new HttpClient();
        PostMethod postMethod = postMethod = new PostMethod(loginUrl);
        // 设置登陆时要求的信息，用户名和密码
        NameValuePair[] data = { new NameValuePair("username", "admin"),
                new NameValuePair("password", "password") };
        postMethod.setRequestBody(data);
        int post_status = httpClient.executeMethod(postMethod);
//        assertEquals(200,post_status);

        GetMethod getMethod_admin = new GetMethod(adminPage);
        int get_status_admin = httpClient.executeMethod(getMethod_admin);
        assertEquals(200,get_status_admin);

        GetMethod getMethod_user = new GetMethod(adminPage);
        int get_status_user = httpClient.executeMethod(getMethod_user);
        assertEquals(200,get_status_user);
    }

}
```

## 根据登录用户跳转到不同的登录页面
网上找到的例子通过自定义实现AuthenticationSuccessHandler来满足根据用户角色跳转到不同登录页面的要求;但如此一来，使Spring Security失去了 SaveRequest相关功能，需要改进。

在 src/main/java/user/security/custom/下创建 LoginSuccessHandler.java
```java
package user.security.custom;


import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;

import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.util.StringUtils;


import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Set;

@Configuration
// 登录成功之后的处理
public class LoginSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    protected final Log logger = LogFactory.getLog(this.getClass());
    private RequestCache requestCache = new HttpSessionRequestCache();

    public LoginSuccessHandler() {
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        SavedRequest savedRequest = requestCache.getRequest(request, response);
        if (savedRequest == null) {

            Set<String> roles = AuthorityUtils.authorityListToSet(authentication.getAuthorities());

            String path = request.getContextPath() ;
            String basePath = request.getScheme()+"://"+request.getServerName()+":"+request.getServerPort()+path+"/";
            if (roles.contains("ROLE_ADMIN")){
                this.logger.debug("Redirecting to default page for  " +"ROLE_ADMIN : "+ basePath+"admin");
                response.sendRedirect(basePath+"admin");
                return ;
            }
            if (roles.contains("ROLE_USER")){
                this.logger.debug("Redirecting to default page for  " +"ROLE_USER : "+ basePath+"user");
                response.sendRedirect(basePath+"user");
                return;
            }

        } else {
            String targetUrlParameter = this.getTargetUrlParameter();
            if (!this.isAlwaysUseDefaultTargetUrl() && (targetUrlParameter == null || !StringUtils.hasText(request.getParameter(targetUrlParameter)))) {
                this.clearAuthenticationAttributes(request);
                String targetUrl = savedRequest.getRedirectUrl();
                this.logger.debug("Redirecting to DefaultSavedRequest Url: " + targetUrl);
                this.getRedirectStrategy().sendRedirect(request, response, targetUrl);
            } else {
                this.requestCache.removeRequest(request, response);
                super.onAuthenticationSuccess(request, response, authentication);

            }
        }

    }

    public void setRequestCache(RequestCache requestCache) {
        this.requestCache = requestCache;
    }

}
```
修改src/main/java/user/security/config/WebSecurityConfig.java中修改配置方法;指定登录成功的处理流程和禁止csrf保护
```java_holder_method_tree
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
```
### 测试
由于没搞懂MockMVC处理跳转测试，先使用commons-httpclient模拟请求。在src/test/java/user/security/access/下创建LoginSuccessHandler.java
```java
package user.security.access;

import org.apache.commons.httpclient.Header;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.httpclient.NameValuePair;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.httpclient.methods.PostMethod;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.*;

// 测试登录时页面跳转情况
// 缺陷: 服务地址硬编码
public class LoginSuccessHandlerTest {

    private String loginUrl;
    private String securedUrl;
    private String unSecuredUrl;
    private String adminPage;
    @Before
    public void setup(){

        // 登陆 Url
        loginUrl = "http://localhost:7005/login";
        // 需要授权才能访问的URL
        securedUrl = "http://localhost:7005/welcome";
        // 不需要授权就可访问的URL
        unSecuredUrl = "http://localhost:7005/home";
        adminPage = "http://localhost:7005/admin";
    }

    // 先访问受保护页面，然后登录
    // 认证成功并授权成功后,返回之前访问的受保护页面
    @Test
    public void redirectToSecuredPage() throws  Exception{
        HttpClient httpClient = new HttpClient();
        PostMethod postMethod = postMethod = new PostMethod(loginUrl);
        // 设置登陆时要求的信息，用户名和密码
        NameValuePair[] data = { new NameValuePair("username", "admin"),
                new NameValuePair("password", "password") };
        postMethod.setRequestBody(data);
        GetMethod getMethod = new GetMethod(securedUrl);
        httpClient.executeMethod(getMethod);
        int post_status = httpClient.executeMethod(postMethod);
        if (post_status == HttpStatus.SC_MOVED_TEMPORARILY){
            //读取新的URL地址
            Header header = postMethod.getResponseHeader("location");
            if (header != null) {
                String new_url = header.getValue();
                assertEquals(securedUrl,new_url);
            }
        }

    }

    // 先访问非受保护页面 然后登录
    // 认证成功后,跳转到管理员界面
    @Test
    public void redirectToAdminPage() throws  Exception{
        HttpClient httpClient = new HttpClient();
        PostMethod postMethod = postMethod = new PostMethod(loginUrl);
        // 设置登陆时要求的信息，用户名和密码
        NameValuePair[] data = { new NameValuePair("username", "admin"),
                new NameValuePair("password", "password") };
        postMethod.setRequestBody(data);
        GetMethod getMethod = new GetMethod(unSecuredUrl); // 先访问非受保护页面
        httpClient.executeMethod(getMethod);
        int post_status = httpClient.executeMethod(postMethod);
        if (post_status == HttpStatus.SC_MOVED_TEMPORARILY){
            //读取新的URL地址
            Header header = postMethod.getResponseHeader("location");
            if (header != null) {
                String new_url = header.getValue();

                assertEquals(adminPage,new_url);    // 跳转到管理员界面
            }
        }

    }
}

```
#### 注意
请求地址被硬编码.更改application.yaml文件好后记得同时更改本文件;

## 使用数据库存储存储用户/角色信息
### 更新maven依赖
```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-data-jpa</artifactId>
</dependency>

<dependency>
    <groupId>com.h2database</groupId>
    <artifactId>h2</artifactId>
</dependency>
```
### 更新application.yaml
```yaml
spring:
  application:
    name: user-security-v1
  jpa:
    hibernate:
      ddl-auto: create-drop
    generate-ddl: true
    show-sql: true
  datasource:
    platform: h2
    server:
server:
  port: 7005
```
暂时使用的是内存数据库;程序运行结束将自动删除数据,适用于开发测试阶段;正式环境需要更改为持久化存储

### 创建 POJO
在src/main/java/user/security/domain/下创建SysUser.java和SysRole.java,并利用JPA的@ManyToMany自动创建和维护用户-角色表

SysUser.java
```java
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
```

SysRole.java
```java
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
```
### 利用JpaRepository接口实现 repository/DAO 层
在src/main/java/user/security/repository/下创建 SysUserRepository.java 和 SysRoleRepository.java, 并实现自定义的查询方法

SysUserRepository.java
```java
package user.security.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import user.security.domain.SysUser;

public interface SysUserRepository extends JpaRepository<SysUser,Long> {
    public SysUser findById(Long id);
    public SysUser findByName(String name);
    public SysUser findByEmail(String email);
    public SysUser findByNameOrEmail(String name,String email);

}
```

SysRoleRepository.java
```java
package user.security.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import user.security.domain.SysRole;

public interface SysRoleRepository  extends JpaRepository<SysRole,Long> {
    public SysRole findByName(String name);
}
```
### 实现Service层
在 src/main/java/user/security/service/下创建 SysUserService.java 和 SysRoleService.java 以屏蔽 repository层暴露的多余接口;并在service层实现业务逻辑

SysUserService.java
```java
package user.security.service;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import user.security.domain.SysRole;
import user.security.domain.SysUser;
import user.security.repository.SysUserRepository;

import javax.annotation.Resource;
import javax.validation.constraints.NotNull;
import java.util.Date;
import java.util.HashSet;

@Service
public class SysUserService {
    @Resource
    private SysUserRepository sysUserRepository;
    @Resource
    private BCryptPasswordEncoder bCryptPasswordEncoder;
    @Resource
    private SysRoleService sysRoleService;

    public SysUser create(@NotNull String username, @NotNull String password){
       return create(username,password,null,sysRoleService.user());
    }

    public SysUser create(@NotNull String username,@NotNull String password,SysRole role){
        if(role == null || role.getId() == null){
            role = sysRoleService.user();
        }
        return create(username,password,null,role);
    }

    public SysUser create(@NotNull String username,@NotNull String password,String email,SysRole... roles){
        SysUser exist = sysUserRepository.findByName(username);
        if (exist != null){
            return null;
        }

        if (email != null) {
            exist = sysUserRepository.findByEmail(email);
            if (exist != null){
                return null;
            }
        }

        SysUser user = new SysUser();
        user.setName(username);
        user.setPassword(bCryptPasswordEncoder.encode(password));
        user.setEmail(email);
        user.setCreatedTime(new Date());

        // 默认注册为普通用户
        HashSet<SysRole> roleSet = new HashSet<SysRole>();
        if(roles == null){
            roles = new SysRole[1];
            roles[1] = sysRoleService.admin();
        }

        for (SysRole role : roles){
            if(role == null || role.getId() == null){
                continue;
            }
            roleSet.add(role);
        }

        user.setSysRoles(roleSet);

        sysUserRepository.save(user);

        return user;
    }

    public SysUser create(@NotNull String username,@NotNull String password, String email){
        return create(username,password,email,sysRoleService.user());
    }
}

```
#### 注意: 默认创建的用户均为 普通用户 (ROLE_USER)

SysRoleService.java
```java
package user.security.service;

import org.springframework.stereotype.Service;
import user.security.domain.SysRole;
import user.security.repository.SysRoleRepository;

import javax.annotation.PostConstruct;
import javax.annotation.Resource;
import javax.validation.constraints.NotNull;

@Service
public class SysRoleService {
    @Resource
    private SysRoleRepository sysRoleRepository;
    private SysRole user_role;
    private SysRole admin_role;

    @PostConstruct
    public void setup(){
        user_role = sysRoleRepository.findByName("ROLE_USER");
        admin_role = sysRoleRepository.findByName("ROLE_ADMIN");
        
        if (user_role == null){
            user_role = new SysRole();
            user_role.setName("ROLE_USER");

            sysRoleRepository.save(user_role);
        }

        if (admin_role == null) {
            admin_role = new SysRole();
            admin_role.setName("ROLE_ADMIN");

            sysRoleRepository.save(admin_role);
        }
    }

    public SysRole create(@NotNull String roleName){
        SysRole role = new SysRole();
        role.setName(roleName);
        sysRoleRepository.save(role);
        if (role.getId() != null){
            return role;
        }
        return null;
    }

    public SysRole user(){
        return user_role;
    }

    public SysRole admin(){
        return admin_role;
    }
}
```
#### 注意: 默认为应用创建两个角色 ROLE_ADMIN 和 ROLE_USER

### 为应用创建默认用户
为了保证之前写的测试用例仍能跑通,需要为应用创建两个默认账户 user/password/ROLE_USER 和 admin/password/ROLE_ADMIN

DevProfieConfig.java
```java
package user.security;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import user.security.service.SysRoleService;
import user.security.service.SysUserService;

import javax.annotation.PostConstruct;
import javax.annotation.Resource;

@Configuration
// @Profile(value = "dev")
public class DevProfieConfig {
    @Resource
    private SysRoleService roleService;
    @Resource
    private SysUserService userService;
    @PostConstruct
    public void setup(){
        // 默认创建具有ROLE_USER权限的用户
        userService.create("user","password");
        userService.create("admin","password",roleService.admin());
    }
}
```
### 修改配置类
修改WebSecurityConfig.java
```java_holder_method_tree
@Autowired
@Override
protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    auth
            .userDetailsService(customUserDetailsService)
            .passwordEncoder(bCryptPasswordEncoder());
}

@Bean
BCryptPasswordEncoder bCryptPasswordEncoder(){
    return new BCryptPasswordEncoder();
}
```
## 用户注册
### 前端页面
在 src/main/resources/templates/下创建register.html
```html
<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml" xmlns:th="http://www.thymeleaf.org">
<head>
    <meta charset="UTF-8"/>
    <title>SignUp Page</title>
</head>
<body>
<form th:action="@{/signup}" method="post">
    <div><label> User Name : <input type="text" name="username"/> </label></div>
    <div><label> Password: <input type="password" name="password"/> </label></div>
    <!--
    <div><label> confirm password: <input type="password" name="confirm"/> </label></div>
    -->
    <div><input type="submit" value="Sign Up"/></div>
</form>
</body>
</html>
```
### 控制器
在src/main/java/user/security/web/controller/下创建控制器 UserSignupController.java
```java
package user.security.web.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import user.security.domain.SysUser;
import user.security.service.SysUserService;

import javax.annotation.Resource;

@Controller
@RequestMapping("/signup")
public class UserSignupController {
    @Resource
    private SysUserService userService;

    @PostMapping
    public String signupByUserName(
            @RequestParam(value = "username", required = true) String username,
            @RequestParam(value = "password", required = true) String password){

        SysUser user = userService.create(username,password);

        if(user == null){
            return "error";
        }
        return "login"; // 由于创建用户之后可能涉及到根据用户角色进行跳转, 故而交给登录逻辑进行处理
    }
}
```

### 配置类
修改 MvcConfig.java
```java
package user.security.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
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
        registry.addViewController("/register").setViewName("register");
        registry.addViewController("/error").setViewName("error");
    }
}
```

修改WebSecurityConfig.java,使 /register和/signup 无需授权即可访问; 并禁止 csrf保护，以使POST方法可以传递参数到后端
```java_holder_method_tree
// 定义了哪些URL路径应该被拦截
@Override
protected void configure(HttpSecurity http) throws Exception {
   http
           // “/“, “/home”允许所有人访问
           .authorizeRequests()
                .antMatchers("/","/home","/register","/signup").permitAll()
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
```
### 测试
在src/test/java/user/security/access/下创建SignupControllerTest.java, 使用随机用户名注册一个账户，并登录，测试返回页面是否为/user
```java
package user.security.access;

import org.apache.commons.httpclient.Header;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.httpclient.NameValuePair;
import org.apache.commons.httpclient.methods.PostMethod;
import org.junit.Before;
import org.junit.Test;

import java.util.Random;

import static org.junit.Assert.assertEquals;

public class SignupControllerTest {
    private String signupUrl;
    private String loginUrl;
    private String adminPage;
    private String userPage;

    @Before
    public void setup(){

        // 登陆 Url
        loginUrl = "http://localhost:7005/login";
        // 管理员页面
        adminPage = "http://localhost:7005/admin";
        // 普通用户页面
        userPage = "http://localhost:7005/user";
        signupUrl =  "http://localhost:7005/signup";
    }
    @Test
    public void registerThenLogin() throws  Exception{
        HttpClient httpClient = new HttpClient();
        PostMethod postMethod = new PostMethod(signupUrl);
        // 设置登陆时要求的信息，用户名和密码
        String username = "username_"+ new Random().nextInt();
        NameValuePair[] data = { new NameValuePair("username", username),
                new NameValuePair("password", "password") };
        postMethod.setRequestBody(data);
        int post_status = httpClient.executeMethod(postMethod);
        assertEquals(200,post_status);

        PostMethod loginMethod = new PostMethod(signupUrl);
        // 设置登陆时要求的信息，用户名和密码
        NameValuePair[] user_password = { new NameValuePair("username", username),
                new NameValuePair("password", "password") };

        loginMethod.setRequestBody(user_password);
        int login_status = httpClient.executeMethod(loginMethod);
        if (login_status == HttpStatus.SC_MOVED_TEMPORARILY){
            //读取新的URL地址
            Header header = loginMethod.getResponseHeader("location");
            if (header != null) {
                String new_url = header.getValue();

                assertEquals(userPage,new_url);    // 跳转到管理员界面
            }
        }
    }
}

```

## 使用邮箱登录
修改src/main/java/user/security/custom/CustomUserDetailsService.java,使用name和Email两个字段进行查询,[查询结果必需唯一，否则将报NotUniqueResult异常]
```java_holder_method_tree
@Override
public UserDetails loadUserByUsername(String userName) throws UsernameNotFoundException {

    //SysUser对应数据库中的用户表，是最终存储用户和密码的表，可自定义
    //本例使用SysUser中的name作为用户名:
    SysUser user = sysUserRepository.findByNameOrEmail(userName,userName);
    System.out.println("接收到的用户名 ： " + user);
    if (user == null) {
        throw new UsernameNotFoundException("UserName " + userName + " not found");
    }
    // SecurityUser实现UserDetails并将SysUser的name映射为username
    SecurityUser seu = new SecurityUser(user);
    return  seu;
}
```
### 配置类
在src/main/java/user/security/下修改DevProfileConfig.java,创建默认账号时添加邮箱字段
```java_holder_method_tree
@PostConstruct
public void setup(){
    // 默认创建具有ROLE_USER权限的用户
    userService.create("user","password","user@exmaple.com");
    userService.create("admin","password","admin@example.com",roleService.admin());
}
```
### 测试
```java
package user.security.access;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;

@RunWith(SpringJUnit4ClassRunner.class)
@WebAppConfiguration
@ContextConfiguration
@SpringBootTest
public class LoginWithEmailTest {
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
    
    @Test
    public void loginWithEmail() throws Exception{
        mockMvc
                .perform(formLogin().user("admin@example.com").password("password"))
                .andExpect(authenticated());
    }
}

```