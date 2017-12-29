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
