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
        userPage = "http://localhost:7005/user";
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

        GetMethod getMethod_user = new GetMethod(userPage);
        int get_status_user = httpClient.executeMethod(getMethod_user);
        assertEquals(200,get_status_user);
    }

}
