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
