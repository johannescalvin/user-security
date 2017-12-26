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
