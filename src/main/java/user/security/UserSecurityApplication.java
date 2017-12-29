package user.security;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@SpringBootApplication
public class UserSecurityApplication {
    UsernamePasswordAuthenticationFilter filter;
    public static void main(String[] args) {
        SpringApplication.run(UserSecurityApplication.class);
    }
}