package user.security.annotation;

import java.lang.annotation.*;

// 水平权限检查注解
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface HorizontalAuthority {

}
