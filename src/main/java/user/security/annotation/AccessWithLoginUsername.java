package user.security.annotation;

import java.lang.annotation.*;

@Target(ElementType.PARAMETER) // 声明在形参列表中
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface AccessWithLoginUsername {
    String msg() default "you should only access your own data.";
}
