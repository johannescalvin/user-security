package user.security.aop;

import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.*;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.ReflectionUtils;
import user.security.annotation.AccessWithLoginUsername;


import java.lang.annotation.Annotation;
import java.lang.reflect.Method;

// 使用AOP检查被注解的参数
@Component
@Aspect
public class HorizontalAuthorityInterceptor {
    // 拦截 @HorizontalAuthority 修饰的方法
    @Pointcut("@annotation(user.security.annotation.HorizontalAuthority)")
    public void check(){

    }

    // @Before无法中止所拦截的方法的执行 故而使用@Around
    @Around("check()")
    public Object doBefore(ProceedingJoinPoint proceedingJoinPoint) throws Throwable  {
        Object target = proceedingJoinPoint.getTarget();
        Class<?> clazz = target.getClass();
        //拦截的方法名
		String methodName = proceedingJoinPoint.getSignature().getName();
        //通过反射获取对象注解的方法
		Method method = ReflectionUtils.findMethod(target.getClass(), methodName,String.class);
		// 获取该方法上的参数
        Object[] args = proceedingJoinPoint.getArgs();
        //获取该方法在参数上的注解，每个参数可以有多个注解，得到的是一个二维数组
		Annotation[][] parameterAnnotaions = method.getParameterAnnotations();
		for (int i = 0; i < parameterAnnotaions.length; i++){
		    // 单个参数上的注解
            Annotation[] oneParameterAnnotaions = parameterAnnotaions[i];
            for (int j = 0; j < oneParameterAnnotaions.length; j++){
                // 只有本人能获取
                if (oneParameterAnnotaions[j].annotationType() == AccessWithLoginUsername.class){
                    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
                    String name  = auth.getName(); // 当前登录用户
                    String msg = ((AccessWithLoginUsername)oneParameterAnnotaions[j]).msg();
                    if (!name.equals(args[i])){
                        throw new Exception(msg);
                    }
                }
            }
        }

        return proceedingJoinPoint.proceed(args);
    }
}
