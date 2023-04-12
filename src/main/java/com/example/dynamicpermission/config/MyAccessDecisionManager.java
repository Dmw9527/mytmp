package com.example.dynamicpermission.config;

import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.Collection;

/**
 * @ClassName MyAccessDecisionManager
 * @Author Guo Jie
 * @Description :这个决策管理器会被引入到SecurityConfig中
 * @Related-Explanation :AccessDecisionManager是Spring Security中的一个重要类，用于实现权限决策的逻辑。在Spring
 * Security中，AccessDecisionManager被用于判断用户是否有权访问特定的资源（如URL、方法等）。当用户访问需要授权的资源时，Spring
 * Security会调用AccessDecisionManager来进行授权决策，由该类来决定用户是否有权访问该资源。
 */
@Component
public class MyAccessDecisionManager implements AccessDecisionManager {

    /**
     * <code color="yellow">Description</code>:
     * 这个方法允许你抛异常对吧，如果抛出异常，证明请求是要终止的！
     * 如果没有抛出异常，证明是ok的
     * 第一个参数能让你知道当前用户有哪些角色，第三个参数能让你知道用户请求的url需要哪些角色
     *
     * @param    authentication 我们登陆成功后其实也有一个这个参数，这个参数里保存了当前登录的用户信息
     * @param    object 个FilterInvocation对象，这个对象用来获取当前请求的信息即与url相关的
     * @param    configAttributes 其实放的就是 url需要的角色列表，就是配置解析url过滤器时的那个方法的返回值啊
     */

    @Override
    public void decide(Authentication authentication, Object object, Collection<ConfigAttribute> configAttributes) throws AccessDeniedException, InsufficientAuthenticationException {
        //从需要的角色列表里一个个拿出角色，一个个遍历，当然有可能是我们设置的默认的ROLE_login
        for (ConfigAttribute configAttribute : configAttributes) {
            if ("ROLE_login".equals(configAttribute.getAttribute())) {
                //Anonymous 匿名的，不记名的
                if (authentication instanceof AnonymousAuthenticationToken) {
                    throw new AccessDeniedException("匿名用户,非法请求");
                } else {
                    return;
                }
            }
            //出了上面这个if,就说明用户访问的资源需要的角色不是登录之后就行的（ROLE_login） 而是我们数据库里的正经角色
            //我们有的角色
            Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();

            //那如果你需要的角色我正好有，那不是就ok，现在就来遍历
            for (GrantedAuthority authority : authorities) {
                if (authority.getAuthority().equals(configAttribute.getAttribute())) {
                    return;
                }
            }
        }
        //如果这个for都执行完了，程序还没有return，就说明用户不具备访问资源需要的菜单
        throw new AccessDeniedException("用户未拥有访问资源对应的角色,非法请求");
    }

    @Override
    public boolean supports(ConfigAttribute attribute) {
        return true;
    }


    @Override
    public boolean supports(Class<?> clazz) {
        return true;
    }


}
