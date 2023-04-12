package com.example.dynamicpermission.filter;

import com.example.dynamicpermission.entity.Menu;
import com.example.dynamicpermission.entity.Role;
import com.example.dynamicpermission.service.MenuService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;

import java.util.Collection;
import java.util.List;


/**
 * <code color="yellow">Description :<BR></code>
 * 这个url过滤器会被引入到SecurityConfig中
 * Security中的一个核心类，用于为安全过滤器提供相关的元数据。这个类主要用于对Web请求进行过滤和授权，并可以基于不同的Web资源提供不同的安全性，例如HTTP资源、Spring
 * MVC控制器和方法等等。通过该类，我们可以获取到当前请求需要的安全元数据，包括云杉路径匹配器、授权决策管理器等。
 *
 * FilterInvocationSecurityMetadataSource的主要作用是从指定的资源中提取安全数据，包括资源需要的权限、角色、IP
 * 地址等信息，然后将这些元数据传递给其他的安全组件，比如AccessDecisionManager，来完成授权决策。在Spring
 * Security中，FilterInvocationSecurityMetadataSource是最关键的安全元数据提供者。<code></code>
 * 通常情况下，我们需要根据不同的URL路径提供不同的安全性。例如，对于访问/admin路径的请求，需要进行ROLE_ADMIN的授权，对于访问/user路径的请求，需要进行ROLE_USER
 * 的授权。在这种情况下，我们就可以通过FilterInvocationSecurityMetadataSource类来提供这些安全元数据，然后通过AccessDecisionManager来判断用户是否有权访问特定路径的资源。
 *
 * 总之，FilterInvocationSecurityMetadataSource是Spring Security提供的一个核心类，用于对Web请求进行过滤和授权，并提供不同资源的安全元数据，是实现Spring
 * Security授权机制的重要组成部分。
 *
 *
 * @FullPath [dynamic-permission] --- com.example.dynamicpermission.filter.MyUrlFilter
 * @Author Guo Jie
 */
@Component
public class MyUrlFilter implements FilterInvocationSecurityMetadataSource {

    @Autowired
    MenuService menuService;

    AntPathMatcher pathMatcher=new AntPathMatcher();

    /**
     * Description:
     * 返回的访问这个menu资源(url)需要的角色
     *
     * @param	object
     * 参数object实际上就是个FilterInvocation对象
     * @return	java.util.Collection<org.springframework.security.access.ConfigAttribute> –
     * return的集合就是解析完了url之后，返回的访问这个url需要的角色，当然，没有在我们menu里面的url，我们就默认设置个登录后访问！
    */
    @Override
    public Collection<ConfigAttribute> getAttributes(Object object) throws IllegalArgumentException {
        String url = ((FilterInvocation) object).getRequestUrl();
        List<Menu> allMenus = menuService.getAllMenus();
        for (Menu menu : allMenus) {
            if(pathMatcher.match(menu.getPattern(),url)){
                //匹配对上了，就看看你需要什么角色，查出需要的角色列表，返回即可。
                List<Role> roles = menu.getRoles();
                String[] roleArr = new String[roles.size()];
                for (int i = 0; i < roles.size(); i++) {
                    roleArr[i]=roles.get(i).getName();
                }
                return SecurityConfig.createList(roleArr);
            }
        }
        return SecurityConfig.createList("ROLE_login");
    }


    @Override
    public Collection<ConfigAttribute> getAllConfigAttributes() {
        return null;
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return true;
    }
}
