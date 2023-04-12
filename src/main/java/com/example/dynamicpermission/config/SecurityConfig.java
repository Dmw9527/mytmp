package com.example.dynamicpermission.config;

import com.example.dynamicpermission.filter.MyUrlFilter;
import com.example.dynamicpermission.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    UserService userService;
    @Autowired
    MyAccessDecisionManager myAccessDecisionManager;
    @Autowired
    MyUrlFilter myUrlFilter;


    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userService);
    }


//    ※※※
//    @Override
//    public void configure(WebSecurity web) throws Exception {
//        //注意这个"/error"解决了状态码999的问题
//        //不过我们是基于URL的请求授权，因为url过滤器的机制问题，我们可以在数据库中的menu表中加上相关的资源（只要不配置路径）
//        web.ignoring().antMatchers("/index.html","/qaq/**","/abc.jpg","/img/bcd.png","/img/cde.jpg","/error");
//
//    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .withObjectPostProcessor(new ObjectPostProcessor<FilterSecurityInterceptor>() {
                    @Override
                    public <O extends FilterSecurityInterceptor> O postProcess(O object) {
                        object.setAccessDecisionManager(myAccessDecisionManager);
                        object.setSecurityMetadataSource(myUrlFilter);
                        return object;
                    }
                })
                .and()
                .formLogin()
                .loginProcessingUrl("/doLogin")//这个不配也行，但如果要用postman测试的话，最好还是配一下
                .permitAll()
                .and()
                .csrf().disable();
    }

}
