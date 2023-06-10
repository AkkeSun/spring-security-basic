package com.example.springsecuritybasic.config;

import com.example.springsecuritybasic.filter.CustomFilter;
import com.example.springsecuritybasic.handler.CustomAuthenticationFailureHandler;
import com.example.springsecuritybasic.handler.CustomAuthenticationSuccessHandler;
import com.example.springsecuritybasic.provider.CustomAuthenticationProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Order(1) // 기본 security 설정은 SecurityConfig 에서 하고 CustomSecurityConfig 는 커스텀 필터를 매핑해주는 역할로만 사용
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class CustomSecurityConfig extends WebSecurityConfigurerAdapter {

    private final CustomAuthenticationProvider customAuthenticationProvider;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) {
        auth.authenticationProvider(customAuthenticationProvider);
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.cors()
            .and()
            .csrf().disable();
        /*
            커스텀 필터를 사용하는 경우 CustomAuthenticationDetails 를 통해 추가적인 필드를 받는 경우
            커스텀 필터 내에서 CustomAuthenticationDetailsSource 를 통해 직접 추가 필드를 처리해주기 때문에
            .authenticationDetailsSource(authenticationDetailsSource) 를 설정할 필요가 없다
         */
        http.addFilterBefore(customFilter(), UsernamePasswordAuthenticationFilter.class);
    }


    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Bean
    public CustomFilter customFilter() throws Exception {
        CustomFilter customFilter = new CustomFilter();
        customFilter.setAuthenticationManager(authenticationManagerBean());
        // 핸들러 설정을 반드시 해주어야 합니다.
        customFilter.setAuthenticationSuccessHandler(new CustomAuthenticationSuccessHandler());
        customFilter.setAuthenticationFailureHandler(new CustomAuthenticationFailureHandler());
        return customFilter;
    }

}
