package com.example.springsecuritybasic.config;

import com.example.springsecuritybasic.authenticationDetails.CustomAuthenticationDetailsSource;
import com.example.springsecuritybasic.provider.CustomAuthenticationProvider;
import com.example.springsecuritybasic.service.CustomUserDetailsService;
import java.io.IOException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.AccessDeniedHandler;

@Order(0)
@Configuration
@EnableWebSecurity // 웹 보안 활성화
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final CustomUserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;
    private final CustomAuthenticationDetailsSource authenticationDetailsSource;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder);
       // auth.authenticationProvider(customAuthenticationProvider());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        /**************************************
         *               인가 정책
         **************************************/
        http
            // 순서 : 1. 전체 허용, 2. 아래로 갈수록 권한이 넓어지도록 설정
            .authorizeRequests()
            .antMatchers("/loginPage", "/login-process", "/loginFailed", "/customLogin").permitAll()
            .antMatchers("/test1/user").hasRole("USER")
            .antMatchers("/test1/admin/pay").hasRole("ADMIN")
            .antMatchers("/test1/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
            .anyRequest().authenticated() // 나머지 요청은 인증받으면 누구나 접근 가능
        //  .antMatchers("/test/ip").hasIpAddress("127.0.0.1")
        //  .mvcMatchers(HttpMethod.GET, "shop/mvc").permitAll();
        ;


        /**************************************
         *               인증 정책
         **************************************/
        http
            .formLogin()                        // form 로그인 사용
            //.authenticationDetailsSource(authenticationDetailsSource) // 커스텀 입력필드 설정
            .loginPage("/loginPage")            // 커스텀 로그인 페이지 url
            .defaultSuccessUrl("/loginSuccess") // 로그인 성공시 이동할 url
            .failureForwardUrl("/loginFailed")  // 로그인 실패시 이동할 url (POST 요청)
            .usernameParameter("username")      // 로그인 아이디 파라미터명 (default = username)
            .passwordParameter("password")      // 로그인 패스워드 파라미터명 (default = password)
            .loginProcessingUrl("/login-process") // 로그인 프로세싱 POST url (default = /login) : 해당 경로를 POST 요청하면 로그인을 처리할 수 있다.

        // 로그인 성공시 실행되는 핸들러
            /*
            .successHandler(new AuthenticationSuccessHandler() {
                @Override
                public void onAuthenticationSuccess(HttpServletRequest httpServletRequest,
                    HttpServletResponse httpServletResponse, Authentication authentication) throws IOException {
                    System.out.println("authentication " + authentication.getName());
                    RequestCache requestCache = new HttpSessionRequestCache();
                    // 원래 사용자가 가고자 했던 요청정보
                    SavedRequest request = requestCache.getRequest(httpServletRequest, httpServletResponse);
                    String redirectUrl = request.getRedirectUrl();
                    httpServletResponse.sendRedirect(redirectUrl);
                }
            })
            // 로그인 실패시 실행되는 핸들러 (시큐리티가 제공하는 Form Login 페이지 사용시)
            .failureHandler(new AuthenticationFailureHandler() {
                @Override
                public void onAuthenticationFailure(HttpServletRequest httpServletRequest,
                    HttpServletResponse httpServletResponse, AuthenticationException e) throws IOException {
                    httpServletRequest.setAttribute("msg", e.getMessage());
                    httpServletResponse.sendRedirect("/loginFailed");
                }
            })
            */
        ;

        /****************************************
         *               세션관리
         * 스프링시큐리티는 기본적으로 세션을 기반으로 작동함
         * 시큐리티 프로젝트를 토큰 기반으로 서비스하고 싶다면 세션설정을 차단해야한다.
         ****************************************/
        /*
        http
            .sessionManagement()
            .maximumSessions(1)              // 최대 세션 허용개수
            .maxSessionsPreventsLogin(true)  // 현재 사용자 인증 실패 처리
        //  .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) //  세션 미사용
        ;
         */



        /****************************************
         *               로그아웃
         ****************************************/
        /*
        http
            .logout()
            .logoutSuccessUrl("/logout")  // 로그아웃 url
            .logoutSuccessUrl("/login")   // 로그아웃 성공시 이동하는 url
            .deleteCookies("remember-me") // 쿠키 삭제
            // 로그아웃 처리 핸들러
            .addLogoutHandler(new LogoutHandler() {
                @Override
                public void logout(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) {
                    HttpSession session = httpServletRequest.getSession();
                    session.invalidate();
                }
            })
            // 로그아웃 성공시 실행되는 핸들러
            .logoutSuccessHandler(new LogoutSuccessHandler() {
                @Override
                public void onLogoutSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) throws IOException, ServletException {
                    httpServletResponse.sendRedirect("/login");
                }
            })

        ;
         */


        /**************************************
         *              예외 공용 처리
         **************************************/
        //------- 인증 예외 처리 : 활성화 시 spring security login 페이지가 비활성화 된다 --------
        // ------ 커스텀 loginPage를 생성해야하며 커스텀 loginPage 로 리다이렉트한다
        //------- 에러 메시지를 자동으로 던진다 -------
        /*
        http
            .exceptionHandling()
            .authenticationEntryPoint(new AuthenticationEntryPoint() {
                @Override
                public void commence(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AuthenticationException e) throws IOException {
                    httpServletResponse.sendRedirect("/login/custom");
                }
            })
        ;
         */

        //------- 인가 예외 처리 : 권한이 없는 url 접속 --------
        http
            .exceptionHandling()
            .accessDeniedHandler(new AccessDeniedHandler() {
                @Override
                public void handle(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AccessDeniedException e) throws IOException {
                    httpServletResponse.sendRedirect("/test1/denied");
                }
            })
        ;

        /**************************************
         *             그 외
         **************************************/
        http
            .csrf().disable() // csrf 보안 해제
            .cors(); // cors 허용

    }

    /**************************************
     *           정적파일 허용
     **************************************/
    @Override
    public void configure(WebSecurity web) {
        web.ignoring()
            .requestMatchers(PathRequest.toStaticResources().atCommonLocations()) //기본 설정된 모든 정적파일들
            .antMatchers("/favicon.ico", "/resources/**");
    }

    @Bean
    public CustomAuthenticationProvider customAuthenticationProvider(){
        return new CustomAuthenticationProvider(userDetailsService, passwordEncoder);
    }
}
