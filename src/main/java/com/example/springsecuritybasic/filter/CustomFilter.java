package com.example.springsecuritybasic.filter;

import com.example.springsecuritybasic.authenticationDetails.CustomWebAuthenticationDetails;
import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.StringUtils;

/**
 * 특정 경로에 들어오는 경우에만 작동하는 필터
 */
public class CustomFilter extends AbstractAuthenticationProcessingFilter {

    // 요청받을 login url
    public CustomFilter() {
        super(new AntPathRequestMatcher("/customLogin"));
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {

        String username = request.getParameter("username");
        String password = request.getParameter("password");

        // STEP 1 : 입력받은 사용자 정보로 미인증 Token 생성
        if(StringUtils.isEmpty(username) || StringUtils.isEmpty(password)){
            throw new IllegalArgumentException("Username or Password is empty");
        }
        UsernamePasswordAuthenticationToken token =
            new UsernamePasswordAuthenticationToken(username, password);
        CustomWebAuthenticationDetails details = new CustomWebAuthenticationDetails(request);
        token.setDetails(details);

        // STEP 2 : AuthenticationManager 에게 전달
        return getAuthenticationManager().authenticate(token);
    }
}
