package com.example.springsecuritybasic.provider;

import com.example.springsecuritybasic.authenticationDetails.CustomWebAuthenticationDetails;
import com.example.springsecuritybasic.service.CustomUserDetailsService;
import javax.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.StringUtils;
/*
    커스텀 인증을 처리하는 객채
 */
@RequiredArgsConstructor
public class CustomAuthenticationProvider implements AuthenticationProvider {

    private final CustomUserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;

    @Override
    @Transactional
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        // STEP 1 : 사용자가 입력한 데이터를 기반으로 생성된 미인증 토큰으로 사용자 입력 정보를 추출
        String username = authentication.getName();
        String password = (String) authentication.getCredentials();
        CustomWebAuthenticationDetails authenticationDetails =
            (CustomWebAuthenticationDetails)authentication.getDetails();
        String snsSync = authenticationDetails.getSnsSync();

        // STEP 2 : 입력 정보가 올바른지 검증
        // 개인 인증 서버의 데이터로 접근한 경우 패스워드 검증
        UserDetails userDetails = null;
        if(!StringUtils.hasText(snsSync)){
            userDetails = userDetailsService.loadUserByUsername(username);;
            if(!passwordEncoder.matches(password, userDetails.getPassword())){
                throw new BadCredentialsException("Invalid Username or Password");
            }
        // SNS 연동 계정 데이터로 접근한 경우 검증
        } else {
            String secretKey = authenticationDetails.getSnsSecretKey();
            userDetails = userDetailsService.loadUserByUsernameAndSnsSync(username, snsSync, secretKey);
        }

        // STEP 3 : 인증 성공하면 토큰 생성
        return new UsernamePasswordAuthenticationToken(username, password, userDetails.getAuthorities());
    }

    @Override
    // Authentication과 해당 토큰이 같을 때 구동
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }
}
