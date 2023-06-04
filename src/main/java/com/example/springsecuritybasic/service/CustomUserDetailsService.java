package com.example.springsecuritybasic.service;

import com.example.springsecuritybasic.domain.Member;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

public interface CustomUserDetailsService extends UserDetailsService {
    Member save(Member member);
    UserDetails loadUserByUsernameAndSnsSync(String username, String snsSync, String snsSecretKey);
}
