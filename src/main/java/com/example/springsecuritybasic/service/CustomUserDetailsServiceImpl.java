package com.example.springsecuritybasic.service;

import com.example.springsecuritybasic.domain.Member;
import com.example.springsecuritybasic.domain.Role;
import com.example.springsecuritybasic.repository.MemberRepository;
import java.util.Collection;
import java.util.List;
import javax.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

/*
    1. Authentication Provider 가 UserDetailsService 를 호출
    2. DB에 저장된 사용자 정보 조회
    3. 사용자 정보가 있다면 UserDetails 생성 후 리턴
 */
@Service
@RequiredArgsConstructor
public class CustomUserDetailsServiceImpl implements CustomUserDetailsService {

    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;

    // ======================= UserDetailsService @Override ========================
    @Transactional
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Member member = memberRepository.findByUsername(username).orElseThrow(
            () -> new UsernameNotFoundException("USER IS NOT EXISTS"));
        return new User(member.getUsername(), member.getPassword(), getAuthorities(member));
    }

    private Collection<? extends GrantedAuthority> getAuthorities(Member member) {
        return List.of(new SimpleGrantedAuthority(member.getRole().name()));
    }
    // =============================================================================

    @Transactional
    public Member save(Member member) {
        // 시큐리티 계정은 항상 password 가 암호화 되어있어야 합니다.
        member.setPassword(passwordEncoder.encode(member.getPassword()));
        if(StringUtils.hasText(member.getSnsSecretKey())){
            member.setSnsSecretKey(passwordEncoder.encode(member.getSnsSecretKey()));
        }
        return memberRepository.save(member);
    }

    @Transactional
    public UserDetails loadUserByUsernameAndSnsSync(String username, String snsSync, String snsSecretKey) {
        Member member = memberRepository.findByUsernameAndSnsSync(username, snsSync).orElseThrow(
            () -> new UsernameNotFoundException("USER IS NOT EXISTS"));
        if(!passwordEncoder.matches(snsSecretKey, member.getSnsSecretKey())){
            throw new BadCredentialsException("Invalid Username Data");
        }
        return new User(member.getUsername(), member.getPassword(), getAuthorities(member));
    }

    @PostConstruct
    public void init(){
        if(memberRepository.findByUsername("user").isEmpty()){
            Member member = new Member();
            member.setUsername("user");
            member.setPassword("1234");
            member.setRole(Role.ROLE_USER);
            System.out.println(this.save(member));
        }
        if(memberRepository.findByUsername("user2").isEmpty()){
            Member member = new Member();
            member.setUsername("user2");
            member.setPassword("1234");
            member.setRole(Role.ROLE_ADMIN);
            member.setSnsSync("google");
            member.setSnsSecretKey("hello");
            System.out.println(this.save(member));
        }
    }
}
