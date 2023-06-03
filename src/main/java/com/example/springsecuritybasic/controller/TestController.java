package com.example.springsecuritybasic.controller;

import javax.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {

    @GetMapping("/loginSuccess")
    public Authentication loginSuccess(Authentication authentication){
        return authentication;
    }

    @GetMapping("/loginFailed")
    public String loginFailed(HttpServletRequest request){
        return request.getAttribute("msg").toString();
    }

}
