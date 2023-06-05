package com.example.springsecuritybasic.controller;

import javax.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {

    @GetMapping("/loginSuccess")
    public Authentication loginSuccess(Authentication authentication){
        return authentication;
    }

    @PostMapping("/loginFailed")
    public String loginFailed(){
        return "loginFailed";
    }

    @GetMapping("/loginFailed")
    public String loginFailed2(){
        return "loginFailed";
    }

}
