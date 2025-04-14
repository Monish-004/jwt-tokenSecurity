package com.example.Spring.security.controller;

import com.example.Spring.security.entity.MyApplication;
import com.example.Spring.security.serviceImplementation.JwtService;
import com.example.Spring.security.serviceImplementation.MyApplicationServiceLayer;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SpringController
{
    @Autowired
    private MyApplicationServiceLayer myApplicationServiceLayer;
    @Autowired
    private JwtService jwtService;
    @Autowired
    private AuthenticationManager authenticationManager;

    // http://localhost:8080/message
    @GetMapping("message")
    public String message(HttpServletRequest request)
    {
        return "Hii!! " + request.getSession().getId() ;
    }

    // http://localhost:8080/token
    @GetMapping("token")
    public CsrfToken getCsrfToken(HttpServletRequest request)
    {
        return (CsrfToken) request.getAttribute("_csrf");
    }

    // http://localhost:8080/about-java
    @GetMapping("about-java")
    public String java()
    {
        return "Hey!! Welcome to JAVA World!";
    }

    // http://localhost:8080/register
    @PostMapping("register")
    public ResponseEntity<String> signup(@RequestBody MyApplication registerationForNewUser)
    {
        myApplicationServiceLayer.saveRegisterationDetails(registerationForNewUser);
        return new ResponseEntity<>("USER SUCCESSFULLY REGISTERED!!", HttpStatus.CREATED);
    }

    // http://localhost:8080/login
    @PostMapping("login")
    public String Login (@RequestBody MyApplication user)
    {
        Authentication authentication = authenticationManager
                .authenticate(new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword()));
        if(authentication.isAuthenticated())
        {
            return jwtService.generateToken(user.getUsername());
        }
        else
            return "Failed!!";

    }
}
