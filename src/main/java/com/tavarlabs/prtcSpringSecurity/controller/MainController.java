package com.tavarlabs.prtcSpringSecurity.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1")
public class MainController {

    @GetMapping("/welcome")
    public String welcome() {return "Everyone access";}

    @GetMapping("/user")
    public String userAccess() {return "User Content with jwt";}

    @GetMapping("/special")
    public String specialAccess() {return "Special Content with jwt";}
}
