package com.example.proxygateway.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class WebUiController {

    @GetMapping("/")
    public String index() {
        return "forward:/index.html";
    }
}
