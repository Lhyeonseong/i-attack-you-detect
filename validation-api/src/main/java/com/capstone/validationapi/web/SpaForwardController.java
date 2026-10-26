package com.capstone.validationapi.web;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

@Controller
public class SpaForwardController {

    @GetMapping({
            "/overview",
            "/attacks",
            "/detection",
            "/attck",
            "/system",
            "/revalidate",
            "/report"
    })
    public String forwardStaticRoutes() {
        return "forward:/index.html";
    }

    @GetMapping("/attempts/{id}")
    public String forwardAttemptDetail(@PathVariable String id) {
        return "forward:/index.html";
    }
}
