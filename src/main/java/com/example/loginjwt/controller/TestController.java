package com.example.loginjwt.controller;

import com.example.loginjwt.dto.TokenInfo;
import com.example.loginjwt.util.TokenIssuer;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class TestController {
    private final TokenIssuer tokenIssuer;

    @GetMapping("/issue")
    public TokenInfo test(@RequestParam String email) {
        return tokenIssuer.issue(email);
    }

    @GetMapping("/validate")
    public boolean validate(@RequestParam String token, @RequestParam String email) {
        return tokenIssuer.validate(token, email);
    }

}
