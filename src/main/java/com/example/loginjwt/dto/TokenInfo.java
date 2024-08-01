package com.example.loginjwt.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class TokenInfo {
    private String accessToken;
    private String refreshToken;
    private long refreshTokenExpirationTime;
    private long accessTokenExpirationTime;
}
