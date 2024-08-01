package com.example.loginjwt.util;

import com.example.loginjwt.dto.TokenInfo;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SecurityException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;

@Slf4j
@Component
public class TokenIssuer {

    private final String issuer;
    private final SecretKey key;
    private final long accessTokenValidityInMilliseconds;
    private final long refreshTokenValidityInMilliseconds;

    public TokenIssuer(
            @Value("${jwt.secret-key}") String secretKey,
            @Value("${jwt.issuer}") String issuer,
            @Value("${jwt.access-token-validity-in-minutes}") long accessTokenValidityInMinutes,
            @Value("${jwt.refresh-token-validity-in-minutes}") long refreshTokenValidityInMinutes
    ){
        this.issuer = issuer;
        this.accessTokenValidityInMilliseconds = accessTokenValidityInMinutes * 60 * 1000;
        this.refreshTokenValidityInMilliseconds = refreshTokenValidityInMinutes * 60 * 1000;
        this.key = Keys.hmacShaKeyFor(Decoders.BASE64URL.decode(secretKey));
    }

    public TokenInfo issue(String email) {
        long currentTime = new Date().getTime();
        String accessToken = buildDefaultJwt(currentTime,currentTime+accessTokenValidityInMilliseconds)
                .subject(email)
                .claim("type","access")
                .compact();
        String refreshToken = buildDefaultJwt(currentTime,currentTime+refreshTokenValidityInMilliseconds)
                .claim("type","refresh")
                .compact();
        return TokenInfo.builder()
                .accessToken(accessToken)
                .accessTokenExpirationTime(accessTokenValidityInMilliseconds)
                .refreshToken(refreshToken)
                .refreshTokenExpirationTime(refreshTokenValidityInMilliseconds)
                .build();
    }

    public Claims parse(String token) {
        try {
            return getPayload(token);
        } catch (ExpiredJwtException e) {
            return e.getClaims();
        }
    }

    public boolean validate(String token,String email) {
        try {
            Claims claims = getPayload(token);
            return claims.getSubject().equals(email);
        } catch (SecurityException | MalformedJwtException e) {
            log.info("Invalid JWT Token");
        } catch (ExpiredJwtException e) {
            log.info("Expired JWT Token");
        } catch (UnsupportedJwtException e) {
            log.info("Unsupported JWT Token");
        } catch (IllegalArgumentException e) {
            log.info("JWT claims string is empty.");
        }
        return false;
    }

    private Claims getPayload(String token){
        return Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    private JwtBuilder buildDefaultJwt(long currentTime,long expireTime){
        return Jwts.builder()
                .issuedAt(new Date(currentTime))
                .issuer(issuer)
                .expiration(new Date(expireTime))
                .signWith(key);
    }
}
