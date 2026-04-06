package com.tavarlabs.prtcSpringSecurity.security;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
@Slf4j
public class JwtUtil {

    @Value("${jwt.secret}")
    private String jwtSecret;

    @Value("${jwt.expiration}")
    private int jwtExpirationMs;

    private SecretKey key;

    /*
     * Since Spring calls first the constructor of the class before injecting dependencies in this case
     * 'jwtSecret' and 'jwtExpirationMs' which have the @Value. If you use a conventional constructor, this
     * will throw a null pointer exception because neither 'jwtSecret' nor 'jwtExpirationMs' would be
     * initialized at this specific moment.
     *
     * So that's why this init() method is used with this annotation of @PostConstruct, so when Spring creates
     * the bean for this class (JwtUtil) it set up what's inside the init() method after the class is fully
     * constructed and all dependencies have been injected that way we can set up SecretKey object in a safe
     * manner.
     *
     * This @PostConstruct is all about timing.
     * **/
    @PostConstruct
    public void init(){ this.key = Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8)); }

    public String generateToken(String username){
        return Jwts.builder()
                .subject(username)
                .issuedAt(new Date())
                .expiration(new Date((new Date()).getTime() + jwtExpirationMs))
                .signWith(key)
                .compact();
    }

    public String getUserFromToken(String token) {
        return Jwts.parser().verifyWith(key).build()
                .parseSignedClaims(token)
                .getPayload()
                .getSubject();
    }

    public boolean validateJwtToken(String token){
        try{
            Jwts.parser().verifyWith(key).build().parseSignedClaims(token);
            return true;
        } catch (Exception e){
            log.error("JWT validation error: {}", e.getMessage());
        }
        return false;
    }
}
