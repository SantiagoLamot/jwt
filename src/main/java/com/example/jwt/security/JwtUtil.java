package com.example.jwt.security;

import java.util.Date;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Component
public class JwtUtil {
    private final String SECRET = "123321";

    public String generarToken(String username){
        return Jwts.builder()
        .setSubject(username)
        .setIssuedAt(new Date())
        .setExpiration(new Date(System.currentTimeMillis()+1000*60*60))
        .signWith(SignatureAlgorithm.HS256, SECRET)
        .compact();
    }
    public String extraerUsername(String token){
        return Jwts.parser().setSigningKey(SECRET).parseClaimsJws(token).getBody().getSubject();
    }
    public boolean validarToken(String token, UserDetails userDetails){
        String username = extraerUsername(token);
        return username.equals(userDetails.getUsername())&& !estaExpirado(token);
    }
    private boolean estaExpirado(String token){
        return Jwts.parser().setSigningKey(SECRET)
        .parseClaimsJws(token).getBody().getExpiration().before(new Date());
    }
}
