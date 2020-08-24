package com.app.springsecurityapp.config;

import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties.Jwt;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;

@Service
public class JwtUtil {
	
	private String secret;
	private int jwtExpirationinMs;
	
	
	@Value("${jwt.secret}")
	public void setSecret(String secret) {
		this.secret = secret;
	}
	
	@Value("${jwt.jwtExpirationInMs}")
	public void setJwtExpirationinMs(int jwtExpirationinMs) {
		this.jwtExpirationinMs = jwtExpirationinMs;
	}
	
	public String generateToken(UserDetails userdetails) {
		Map<String,Object> claims= new HashMap<>();
		
		Collection<? extends GrantedAuthority> roles=userdetails.getAuthorities();
			
		if(roles.contains(new SimpleGrantedAuthority("ROLE_ADMIN"))) {
			claims.put("isAdmin", true);
		}
		
		if(roles.contains(new SimpleGrantedAuthority("ROLE_USER"))) {
			claims.put("isUser", true);
		}
		
		return doGenerateToken(claims,userdetails.getUsername());
	}

	private String doGenerateToken(Map<String, Object> claims, String subject) {
		return Jwts.builder().setClaims(claims).setSubject(subject)
				.setIssuedAt(new Date(System.currentTimeMillis()))
				.setExpiration(new Date(System.currentTimeMillis()+jwtExpirationinMs))
				.signWith(SignatureAlgorithm.HS512, secret)
				.compact();
	}
	
	public boolean validateToken(String token) {
		
		try {
			Jws<Claims> cliams = Jwts.parser().setSigningKey(secret).parseClaimsJws(token);
			return true;
		} catch (ExpiredJwtException e) {
			throw e;
		} catch (UnsupportedJwtException | MalformedJwtException | SignatureException | IllegalArgumentException e) {
			throw new BadCredentialsException("INVALID_CREDENTIALS",e);
		} 
		
	}
	
	public String getUsernameFromToken(String token) {
			Claims claims = Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();
			return claims.getSubject();
	}
	
	public List<SimpleGrantedAuthority> getRolesFromToken(String token){
		List<SimpleGrantedAuthority> roles=null;
			Claims claims = Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();
			
			
			Boolean isAdmin=claims.get("isAdmin",Boolean.class);
			Boolean isUser=claims.get("isUser",Boolean.class);
			
			if(isAdmin !=null && isAdmin) {
				roles = Arrays.asList(new SimpleGrantedAuthority("ROLE_ADMIN"));
			}
			
			if(isUser !=null && isUser) {
				roles = Arrays.asList(new SimpleGrantedAuthority("ROLE_USER"));
			}
			
			return roles;
		
	}
	
	
	
}
