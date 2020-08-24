package com.app.springsecurityapp.config;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import io.jsonwebtoken.ExpiredJwtException;

@Component
public class CustomJwtAuthenticationFilter extends  OncePerRequestFilter{

	@Autowired
	private JwtUtil jwtutil;
	
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		
		String jwtToken=extractjwttokenfromRequest(request);
		
		try {
			if(StringUtils.hasText(jwtToken) && jwtutil.validateToken(jwtToken)) {
				
				UserDetails userdetails=new User(jwtutil.getUsernameFromToken(jwtToken), "",jwtutil.getRolesFromToken(jwtToken));
				
				UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken= new UsernamePasswordAuthenticationToken(userdetails,"",jwtutil.getRolesFromToken(jwtToken));
				
				SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
				
			}else {
				System.out.println("Can't set the Security Context");
			}
		} catch (ExpiredJwtException ex) {
			request.setAttribute("exception", ex);
			throw ex;
		} catch (BadCredentialsException ex) {
			request.setAttribute("exception", ex);
			throw ex;
		}
		filterChain.doFilter(request, response);
	}

	private String extractjwttokenfromRequest(HttpServletRequest request) {

			String bearerToken=request.getHeader("Authorization");
			
			if(StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
				return bearerToken.substring(7, bearerToken.length());
			}
			
		return null;
	}

}
