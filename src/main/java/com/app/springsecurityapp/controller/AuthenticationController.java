package com.app.springsecurityapp.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.app.springsecurityapp.config.CustomUserDetailService;
import com.app.springsecurityapp.config.JwtUtil;
import com.app.springsecurityapp.model.AuthenticationRequest;
import com.app.springsecurityapp.model.AuthenticationResponse;
import com.app.springsecurityapp.model.UserVO;

@RestController
public class AuthenticationController {

	@Autowired
	private AuthenticationManager authManager;
	
	@Autowired
	private CustomUserDetailService userService;
	
	@Autowired
	private JwtUtil jwtUtils;
	
	
	@PostMapping("/authenticate")
	public ResponseEntity<?> createAuthenticationToken(@RequestBody AuthenticationRequest authrequest) throws Exception{
		
		try {
			authManager.authenticate(new  UsernamePasswordAuthenticationToken(authrequest.getUsername(), authrequest.getPassword()));
			
			UserDetails userDetails = userService.loadUserByUsername(authrequest.getUsername());
			
			String token = jwtUtils.generateToken(userDetails);

			return ResponseEntity.ok(new AuthenticationResponse(token));
			
		} catch (DisabledException e) {
			throw new Exception("USER_DISABLED ",e);
		}catch (BadCredentialsException e) {
			throw new Exception("INVALID_CREDENTIALS ",e);
		}
		
	}
	
	@PostMapping("/register")
	public ResponseEntity<?> saveUser(@RequestBody UserVO uservo){
		return ResponseEntity.ok(userService.saveuser(uservo));
	}
	
}
