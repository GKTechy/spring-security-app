package com.app.springsecurityapp.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ResourceController {
	
	
	@GetMapping("/hellouser")
	public String getUser() {
		return "Hello User";
	}
	
	@GetMapping("/helloadmin")
	public String getAdmin() {
		return "Hello Admin";
	}
}
