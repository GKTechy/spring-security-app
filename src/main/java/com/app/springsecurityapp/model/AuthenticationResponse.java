package com.app.springsecurityapp.model;

public class AuthenticationResponse {

	private String token;

	public AuthenticationResponse() {
		super();
	}

	public AuthenticationResponse(String token) {
		super();
		this.token = token;
	}


	public String getToken() {
		return token;
	}

	public void setToken(String token) {
		this.token = token;
	}
	

	@Override
	public String toString() {
		return "AuthenticationResponse [token=" + token + "]";
	}
	
	
}
