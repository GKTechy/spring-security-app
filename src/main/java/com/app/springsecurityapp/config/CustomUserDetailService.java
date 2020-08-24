package com.app.springsecurityapp.config;
import java.util.Arrays;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.app.springsecurityapp.dao.UserRepository;
import com.app.springsecurityapp.model.UserEntity;
import com.app.springsecurityapp.model.UserVO;


@Service
public class CustomUserDetailService implements UserDetailsService{

	@Autowired
	private UserRepository userRepo;
	
	@Autowired
	private PasswordEncoder bcryptEncoder;
	
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

		List<SimpleGrantedAuthority> roles=null;
		
		UserEntity uservo=userRepo.findByUsername(username);
		if(uservo !=null) {
			roles = Arrays.asList(new SimpleGrantedAuthority(uservo.getRole()));
			return new User(uservo.getUsername(),uservo.getPassword(),roles);
		}
		
//		if(username.equals("admin")) {
//			roles = Arrays.asList(new SimpleGrantedAuthority("ROLE_ADMIN"));
//			return new User("admin","$2a$10$hyQEJhFheHWVbNM9azYnYe.3TwCWwrEcsRApHZUrX6r5YvkqcN49a",roles);
//		}
//		
//		if(username.equals("user")) {
//			roles = Arrays.asList(new SimpleGrantedAuthority("ROLE_USER"));
//			return new User("user","$2a$10$.9xX3lzjwuU4wkOHy.bd8un9nRsB16ltyRjsLRKKdlbYrY1W13oLy",roles);
//		}
//		
		
		throw new UsernameNotFoundException(" User not found with name : " +username);
	}
	
	
	public UserEntity saveuser(UserVO uservo) {
		UserEntity user=new UserEntity();
		user.setUsername(uservo.getUsername());
		user.setPassword(bcryptEncoder.encode(uservo.getPassword())); //need to change password 
		user.setRole(uservo.getRole());
		
		return userRepo.save(user);
	}
}
