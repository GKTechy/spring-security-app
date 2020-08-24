package com.app.springsecurityapp.dao;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.app.springsecurityapp.model.UserEntity;

@Repository
public interface UserRepository  extends JpaRepository<UserEntity, Long>{
	
	UserEntity findByUsername(String username);
	
}
