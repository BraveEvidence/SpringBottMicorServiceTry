package com.nobody.photoapp.api.users;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@SpringBootApplication
public class UsersApplication {
 
	public static void main(String[] args) {
		SpringApplication.run(UsersApplication.class, args);
	}

	@Bean
	public BCryptPasswordEncoder bCryptPasswordEncoder() {
		return new BCryptPasswordEncoder();
	}

}

//http://localhost:8010/


//http://localhost:8082/users-ws/h2-console
//add jwt to apigateway pom file
//AuthenticationFilter.java
//AuthorizationHeaderFilter in apigateway
//application.properties => apigateway

//
