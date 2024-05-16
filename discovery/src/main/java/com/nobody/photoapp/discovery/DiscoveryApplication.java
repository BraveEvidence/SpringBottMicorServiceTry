package com.nobody.photoapp.discovery;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.netflix.eureka.server.EnableEurekaServer;

@SpringBootApplication
@EnableEurekaServer
public class DiscoveryApplication {
 
	public static void main(String[] args) {
		SpringApplication.run(DiscoveryApplication.class, args);
	}

} 
 
//Add @EnableEurekaServer in this file
//application.properties
//Go to localhost:8010

// ========
