package com.nobody.photapp.api.apigateway;


import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwe;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

import org.springframework.http.server.reactive.ServerHttpResponse;
import reactor.core.publisher.Mono;

@Component
public class AuthorizationHeaderFilter extends AbstractGatewayFilterFactory<AuthorizationHeaderFilter.Config>{

    @Autowired
    private Environment environment;

    public AuthorizationHeaderFilter(){
        super(Config.class);
    }

    public static class Config{

    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange,chain)->{
            ServerHttpRequest request = exchange.getRequest();
            if(!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)){
                return onError(exchange,"No authorization header",HttpStatus.UNAUTHORIZED);
            }
            String authorizationHeader = request.getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);
            String jwt = authorizationHeader.replace("Bearer ", ""); //Make sure you add space
            if(!isJwtValid(jwt)){
                return onError(exchange, "Jwt token is invalid",HttpStatus.UNAUTHORIZED);
            }
            return chain.filter(exchange);
        };
    }

    private Mono<Void> onError(ServerWebExchange exchange,String err,HttpStatus httpStatus){
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);
        return response.setComplete();
    }

    private boolean isJwtValid(String jwt){
        System.out.println("1");
        boolean isValid = false;
        String subject = null;
        String tokenSecret = environment.getProperty("token.secret");
        System.out.println("2 "+tokenSecret);
        SecretKey secretKey = Keys.hmacShaKeyFor(tokenSecret.getBytes());

        JwtParser jwtParser = Jwts.parser().verifyWith(secretKey).build();
        try{
            // Jwt<Header,Claims> parsedToken = jwtParser.parse(jwt);
            subject = jwtParser.parseSignedClaims(jwt).getPayload().get("userId").toString();
            System.out.println("3 "+subject);
        } catch(Exception ex){
            isValid = false;
            System.out.println("4 "+ex.getLocalizedMessage());
        }

        if(subject == null || subject.isEmpty()){
            isValid = false;
        } else {
            isValid = true;
        }
        System.out.println("5 ");
        return isValid;
    }

  
}
