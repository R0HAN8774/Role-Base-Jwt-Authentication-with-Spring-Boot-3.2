package com.security.service;

import java.util.Map;

import org.springframework.security.core.userdetails.UserDetails;

public interface JWTService {

	String getUsernameFromToken(String token);

	String generateToken(UserDetails userDetails);

	String generateRefreshToken(Map<String, Object> extractClaims, UserDetails userDetails);

	boolean isTokenValid(String token, UserDetails userDetails);

}
