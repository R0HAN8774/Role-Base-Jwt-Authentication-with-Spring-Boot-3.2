package com.security.service.impl;

import java.util.HashMap;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.security.dto.RefreshTokenRequest;
import com.security.dto.SignInRequest;
import com.security.dto.SignUpRequest;
import com.security.entity.Role;
import com.security.entity.User;
import com.security.repository.UserRepository;
import com.security.response.JwtAuthenticationResponse;
import com.security.service.AuthenticationService;
import com.security.service.JWTService;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthenticationServiceImpl implements AuthenticationService {

	private final UserRepository userRepository;
	private final PasswordEncoder passwordEncoder;
	private final AuthenticationManager authenticationManager;
	private final JWTService jwtService;

	@Override
	public User signUp(SignUpRequest signUpRequest) {
		User user = new User();
		user.setUserName(signUpRequest.getUserName());
		user.setUserEmail(signUpRequest.getUserEmail());
		user.setRole(Role.USER);
		user.setUserPassword(passwordEncoder.encode(signUpRequest.getUserPassword()));
		return userRepository.save(user);

	}

	@Override
	public JwtAuthenticationResponse signIn(SignInRequest signInRequest) {

		authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(signInRequest.getUserEmail(), signInRequest.getUserPassword()));
		User user = userRepository.findByUserEmail(signInRequest.getUserEmail())
				.orElseThrow(() -> new IllegalArgumentException("Invalid Credentials"));

		String token = jwtService.generateToken(user);
		String refreshToken = jwtService.generateRefreshToken(new HashMap<>(), user);

		JwtAuthenticationResponse jwtAuthenticationResponse = new JwtAuthenticationResponse();
		jwtAuthenticationResponse.setToken(token);
		jwtAuthenticationResponse.setRefreshToken(refreshToken);
		return jwtAuthenticationResponse;
	}

	@Override
	public JwtAuthenticationResponse refreshToken(RefreshTokenRequest refreshTokenRequest) {

		String userEmail = jwtService.getUsernameFromToken(refreshTokenRequest.getToken());
		User user = userRepository.findByUserEmail(userEmail).orElseThrow();

		if (jwtService.isTokenValid(refreshTokenRequest.getToken(), user)) {
			String token = jwtService.generateToken(user);

			JwtAuthenticationResponse jwtAuthenticationResponse = new JwtAuthenticationResponse();
			jwtAuthenticationResponse.setToken(token);
			jwtAuthenticationResponse.setRefreshToken(refreshTokenRequest.getToken());
			return jwtAuthenticationResponse;
		}
		return null;

	}
}
