package com.security.service;

import com.security.dto.RefreshTokenRequest;
import com.security.dto.SignInRequest;
import com.security.dto.SignUpRequest;
import com.security.entity.User;
import com.security.response.JwtAuthenticationResponse;

public interface AuthenticationService {

	User signUp(SignUpRequest signUpRequest);

	JwtAuthenticationResponse signIn(SignInRequest signInRequest);

	JwtAuthenticationResponse refreshToken(RefreshTokenRequest refreshTokenRequest);
}
