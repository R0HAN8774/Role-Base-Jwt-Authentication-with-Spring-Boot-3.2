package com.security.dto;

import lombok.Data;

@Data
public class SignInRequest {

	private String userEmail;
	private String userPassword;
}
