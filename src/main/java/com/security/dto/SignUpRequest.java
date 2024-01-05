package com.security.dto;

import lombok.Data;

@Data
public class SignUpRequest {

    private String userName;
    private String userEmail;
    private String userPassword;
}
