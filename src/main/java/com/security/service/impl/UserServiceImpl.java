package com.security.service.impl;

import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.security.repository.UserRepository;
import com.security.service.UserService;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

	private final UserRepository userRepository;

	@Override
	public UserDetailsService userDetailsService() {
		return username -> userRepository.findByUserEmail(username)
				.orElseThrow(() -> new UsernameNotFoundException("User Not Found !!"));
	}

}
