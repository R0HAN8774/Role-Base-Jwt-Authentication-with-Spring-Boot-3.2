package com.security;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import com.security.entity.Role;
import com.security.entity.User;
import com.security.repository.UserRepository;

@SpringBootApplication
public class SpringSecurityApplication implements CommandLineRunner {

	private final UserRepository userRepository;

	public SpringSecurityApplication(UserRepository userRepository) {
		this.userRepository = userRepository;
	}

	public static void main(String[] args) {
		SpringApplication.run(SpringSecurityApplication.class, args);
	}

	@Override
	public void run(String... args) throws Exception {
		User adminAccount = userRepository.findByRole(Role.ADMIN);
		if (null == adminAccount) {
			User user = new User();
			user.setUserEmail("admin@gmail.com");
			user.setUserName("admin");
			user.setRole(Role.ADMIN);
			user.setUserPassword(new BCryptPasswordEncoder().encode("admin"));
			userRepository.save(user);

		}

	}
}
