package com.example.amigosecurity.auth;

import org.springframework.stereotype.Component;

import java.util.Optional;

@Component
public interface ApplicationUserDao {

    Optional<ApplicationUser> selectApplicationUserByUsername(String username);

}
