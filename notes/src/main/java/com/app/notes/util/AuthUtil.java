package com.app.notes.util;

import com.app.notes.models.User;
import com.app.notes.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

@Component
public class AuthUtil {

    @Autowired
    UserRepository userRepository;

    public Long loggedInUserId(){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        User user = userRepository.findByUsername(authentication.getName())
                .orElseThrow(() -> new RuntimeException("User not found"));
        return user.getUserId();
    }

    public User loggedInUser(){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return userRepository.findByUsername(authentication.getName())
                .orElseThrow(() -> new RuntimeException("User not found"));
    }
}
