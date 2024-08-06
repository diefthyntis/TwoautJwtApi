package com.diefthyntis.TwoautJwtApi.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;


import com.diefthyntis.TwoautJwtApi.model.Internaut;
import com.diefthyntis.TwoautJwtApi.repository.InternautRepository;

/*
 * In the code, we get full custom User object using UserRepository, 
 * then we build a UserDetails object using static build() method.
 */

@Service
public class UserService implements UserDetailsService {
  @Autowired
  InternautRepository internautRepository;

  @Override
  @Transactional
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    Internaut internaut = internautRepository.findByUsername(username)
        .orElseThrow(() -> new UsernameNotFoundException("User Not Found with username: " + username));

    return Internaut.build(internaut);
  }

}