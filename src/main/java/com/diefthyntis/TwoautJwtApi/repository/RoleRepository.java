package com.diefthyntis.TwoautJwtApi.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.diefthyntis.TwoautJwtApi.model.ERole;
import com.diefthyntis.TwoautJwtApi.model.Role;



@Repository
public interface RoleRepository  extends JpaRepository<Role, Long> {
	Optional<Role> findByName(ERole name);
}
