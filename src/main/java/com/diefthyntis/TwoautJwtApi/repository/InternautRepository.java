package com.diefthyntis.TwoautJwtApi.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.diefthyntis.TwoautJwtApi.model.Internaut;

@Repository
public interface InternautRepository extends JpaRepository<Internaut, Long> {
	Optional<Internaut> findByName(String name);

	  Boolean existsByName(String name);

	  Boolean existsByEmail(String email);

}
