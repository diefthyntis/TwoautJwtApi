package com.diefthyntis.TwoautJwtApi.model;

import java.util.HashSet;
import java.util.Set;

import org.springframework.security.core.userdetails.UserDetails;

import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;



/*
 TWOAUTJWTAPI
 */


@Entity
@Table(name = "internaut", 
    uniqueConstraints = { 
      @UniqueConstraint(columnNames = "name"),
      @UniqueConstraint(columnNames = "email") 
    })
public class Internaut {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @NotBlank
  @Size(max = 20)
  private String name;

  @NotBlank
  @Size(max = 50)
  @Email
  private String email;

  @NotBlank
  @Size(max = 120)
  private String password;

  @ManyToMany(fetch = FetchType.LAZY)
  @JoinTable(  name = "internaut_role", 
        joinColumns = @JoinColumn(name = "internaut_id"), 
        inverseJoinColumns = @JoinColumn(name = "role_id"))
  private Set<Role> roles = new HashSet<>();

  public Internaut() {
  }

  public Internaut(String name, String email, String password) {
    this.name = name;
    this.email = email;
    this.password = password;
  }

public Long getId() {
	return id;
}

public void setId(Long id) {
	this.id = id;
}

public String getName() {
	return name;
}

public void setName(String username) {
	this.name = username;
}

public String getEmail() {
	return email;
}

public void setEmail(String email) {
	this.email = email;
}

public String getPassword() {
	return password;
}

public void setPassword(String password) {
	this.password = password;
}

public Set<Role> getRoles() {
	return roles;
}

public void setRoles(Set<Role> Roles) {
	this.roles = Roles;
}

public static UserDetails build(Internaut internaut) {
	// TODO Auto-generated method stub
	return null;
}

  
  // getters and setters
}