package com.example.springsecuritysample.domain.entity;

import com.example.springsecuritysample.domain.model.AuthorizedMember;
import jakarta.persistence.*;

import java.time.LocalDateTime;
import java.util.Set;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "member")
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class Member {
	@Id
	private String email;
	@Setter
	private String name;
	private String password;
	@ElementCollection(fetch = FetchType.LAZY)
	//@ElementCollection(fetch=FetchType.EAGER)
	private Set<String> roles;
	private LocalDateTime createdAt;
}
