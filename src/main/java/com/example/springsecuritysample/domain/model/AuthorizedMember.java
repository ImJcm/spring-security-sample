package com.example.springsecuritysample.domain.model;

import com.example.springsecuritysample.domain.entity.Member;
import java.util.Collections;
import lombok.Getter;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.transaction.annotation.Transactional;

@Getter
public class AuthorizedMember extends User {

	private final Member member;

	public AuthorizedMember(Member member) {
		super(member.getEmail(), member.getPassword(),
			Collections.singletonList(new SimpleGrantedAuthority("ROLE_MEMBER")));
		this.member = member;
	}
}
