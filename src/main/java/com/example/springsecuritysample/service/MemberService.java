package com.example.springsecuritysample.service;

import com.example.springsecuritysample.configuration.security.JwtUtil;
import com.example.springsecuritysample.domain.entity.Member;
import com.example.springsecuritysample.domain.model.AuthorizedMember;
import com.example.springsecuritysample.dto.LoginRequest;
import com.example.springsecuritysample.dto.MemberInfo;
import com.example.springsecuritysample.dto.SignupRequest;
import com.example.springsecuritysample.repository.MemberRepository;
import com.example.springsecuritysample.repository.MemberRolesRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class MemberService {

	private final MemberRepository memberRepository;
	private final MemberRolesRepository memberRolesRepository;
	private final PasswordEncoder passwordEncoder;

	public MemberInfo getMemberInfo(AuthorizedMember authorizedMember) {
		Member member = memberRolesRepository.findById(authorizedMember.getMember().getEmail()).orElse(null);
		return new MemberInfo(authorizedMember.getMember().getEmail(), authorizedMember.getMember().getName(),member.getRoles());
		//return new MemberInfo(authorizedMember.getMember().getEmail(), authorizedMember.getMember().getName(),authorizedMember.getMember().getRoles());
	}

	public void signup(SignupRequest signupRequest) {
		Member member = new Member(signupRequest.email(), signupRequest.name(),
			passwordEncoder.encode(signupRequest.password()), Set.of("ROLE_MEMBER"),
			LocalDateTime.now());

		memberRepository.save(member);
	}

	public String login(LoginRequest loginRequest) {
		Member member = memberRepository.findByEmail(loginRequest.email());
		if (member == null) {
			throw new UsernameNotFoundException(loginRequest.email());
		}

		if (!passwordEncoder.matches(loginRequest.password(), member.getPassword())) {
			throw new BadCredentialsException("잘못된 요청입니다. 아이디 또는 비밀번호를 확인해주세요.");
		}

		return JwtUtil.createToken(loginRequest.email());
	}
}
