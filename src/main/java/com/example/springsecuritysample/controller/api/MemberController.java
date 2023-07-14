package com.example.springsecuritysample.controller.api;

import com.example.springsecuritysample.domain.entity.Member;
import com.example.springsecuritysample.domain.model.AuthorizedMember;
import com.example.springsecuritysample.dto.LoginRequest;
import com.example.springsecuritysample.dto.MemberInfo;
import com.example.springsecuritysample.dto.SignupRequest;
import com.example.springsecuritysample.service.MemberService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j(topic = "memberController")
@RestController
@RequestMapping("/api/members")
@RequiredArgsConstructor
public class MemberController {

	private final MemberService memberService;

	@PostMapping("/signup")
	public ResponseEntity<String> signup(@RequestBody SignupRequest signupRequest) {
		memberService.signup(signupRequest);
		return ResponseEntity.status(201).body("Signup Succeeded");
	}

	@PostMapping("/login")
	public ResponseEntity<String> login(@RequestBody LoginRequest loginRequest) {
		return ResponseEntity.ok(memberService.login(loginRequest));
	}

	@GetMapping("/info")
	public ResponseEntity<MemberInfo> getMemberInfo(@AuthenticationPrincipal AuthorizedMember authorizedMember) {
		if (authorizedMember == null) {
			return ResponseEntity.badRequest().build();
		}

		// TODO : authorizedMember.getMember()와 같은 중복 개념 접근 개선하기
		//Member member = authorizedMember.getMember();
		MemberInfo memberinfo = memberService.getMemberInfo(authorizedMember);
		/*
		log.info(member.getEmail());
		log.info(member.getPassword());
		log.info(member.getRoles().toString());
		*/
		//return ResponseEntity.ok(new MemberInfo(member.getEmail(), member.getName(), member.getRoles()));
		return ResponseEntity.ok(memberinfo);
	}
}
