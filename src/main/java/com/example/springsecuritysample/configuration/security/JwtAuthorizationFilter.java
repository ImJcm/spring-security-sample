package com.example.springsecuritysample.configuration.security;

import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j(topic = "JwtAuthorizationFilter")
@RequiredArgsConstructor
class JwtAuthorizationFilter extends OncePerRequestFilter {

	private final MemberDetailsServiceImpl memberDetailsService;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
		FilterChain filterChain) throws ServletException, IOException {
		// TODO : 요청에 들어온 JWT를 parsing해서 "ROLE_MEMBER" 권한이 있는지 확인하고, SecurityContextHolder에 context 설정하기

		// jwt token 추출 + Bearer 접두사 제거
		String token = JwtUtil.getTokenFromHeader(request);

		if(StringUtils.hasText(token)) {
			if(!JwtUtil.validateToken(token)) {
				log.error("토큰이 유효하지 않다.");
				return;
			}

			//token parsing
			Claims info = JwtUtil.getUserInfoFromToken(token);

			//ROLE_MEMBER 권한 검사
			//log.info((String) info.get("auth"));
			if(info.get("auth").equals("ROLE_MEMBER")) {
				try {
					//log.info(info.getSubject()) => email
					setAuthentication(info.getSubject());
				} catch (Exception e) {
					log.error(e.getMessage());
					return;
				}
			}
		}
		filterChain.doFilter(request, response);
	}

	public void setAuthentication(String email) {
		SecurityContext context = SecurityContextHolder.createEmptyContext();

		/*
			email 필드 값이 email 값과 같은 DB 데이터를 가져온다.
			이때, AuthorizedMember는 UserDetails 타입으로 캐스팅
		*/
		UserDetails userDetails = memberDetailsService.loadUserByUsername(email);

		//if(userDetails.getAuthorities() == )
		//Authentication 생성
		Authentication authentication = new UsernamePasswordAuthenticationToken(
				userDetails,null,userDetails.getAuthorities());

		//context 에 authentication 객체 저장
		context.setAuthentication(authentication);

		//SecurityContextHolder에 context 저장 후, 전역적으로 Authentication 사용
		SecurityContextHolder.setContext(context);
	}
}
