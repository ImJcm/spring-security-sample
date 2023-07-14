package com.example.springsecuritysample.configuration.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.Key;
import java.util.Date;

import jakarta.servlet.http.HttpServletResponse;
import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

@Slf4j(topic = "JwtUtil")
@UtilityClass
public class JwtUtil {
	private final String AUTHORIZATION_HEADER = "Authorization";
	private final String AUTHORIZATION_KEY = "auth";
	private final String BEARER_PREFIX = "Bearer ";

	private final int VALUE_INDEX = 7;
	private final long TOKEN_DURATION = 60 * 60 * 1000L; // 60분

	private final SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;
	private final Key key = Keys.secretKeyFor(signatureAlgorithm);

	public String createToken(String username) {
		Date now = new Date();

		return BEARER_PREFIX +
			Jwts.builder()
				.setSubject(username) // 사용자 식별자값(ID)
				.claim(AUTHORIZATION_KEY, "ROLE_MEMBER") // 사용자 권한
				.setExpiration(new Date(now.getTime() + TOKEN_DURATION)) // 만료 시간
				.setIssuedAt(now) // 발급일
				.signWith(key, signatureAlgorithm) // 암호화 알고리즘
				.compact();
	}

	public String getTokenFromHeader(HttpServletRequest request) {
		String token = request.getHeader(AUTHORIZATION_HEADER);

		if (StringUtils.hasText(token) && token.startsWith(BEARER_PREFIX)) {
			return token.substring(VALUE_INDEX);
		}
		return null;
	}

	public boolean validateToken(String token) {
		try {
			Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
			return true;
		} catch (SecurityException | MalformedJwtException e) {
			log.error("Invalid JWT signature, 유효하지 않는 JWT 서명 입니다.");
		} catch (ExpiredJwtException e) {
			log.error("Expired JWT token, 만료된 JWT token 입니다.");
		} catch (UnsupportedJwtException e) {
			log.error("Unsupported JWT token, 지원되지 않는 JWT 토큰 입니다.");
		} catch (IllegalArgumentException e) {
			log.error("JWT claims is empty, 잘못된 JWT 토큰 입니다.");
		}
		return false;
	}

	public Claims getUserInfoFromToken(String token) {
		return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody();
	}

	/*
		jwt token 생성 후, 클라이언트 cookie에 "Authorization"으로 저장
	 */
	/*public void addJwtToCookie(String jwtToken, HttpServletResponse response) {
		try {
			//JWT token값에 공백문자가 있으면 안되므로, 공백이 있는 경우 %20 아스키문자로 변환
			jwtToken = URLEncoder.encode(jwtToken, "utf-8").replaceAll("\\+", "%20");

			//AUTHTENTICATION_HEADER name으로 JWT token을 cookie로 저장
			Cookie cookie = new Cookie(AUTHORIZATION_HEADER, jwtToken);
			cookie.setPath("/");

			//Response 객체에 Cookie 추가
			response.addCookie(cookie);
		} catch (UnsupportedEncodingException e) {
			log.error(e.getMessage());
		}
	}*/
}
