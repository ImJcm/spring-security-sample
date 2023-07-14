package com.example.springsecuritysample.repository;

import com.example.springsecuritysample.domain.entity.Member;
import org.springframework.data.jpa.repository.JpaRepository;

public interface MemberRepository extends JpaRepository<Member, String> {

	Member findByEmail(String email);
}
