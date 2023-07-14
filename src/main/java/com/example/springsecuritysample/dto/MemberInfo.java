package com.example.springsecuritysample.dto;

import java.util.Set;

public record MemberInfo(String email, String name, Set<String> roles) {
}
