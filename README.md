﻿# tutorial-jwt-api


## 기능
- 회원가입
- 로그인
- 권한 확인


## 토큰 발급 / 인증 분리
- [사용자] 인증 요청 --> [토큰 발급 서버] 토큰 발급 --> [사용자] 사용자 페이지 요청 --> [API 게이트웨이 서버] 토큰 검증 --> [API 서버] 데이터 리텅 --> [사용자] 서비스 이용
