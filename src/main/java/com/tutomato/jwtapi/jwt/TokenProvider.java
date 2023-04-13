package com.tutomato.jwtapi.jwt;

import io.jsonwebtoken.*;
import org.springframework.security.core.userdetails.User;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

//토큰 생성
//토큰 권한 확인
//토큰 유효성 검사
@Component
public class TokenProvider implements InitializingBean {

    private final Logger logger = LoggerFactory.getLogger(TokenProvider.class);

    private static final String AUTHORITIES_KEY = "auth";

    private final String secret;
    private final long tokenValidityInMilliseconds;

    private Key key;

    public TokenProvider(
            @Value("${jwt.secret}") String secret,
            @Value("${jwt.token-validity-in-seconds}") long tokenValidityInMilliseconds){
        this.secret = secret;
        this.tokenValidityInMilliseconds = tokenValidityInMilliseconds * 1000;
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        //Base64인코딩 String key값을 디코딩 후 byte[] 변환
        byte[] keyByte = Decoders.BASE64.decode(secret);
        //앞전에 생성된 byte 배열 key값을 사용하여 Key객체 초기화
        this.key = Keys.hmacShaKeyFor(keyByte);
    }

    /*Authentication 권한 정보를 이용하여 Token 객체 생성*/
    public String createToken(Authentication authentication){
     
        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        long now = (new Date()).getTime();
        Date validity = new Date(now + this.tokenValidityInMilliseconds);

        return Jwts.builder()
                //.setHeaderParam("foo", "bar") JWT의 claims와 관련된 컨텐츠, 형식, 암호화 작업에 대한 메타데이터를 제공
                .setSubject(authentication.getName())
                .claim(AUTHORITIES_KEY, authorities) // claim이란 JWT의 body이고 JWT 생성자가 JWT를 받는이들에게 제시하기 바라는 정보를 포함한다.
            /*
                    JwtBuilder는 JWT스펙에 정의한 기본으로 등록된 Cliam names에 대해서 다음과 같은 편리한 setter 메서드를 제공한다.
                setIssuer: iss (Issuer) Claim
                setSubject: sub (Subject) Claim
                setAudience: aud (Audience) Claim
                setExpiration: exp (Expiration Time) Claim
                setNotBefore: nbf (Not Before) Claim
                setIssuedAt: iat (Issued At) Claim
                setId: jit(JWT ID) Claim
            */
                .signWith(key, SignatureAlgorithm.HS512) // JwtBuilder의 signWith 메소드를 호출하여 sign key를 지정하고, JJWT가 지정된 key에 허용된 가장 안전한 알고리즘을 결정하도록 하는게 좋다
                .setExpiration(validity) // 토큰 만료 기간 설정
                .compact();
    }

    /*Token의 권한 정보를 이용하여 Authentication 객체 리턴*/
    public Authentication getAuthentication(String token){
        Claims claims = Jwts
                .parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();

        Collection<? extends GrantedAuthority> authorities =
                Arrays.stream(claims.get(AUTHORITIES_KEY).toString().split(","))
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());

        User principal = new User(claims.getSubject(), "", authorities);

        return new UsernamePasswordAuthenticationToken(principal, token, authorities);
    }

    /*토큰 정보 검증*/
    public boolean validateToken(String token){
        try{
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            return true;
        }catch (SecurityException | MalformedJwtException e){
            logger.error("잘못된 JWT 서명", e);
        }catch (ExpiredJwtException e){
            logger.error("만료된 JWT 토큰", e);
        }catch (UnsupportedJwtException e){
            logger.error("지원하지 않는 JWT 토큰", e);
        }catch (IllegalArgumentException e){
            logger.error("JWT 토큰 정보가 잘못되었습니다.", e);
        }

        return false;
    }
}
