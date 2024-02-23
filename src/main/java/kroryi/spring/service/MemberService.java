package kroryi.spring.service;


import kroryi.spring.entity.Member;
import kroryi.spring.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.Map;
import java.util.Optional;

@Service
@Slf4j
@RequiredArgsConstructor
public class MemberService extends DefaultOAuth2UserService{
    private final MemberRepository memberRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        Map<String, Object> attributes = super.loadUser(userRequest).getAttributes();
        log.info("ATTR INFO : {}", attributes.toString());

        String email = null;
        String oauthType = userRequest.getClientRegistration().getRegistrationId();

        OAuth2User user2 = super.loadUser(userRequest);

        email = switch (oauthType.toLowerCase()) {
            case "kakao" -> ((Map<String,Object>)attributes.get("kakao_account")).get("email").toString();
            case "google" -> attributes.get("email").toString();
            case "naver" -> ((Map<String,Object>)attributes.get("response")).get("email").toString();
            default -> email;
        };

        if(getUserByEmailAndOAuthType(email,oauthType) == null) {
            log.info("{}({}) NOT EXISTS. RESISTER", email, oauthType);
            Member member = new Member();
            member.setEmail(email);
            member.setOauthType(oauthType);

            save(member);
        }
        return super.loadUser(userRequest);
    }

    public void save(Member member) {
        memberRepository.save(member);
    }

    public Member getUserByEmailAndOAuthType(String email, String oauthType) {
        return memberRepository.findByEmailAndOauthType(email, oauthType).orElse(null);
    }

    public Member findByUserId(Long userId){
        return memberRepository.findById(userId)
                .orElseThrow(()->new IllegalArgumentException("unexpected user"));
    }

}
