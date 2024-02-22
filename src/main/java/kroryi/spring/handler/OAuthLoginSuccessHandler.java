package kroryi.spring.handler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import kroryi.spring.entity.Member;
import kroryi.spring.service.MemberService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Map;

@Slf4j
@Component
public class OAuthLoginSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
    @Autowired
    private MemberService memberService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        OAuth2AuthenticationToken token = (OAuth2AuthenticationToken) authentication;
        String email = null;
        String oauthType = token.getAuthorizedClientRegistrationId();

        email = switch (oauthType.toLowerCase()) {
            case "kakao" -> ((Map<String, Object>)token.getPrincipal().getAttribute("kakao_account")).get("email").toString();
            case "naver" -> ((Map<String, Object>)token.getPrincipal().getAttribute("response")).get("email").toString();
            case "google" -> token.getPrincipal().getAttribute("email").toString();
            default -> email;
        };

        log.info("LOGIN SUCCESS : {} FROM {}", email, oauthType);
        Member member = memberService.getUserByEmailAndOAuthType(email, oauthType);

        log.info("USER SAVED IN SESSION");
        HttpSession session = request.getSession();
        session.setAttribute("member", member);

        super.onAuthenticationSuccess(request, response, authentication);
    }

}
