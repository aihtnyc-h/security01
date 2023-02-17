package com.example.security.config;

import com.example.security.security.CustomAccessDeniedHandler;
import com.example.security.security.CustomAuthenticationEntryPoint;
import com.example.security.security.CustomSecurityFilter;
import com.example.security.security.UserDetailsServiceImpl;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@RequiredArgsConstructor
@EnableWebSecurity // 스프링 Security 지원을 가능하게 함
@EnableGlobalMethodSecurity(securedEnabled = true) // @Secured 어노테이션 활성화

public class WebSecurityConfig {

    private final CustomAuthenticationEntryPoint customAuthenticationEntryPoint;
    private final CustomAccessDeniedHandler customAccessDeniedHandler;
    private final UserDetailsServiceImpl userDetailsService;

    // 암호화 기능을 추가!!!
    @Bean // 비밀번호 암호화 기능 등록
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
    //
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {  // webSecurityCustomizer 아래의 시크리티 설정들 보다 우선적을 걸리는 설정이다.
        // h2-console 사용 및 resources 접근 허용 설정
        return (web) -> web.ignoring()
                .requestMatchers(PathRequest.toH2Console())
                .requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        // CSRF 설정
        http.csrf().disable();

        http.authorizeRequests().antMatchers("/api/user/**").permitAll()
                // 시크릿티는 모든 요청들을 다 인증을 하고 있다! permitAll을 통해 인증을 하지 않고 실행을 할 수 있다!
//                .antMatchers("/h2-console/**").permitAll()
//                .antMatchers("/css/**").permitAll()
//                .antMatchers("/js/**").permitAll()
//                .antMatchers("/images/**").permitAll()
//                .requestMatchers(PathRequest.toStaticResources().atCommonLocations()).permitAll()
                // Http 메서드를 사용함으로 써 직겁 get post put 등을 설정하고 주소 설정까지 할 수 있다!
                //.antMatchers(HttpMethod.GET,"/api/user").anonymous()
                // 그외의 요청들을 인증처리 하겠다!
                .anyRequest().authenticated();

        // 로그인 사용
        //http.formLogin().loginPage; // 시크릿티에서 제공하는 디폴트 formLogin!

        // Custom 로그인 페이지 사용
        http.formLogin().loginPage("/api/user/login-page").permitAll();
        // 로그인 페이지로 보낼 때 기존의 로그인 페이지가 아니라 우리가 커스텀한 로그인 페이지를 반환하는 URL로 요청이 된다.
        // permitAll()로 이 요청을 다 허가해 주겠다!

        // Custom Filter 등록하기
        http.addFilterBefore(new CustomSecurityFilter(userDetailsService, passwordEncoder()), UsernamePasswordAuthenticationFilter.class);
        // 어떠한 필터 전에 추가하겠다! 새로운 고갹 시크릿티필터를
        // 비밀번호가 생성된다!

        // 접근 제한 페이지 이동 설정
        //http.exceptionHandling().accessDeniedPage("/api/user/forbidden");
        // 401 Error 처리, Authorization 즉, 인증과정에서 실패할 시 처리
        http.exceptionHandling().authenticationEntryPoint(customAuthenticationEntryPoint);

        // 403 Error 처리, 인증과는 별개로 추가적인 권한이 충족되지 않는 경우
        http.exceptionHandling().accessDeniedHandler(customAccessDeniedHandler);


        return http.build();
    }

}
// 스프링 시크릿티는 기본적으로는 세션 방식을 사용해서 인증 처리를 한다.