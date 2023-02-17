package com.example.security.controller;

import com.example.security.dto.SignupRequestDto;
import com.example.security.entity.User;
import com.example.security.entity.UserRoleEnum;
import com.example.security.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;

import java.util.Optional;

@Controller
@RequiredArgsConstructor
@RequestMapping("/api/user")
public class UserController {

    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;

    // ADMIN_TOKEN
    private static final String ADMIN_TOKEN = "AAABnvxRVklrnYxKZ0aHgTBcXukeZygoC";

    @GetMapping("/signup")
    public ModelAndView signupPage() {
        return new ModelAndView("signup");
    }

    @GetMapping("/login-page")
    public ModelAndView loginPage() {
        return new ModelAndView("login");
    }

    @PostMapping("/signup")
    public String signup(SignupRequestDto signupRequestDto) {

        String username = signupRequestDto.getUsername();
        //패스워드 암호화!!
        String password = passwordEncoder.encode(signupRequestDto.getPassword());

        // 회원 중복 확인
        Optional<User> found = userRepository.findByUsername(username);
        if (found.isPresent()) {
            throw new IllegalArgumentException("중복된 사용자가 존재합니다.");
        }

        // 사용자 ROLE 확인
        UserRoleEnum role = UserRoleEnum.USER;
        if (signupRequestDto.isAdmin()) {
            if (!signupRequestDto.getAdminToken().equals(ADMIN_TOKEN)) {
                throw new IllegalArgumentException("관리자 암호가 틀려 등록이 불가능합니다.");
            }
            role = UserRoleEnum.ADMIN;
        }

        User user = new User(username, password, role);
        userRepository.save(user);

        return "redirect:/api/user/login-page";
    }
    //@AuthenticationPrincipal : 인증객체의 principal 부분의 값을 가지고 온다.
    // 필터에서 인증 객체를 만들 때 principal부분에 UserDetaoils를 넣어줬기 때문에 파라미터로 받아 올 수 있다.
    @PostMapping("/login")
    public String login(@AuthenticationPrincipal UserDetails userDetails) {
        System.out.println("*********************************************************");
        System.out.println("UserController.login");
        System.out.println("userDetails.getUsername() = " + userDetails.getUsername());
        System.out.println("*********************************************************");

        return "redirect:/api/user/login-page";
    }
    @PostMapping("/forbidden")
    public ModelAndView forbidden() {
        return new ModelAndView("forbidden");
    }
}
// 실행시 아래와 같은 결과가 나옴(아직 가입을 안했기 때문!)
//username = null
//password = null
//request.getRequestURI() = /api/user/login-page

// 회원가입을 하게 된다면
//username = user
// password = 1234
//request.getRequestURI() = /api/user/signup

// h2-console (DB 저장 확인!)
// URL : jdbc:h2:mem:db;
// USERS 테이블을 클릭하면 SELECT * FROM USERS 자동 생성! RUN을 누르면 회원가입이 잘 되었다는 것을 확인 할 수 있다!
// 패스워드가 암호화 된 것을 확인 할 수 있음 $2a$10$GhcGR1WQbCuk923HCd8xA.TR2rtwgBhJrAkaZm/FJs9fAaWzjP0N.