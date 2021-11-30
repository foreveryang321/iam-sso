package top.ylonline.iamsso.oauth2.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 * @author yl
 */
@Controller
public class LoginController {

    @RequestMapping("/loginPage")
    public String login() {
        return "login";
    }

    @PostMapping("/login-success")
    public String loginSuccess() {
        return "login-success";
    }

    @PostMapping("/login-fail")
    public String loginFail() {
        return "login-fail";
    }
}
