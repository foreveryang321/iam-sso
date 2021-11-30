package top.ylonline.iamsso.user.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

/**
 * @author yl
 */
@RestController
@RequestMapping(value = "/user")
public class UserController {

    @PreAuthorize("hasAuthority('user:info')")
    @RequestMapping("/info")
    public Principal info(Principal principal) {
        return principal;
    }

    @PreAuthorize("hasAuthority('user:me')")
    @RequestMapping("/me")
    public Principal user(Principal principal) {
        return principal;
    }
}
