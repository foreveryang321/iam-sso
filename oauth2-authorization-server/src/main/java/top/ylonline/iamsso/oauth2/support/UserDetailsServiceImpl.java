package top.ylonline.iamsso.oauth2.support;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

/**
 * @author yl
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class UserDetailsServiceImpl implements UserDetailsService {
    // @Autowired
    // private UserService userService;

    private final PasswordEncoder passwordEncoder;

    /**
     * 授权的时候是对角色授权，而认证的时候应该基于资源，而不是角色，因为资源是不变的，而用户的角色是会变的
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        log.info("登录用户：{}", username);
        if (!"yl".equalsIgnoreCase(username)) {
            throw new UsernameNotFoundException("用户不存在");
        }
        // SysUser sysUser = userService.getUserByName(username);
        // if (null == sysUser) {
        //     throw new UsernameNotFoundException(username);
        // }
        // List<SimpleGrantedAuthority> authorities = new ArrayList<>();
        // for (SysRole role : sysUser.getRoleList()) {
        //     for (SysPermission permission : role.getPermissionList()) {
        //         authorities.add(new SimpleGrantedAuthority(permission.getCode()));
        //     }
        // }
        //
        // return new User(sysUser.getUsername(), sysUser.getPassword(), authorities);

        // BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();
        //        password 方案一：明文存储，用于测试，不能用于生产
        //        String finalPassword = "123456";
        //        password 方案二：用 BCrypt 对密码编码
        //        String finalPassword = bCryptPasswordEncoder.encode("123456");
        // password 方案三：支持多种编码，通过密码的前缀区分编码方式
        // String password = "{bcrypt}" + bCryptPasswordEncoder.encode("123456");
        String password = passwordEncoder.encode("123");

        List<SimpleGrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority("user:info"));
        authorities.add(new SimpleGrantedAuthority("user:list"));
        // 如果这里配置基于角色的权限，需要 ROLE_ 前缀
        // authorities.add(new SimpleGrantedAuthority("ROLE_admin"));

        return User.builder()
                .username(username)
                .password(password)
                // 基于权限
                .authorities(authorities)
                // 基于角色
                .roles("admin", "normal")
                .build();
    }
}
