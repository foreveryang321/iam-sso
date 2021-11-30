package top.ylonline.iamsso.oauth2.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;

import java.util.HashMap;
import java.util.Map;

/**
 * @author yl
 */
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    private static final String LOGIN_PAGE = "/login";
    private static final String LOGIN_SUCCESS = "/login-success";
    private static final String LOGIN_FAIL = "/login-fail";
    private static final String OAUTH_ENDPOINT = "/oauth";

    // @Override
    // protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    //     // 账号密码登录
    //     // auth.userDetailsService().passwordEncoder();
    //     // 微信授权登录、新浪授权登录等实现
    //     // auth.authenticationProvider(WechatAuthenticationProvider);
    //     // auth.authenticationProvider(WeiboAuthenticationProvider);
    // }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        httpSecurityConfig(http);
    }

    private void httpSecurityConfig(HttpSecurity http) throws Exception {
        // permitAll 放行配置需要在 authenticated 之前
        http
                .authorizeRequests(authorizeRequests -> authorizeRequests
                        // 对指定请求放行：不需要认证就可以访问，需要放行登录页面和登录失败页面
                        .antMatchers(
                                OAUTH_ENDPOINT + "/**",
                                LOGIN_PAGE + "/**",
                                LOGIN_FAIL + "/**"
                        ).permitAll()
                        // 需要放行静态资源
                        .antMatchers(
                                "/**/*.css",
                                "/**/*.js",
                                "/**/*.png",
                                "/**/*.gif",
                                "/**/*.jpg",
                                "/**/*.eot",
                                "/**/*.svg",
                                "/**/*.tff",
                                "/**/*.woff"
                        ).permitAll()
                        // 如果 spring.mvc.servlet.path 配置了，antMatchers、mvcMatchers 需要加上该配置
                        // .antMatchers("${spring.mvc.servlet.path}/**/*.js").permitAll()
                        // .mvcMatchers().servletPath("${spring.mvc.servlet.path}").permitAll()
                        // 其他所有请求需要认证才可以访问
                        .anyRequest().authenticated()
                );

        // 自定义登录页面需要禁用 csrf，否则会出现 404 错误
        http.csrf().disable();
        http.formLogin()
                // 自定义表单提交 username 字段，默认值查看 UsernamePasswordAuthenticationFilter#usernameParameter
                // .usernameParameter("username")
                // 自定义表单提交 username 字段，默认值查看 UsernamePasswordAuthenticationFilter#passwordParameter
                // .passwordParameter("password")

                // 自定义登录页面，默认为 GET /login，如果使用默认的，这里不用配置，配置了会包 404
                // .loginPage(LOGIN_PAGE)
                // 自定义登录页面的表单提交接口（默认为 POST /login），需要配置了这个才会执行 UserDetailsService 的逻辑
                // .loginProcessingUrl("/login")
                //
                // // 这种方式适合单体应用
                // // 登录成功跳转页面，只能是 POST 请求，不能是其他类型请求，如果使用 oauth2 等协议登录，这里不能配置登录成功跳转
                // .successForwardUrl(LOGIN_SUCCESS)
                // 登录失败跳转页面，只能是 POST 请求，不能是其他类型请求
                .failureForwardUrl(LOGIN_FAIL)

                // 这种方式适合前后端分离项目
                // 自定义登录成功处理逻辑，实现 AuthenticationSuccessHandler，如果使用 oauth2 等协议登录，这里不能配置登录成功处理器
                // .successHandler()
                // 自定义登录失败处理逻辑，实现 AuthenticationFailureHandler
                // .failureHandler()
                .permitAll()
        ;

        // 异常处理
        // http.exceptionHandling()
        //         // 处理 403 权限不足处理器，实现 AccessDeniedHandler
        //         .accessDeniedHandler();

        // 记住我
        // http.rememberMe()
        //         // 设置数据源，官方自定义支持 memory、jdbc 模式，可以自己实现 redis 模式，实现 PersistentTokenRepository
        //         .tokenRepository()
        //         // 记住我时间配置，默认：2 周，单位：秒，查看 AbstractRememberMeServices#tokenValiditySeconds
        //         .tokenValiditySeconds()
        //         // 自定义登录验证逻辑
        //         .userDetailsService();

        // 退出登录
        // http.logout()
        //         // 自定义退出请求，默认为 POST /logout
        //         .logoutUrl("/logout")
        //         // 这种方式适合单体应用，自定义退出登录成功跳转页面，默认为 GET /login?logout
        //         .logoutSuccessUrl(LOGIN_PAGE)
        //         // 这种方式适合前后端分离应用，自定义退出登录处理器，实现 LogoutSuccessHandler
        //         .logoutSuccessHandler()
        //         // 销毁 session，默认 true，查看 SecurityContextLogoutHandler#logout
        //         .invalidateHttpSession(true)
        //         // 清除 Authentication 对，默认 true
        //         .clearAuthentication(true)
        //         // 清除 cookie
        //         .deleteCookies("cookie name");
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManager() throws Exception {
        return super.authenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        String bcrypt = "bcrypt";
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        Map<String, PasswordEncoder> encoders = new HashMap<>(16);
        encoders.put(bcrypt, new BCryptPasswordEncoder());
        // encoders.put("plain", NoOpPasswordEncoder.getInstance());
        encoders.put("pbkdf2", new Pbkdf2PasswordEncoder());
        encoders.put("scrypt", new SCryptPasswordEncoder());
        //md
        // encoders.put("md4", new Md4PasswordEncoder());
        // encoders.put("md5", new MessageDigestPasswordEncoder("MD5"));
        //sha
        // encoders.put("sha1", new StandardPasswordEncoder("SHA-1", ""));
        // encoders.put("sha256", new StandardPasswordEncoder());
        // encoders.put("sha384", new StandardPasswordEncoder("SHA-384", ""));
        // encoders.put("sha512", new StandardPasswordEncoder("SHA-512", ""));

        // encoders.put("sm3", new SM3PasswordEncoder());

        // encoders.put("ldap", new LdapShaPasswordEncoder());

        //idForEncode is default for encoder
        DelegatingPasswordEncoder delegating = new DelegatingPasswordEncoder(bcrypt, encoders);
        // 如果都不匹配以上加密方式，则使用默认方式
        delegating.setDefaultPasswordEncoderForMatches(encoder);
        return delegating;
    }
}
