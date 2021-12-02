package top.ylonline.easysso.user.config;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.DefaultUserAuthenticationConverter;
import org.springframework.security.oauth2.provider.token.RemoteTokenServices;

/**
 * @author yl
 */
@Configuration
@EnableResourceServer
@EnableGlobalMethodSecurity(prePostEnabled = true)
@RequiredArgsConstructor
public class ResourceServerConfig extends ResourceServerConfigurerAdapter {
    @Value("${security.oauth2.client.client-id}")
    private String clientId;

    @Value("${security.oauth2.client.client-secret}")
    private String secret;

    @Value("${security.oauth2.authorization.check-token-access}")
    private String checkTokenEndpointUrl;

    // @Autowired
    // private RedisConnectionFactory redisConnectionFactory;

    private final UserDetailsService userDetailsService;

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http
                // Since we want the protected resources to be accessible in the UI as well we need
                // session creation to be allowed (it's disabled by default in 2.0.6)
                // .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                // .and()
                .requestMatchers().anyRequest()
                .and()
                .anonymous()
                .and()
                .authorizeRequests()
                // 配置 /user/** 访问控制，必须认证过后才可以访问
                .antMatchers("/user/**").authenticated();

        http.exceptionHandling()
                .accessDeniedHandler((request, response, accessDeniedException) -> {
                    response.setContentType("application/json; charset=utf-8");
                    response.getWriter().println("{\"code\": -1, \"msg\": \"http 没有访问权限\"}");
                })
        ;
    }

    // @Bean
    // public TokenStore redisTokenStore() {
    //     return new RedisTokenStore(redisConnectionFactory);
    // }

    // @Bean
    // public RemoteTokenServices tokenService() {
    //     RemoteTokenServices tokenService = new RemoteTokenServices();
    //     // tokenService.setRestTemplate();
    //     tokenService.setClientId(clientId);
    //     tokenService.setClientSecret(secret);
    //     tokenService.setCheckTokenEndpointUrl(checkTokenEndpointUrl);
    //     return tokenService;
    // }

    @Override
    public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
        // resources.tokenServices(tokenService());
        RemoteTokenServices tokenService = new RemoteTokenServices();
        // tokenService.setRestTemplate();
        tokenService.setClientId(clientId);
        tokenService.setClientSecret(secret);
        tokenService.setCheckTokenEndpointUrl(checkTokenEndpointUrl);

        DefaultUserAuthenticationConverter userAuthenticationConverter = new DefaultUserAuthenticationConverter();
        userAuthenticationConverter.setUserDetailsService(userDetailsService);

        DefaultAccessTokenConverter accessTokenConverter = new DefaultAccessTokenConverter();
        accessTokenConverter.setUserTokenConverter(userAuthenticationConverter);

        tokenService.setAccessTokenConverter(accessTokenConverter);
        resources.tokenServices(tokenService);

        // OAuth2AuthenticationEntryPoint entryPoint = new OAuth2AuthenticationEntryPoint();
        // // 方法一：异常转换器
        // entryPoint.setExceptionTranslator(null);
        // // 方法二：异常渲染器
        // // entryPoint.setExceptionRenderer(null);
        // resources.authenticationEntryPoint(entryPoint);
        // resources.accessDeniedHandler((request, response, accessDeniedException) -> {
        //     response.setContentType("application/json; charset=utf-8");
        //     response.getWriter().println("{\"code\": -1, \"msg\": \"resources 没有访问权限\"}");
        // });
    }
}
