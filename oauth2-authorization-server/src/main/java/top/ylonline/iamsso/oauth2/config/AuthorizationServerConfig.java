package top.ylonline.iamsso.oauth2.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.approval.ApprovalStore;
import org.springframework.security.oauth2.provider.approval.InMemoryApprovalStore;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;

/**
 * @author yl
 */
@Configuration
@EnableAuthorizationServer
@RequiredArgsConstructor
@Slf4j
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {
    private final AuthenticationManager authenticationManager;
    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;
    // private final ClientDetailsService clientDetailsService;
    // private final DataSource dataSource;

    // /**
    //  * 客户端信息来源
    //  */
    // @Bean
    // public ClientDetailsService clientDetailsService() {
    //     return new JdbcClientDetailsService(dataSource);
    // }

    // @Bean
    // public JwtAccessTokenConverter jwtAccessTokenConverter() {
    //     JwtAccessTokenConverter accessTokenConverter = new JwtAccessTokenConverter();
    //     accessTokenConverter.setSigningKey("dev");
    //     return accessTokenConverter;
    // }

    /**
     * token 保存策略，指你生成的 Token 要往哪里存储
     */
    @Bean
    public TokenStore tokenStore() {
        // return new RedisTokenStore(redisConnectionFactory);
        // return new JdbcTokenStore(dataSource);
        // return new JwtTokenStore(jwtAccessTokenConverter());
        return new InMemoryTokenStore();
    }


    /**
     * 授权信息保存策略
     */
    @Bean
    public ApprovalStore approvalStore() {
        // return new JdbcApprovalStore(dataSource);
        return new InMemoryApprovalStore();
    }

    // /**
    //  * 授权码模式数据来源
    //  */
    // @Bean
    // public AuthorizationCodeServices authorizationCodeServices() {
    //     // return new JdbcAuthorizationCodeServices(dataSource);
    //     return new InMemoryAuthorizationCodeServices();
    // }

    // /**
    //  * 令牌管理
    //  */
    // @Bean
    // public AuthorizationServerTokenServices tokenServices() {
    //     DefaultTokenServices tokenServices = new DefaultTokenServices();
    //     // token 保存策略
    //     tokenServices.setTokenStore(tokenStore());
    //     // 支持刷新模式
    //     tokenServices.setSupportRefreshToken(true);
    //     // 客户端信息来源
    //     tokenServices.setClientDetailsService(clientDetailsService);
    //     // token 有效期自定义设置，默认 12 小时
    //     tokenServices.setAccessTokenValiditySeconds(60 * 60 * 12);
    //     // refresh token 有效期自定义设置，默认 30 天
    //     tokenServices.setRefreshTokenValiditySeconds(60 * 60 * 24 * 7);
    //
    //     return tokenServices;
    // }

    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        /*
         * 允许客户端访问 OAuth2 授权接口，否则请求 token 会返回 401
         * 允许表单认证，如果配置支持allowFormAuthenticationForClients，且url中有client_id和client_secret的会走ClientCredentialsTokenEndpointFilter来保护
         * 如果没有支持allowFormAuthenticationForClients或者有支持但是url中没有client_id和client_secret的，走basic认证保护
         */
        security.allowFormAuthenticationForClients();
        // 允许已授权用户访问 TokenKeyEndpoint#getKey
        security.tokenKeyAccess("isAuthenticated()");
        // 允许已授权用户访问 CheckTokenEndpoint#checkToken
        security.checkTokenAccess("isAuthenticated()");
    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        // clients.withClientDetails(clientDetailsService);
        // 配置两个客户端,一个用于password认证一个用于client认证
        clients.inMemory()
                .withClient("app-1")
                .secret(passwordEncoder.encode("123456"))
                // 是否自动授权
                .autoApprove(true)
                .scopes("all")
                // .scopes("read")
                // .scopes("select", "read", "write", "trust", "openid")
                // .authorities("user:info", "ROLE_CLIENT", "ROLE_TRUSTED_CLIENT")
                // .resourceIds("user")
                .authorizedGrantTypes("password", "client_credentials", "authorization_code", "refresh_token", "check_token")
                // access_token 失效时间，单位：秒
                .accessTokenValiditySeconds(7200)
                // refresh_token 失效时间，单位：秒
                .refreshTokenValiditySeconds(7200)
                .redirectUris("https://www.baidu.com")
        ;
    }

    /**
     * 该方法是用来配置Authorization Server endpoints的一些非安全特性的，比如token存储、token自定义、授权类型等等的
     */
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints
                .approvalStore(approvalStore())
                .tokenStore(tokenStore())
                // 如果使用 JwtTokenStore，这里需要配置 JwtAccessTokenConverter
                // .accessTokenConverter(jwtAccessTokenConverter())
                // 配置这个才能启用 password 模式
                .authenticationManager(authenticationManager)
                // .authorizationCodeServices(authorizationCodeServices())
                // .tokenServices(tokenServices())
                // 配置这个才能启用 /oauth/token_key 接口
                // .accessTokenConverter(jwtAccessTokenConverter)
                .allowedTokenEndpointRequestMethods(HttpMethod.GET, HttpMethod.POST)
                // .setClientDetailsService(clientDetailsService)
                .userDetailsService(userDetailsService);

        // endpoints.exceptionTranslator(new WebResponseExceptionTranslator<OAuth2Exception>() {
        //     @Override
        //     public ResponseEntity<OAuth2Exception> translate(Exception e) throws Exception {
        //         HttpHeaders headers = new HttpHeaders();
        //         headers.set("Cache-Control", "no-store");
        //         headers.set("Pragma", "no-cache");
        //
        //         OAuth2Exception exception = OAuth2Exception.create("401", "自定义异常");
        //         return new ResponseEntity<>(exception, HttpStatus.UNAUTHORIZED);
        //     }
        // });
    }
}
