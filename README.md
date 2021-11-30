# oauth2 授权服务

## endpoints

```text
{[/oauth/authorize]}
{[/oauth/authorize],methods=[POST]
{[/oauth/token],methods=[GET]}
{[/oauth/token],methods=[POST]}
{[/oauth/check_token]}
{[/oauth/error]}
```

## 账号信息

- 登录账号密码：yl/123
- 应用信息：client_id=app-1，client_secret=123456，redirect_uri=https://www.baidu.com
- Authorization 要加在请求头中，格式为 Basic base64(client_id:client_secret)，即 Base64 编码

## 获取 Token

### 授权码模式

#### 授权

```shell
GET http://localhost:8080/oauth/authorize?response_type=code&client_id=app-1&state=xyz&redirect_uri=https://www.baidu.com?wq=apisix&scope=all
```

#### 通过 code 获取 Token

```shell
# scope 参数可以选
POST http://localhost:8080/oauth/token?grant_type=authorization_code&code=ma38G8&redirect_uri=https://www.baidu.com?wq=apisix&scope=all
Authorization: Basic YXBwLTE6MTIzNDU2
```

> 正常返回

```json
{
  "access_token": "702d9f90-0e32-4896-824c-7ab473ddb3d5",
  "token_type": "bearer",
  "refresh_token": "f1cfc5fb-8775-4d37-9b62-f65075a7b338",
  "expires_in": 7199,
  "scope": "all"
}
```

> 异常返回

可自定义异常返回格式，参考：org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer#exceptionTranslator

```json
{
  "error": "invalid_grant",
  "error_description": "Invalid authorization code: ma38G8"
}
```

### password 模式

```shell
# scope 参数可以选
POST http://localhost:8080/oauth/token?username=yl&password=123&grant_type=password&scope=all
Authorization: Basic YXBwLTE6MTIzNDU2
```

> 正常返回

```json
{
  "access_token": "702d9f90-0e32-4896-824c-7ab473ddb3d5",
  "token_type": "bearer",
  "refresh_token": "f1cfc5fb-8775-4d37-9b62-f65075a7b338",
  "expires_in": 7181,
  "scope": "all"
}
```

> 异常返回

```json
{
  "error": "invalid_grant",
  "error_description": "用户名或密码错误"
}
```

### client 模式

```shell
# scope 参数可以选
POST http://localhost:8080/oauth/token?grant_type=client_credentials&scope=all&client_id=app-1&client_secret=123456
```

> 正常返回

```json
{
  "access_token": "56465b41-429d-436c-ad8d-613d476ff322",
  "token_type": "bearer",
  "expires_in": 25074,
  "scope": "select"
}
```

> 异常返回

```json
{
  "error": "invalid_client",
  "error_description": "Bad client credentials"
}
```

## 刷新 Token

```shell
# scope 参数可以选
POST http://localhost:8080/oauth/token?scope=all&grant_type=refresh_token&refresh_token=27f4a6d6-d19f-49f4-9e50-ea09d1715203
Authorization: Basic YXBwLTE6MTIzNDU2
```

> 正常返回

```json
{
  "access_token": "ffd740f7-efec-49e3-ac02-43080ab4da94",
  "token_type": "bearer",
  "refresh_token": "1f24341d-f01f-4108-9a07-3f4070d5f219",
  "expires_in": 7199,
  "scope": "all"
}
```

> 异常返回

```json
{
  "error": "invalid_grant",
  "error_description": "Invalid refresh token: 27f4a6d6-d19f-49f4-9e50-ea09d1715203"
}
```

# user 资源服务器

## 资源

在配置中，我们已经配置了对 user 资源的保护

- 有权限：http://127.0.0.1:8081/user/me?access_token=a689b8e7-fc3d-4fc9-9cae-4259c0bb0af3x

- 无权限：http://127.0.0.1:8081/user/info?access_token=a689b8e7-fc3d-4fc9-9cae-4259c0bb0af3

## 自定义异常返回格式

部分异常返回格式自定义可以在授权服务器配置（建议，方便统一格式），也可以在资源服务器配置（不建议）。

### access_denied

```json
{
  "error": "access_denied",
  "error_description": "不允许访问"
}
```

```java
// 自定义 access_denied 返回格式
// 优先级：方法一 > 方法二
// 方法一：org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter#configure(HttpSecurity http)
@Override
public void configure(HttpSecurity http)throws Exception{
        http.exceptionHandling()
        .accessDeniedHandler((request,response,accessDeniedException)->{
        response.setContentType("application/json; charset=utf-8");
        response.getWriter().println("{\"code\": -1, \"msg\": \"没有访问权限\"}");
        });
        }

// 方法二：org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter#configure(ResourceServerSecurityConfigurer resources)
@Override
public void configure(ResourceServerSecurityConfigurer resources)throws Exception{
        resources.accessDeniedHandler((request,response,accessDeniedException)->{
        response.setContentType("application/json; charset=utf-8");
        response.getWriter().println("{\"code\": -1, \"msg\": \"resources 没有访问权限\"}");
        });
        }
```

### invalid_token

```json
{
  "error": "invalid_token",
  "error_description": "dc4c9e29-a690-49fc-af5c-36f5fd76b87d"
}
```

```java
// 自定义 invalid_token 异常返回格式
// 这种方式不生效，未看源码找原因
// org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter#configure(HttpSecurity http)
@Override
public void configure(HttpSecurity http)throws Exception{
        OAuth2AuthenticationEntryPoint entryPoint=new OAuth2AuthenticationEntryPoint();
        // 方法一：异常转换器
        entryPoint.setExceptionTranslator(xxx);
        // 方法二：_异常渲染器
        entryPoint_.setExceptionRenderer(xxx);
        resources.authenticationEntryPoint(entryPoint);
        }

// 这种方式生效
// org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter#configure(ResourceServerSecurityConfigurer resources)
@Override
public void configure(ResourceServerSecurityConfigurer resources)throws Exception{
        OAuth2AuthenticationEntryPoint entryPoint=new OAuth2AuthenticationEntryPoint();
        // 方法一：异常转换器
        entryPoint.setExceptionTranslator(xxx);
        // 方法二：异常渲染器
        entryPoint.setExceptionRenderer(xxx);
        resources.authenticationEntryPoint(entryPoint);
        }
```

### invalid_scope

```json
{
  "error": "invalid_scope",
  "error_description": "Invalid scope: reda",
  "scope": "all"
}
```

```java
// 自定义 invalid_scope 异常返回格式
```
