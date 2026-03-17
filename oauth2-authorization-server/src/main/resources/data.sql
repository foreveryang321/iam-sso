-- 用户信息表
DROP TABLE IF EXISTS t_user;

CREATE TABLE t_user
(
    id       INT AUTO_INCREMENT  PRIMARY KEY,
    username VARCHAR(250) NOT NULL,
    password VARCHAR(250) NOT NULL
);
-- 密码明文：123
INSERT INTO t_user (username, password)
VALUES ('yl', '{bcrypt}$2a$10$2KTMVaMECrXSIWYGuZ91deGECSoRejKAJulCgb33f07bQhMyhSeBq'),
       ('admin', '{bcrypt}$2a$10$2KTMVaMECrXSIWYGuZ91deGECSoRejKAJulCgb33f07bQhMyhSeBq');

-- oauth_client_details 信息表
DROP TABLE IF EXISTS oauth_client_details;

CREATE TABLE oauth_client_details
(
    id                      INT AUTO_INCREMENT  PRIMARY KEY,
    client_id               VARCHAR(250) NOT NULL,
    client_secret           VARCHAR(250) NOT NULL,
    resource_ids            VARCHAR(250) DEFAULT NULL,
    scope                   VARCHAR(250) DEFAULT NULL,
    authorized_grant_types  VARCHAR(250) DEFAULT NULL,
    web_server_redirect_uri VARCHAR(250) DEFAULT NULL,
    authorities             VARCHAR(250) DEFAULT NULL,
    access_token_validity   bigint       DEFAULT 7200,
    refresh_token_validity  bigint       DEFAULT 86400,
    additional_information  VARCHAR(250) DEFAULT NULL,
    autoapprove             VARCHAR(250) DEFAULT NULL
);

INSERT INTO oauth_client_details (client_id,
                                  client_secret,
                                  resource_ids,
                                  scope,
                                  authorized_grant_types,
                                  web_server_redirect_uri,
                                  authorities,
                                  access_token_validity,
                                  refresh_token_validity,
                                  additional_information,
                                  autoapprove)
VALUES ('app-1',
           -- 明文：123456
        '{bcrypt}$2a$10$39v2zBKepnjamrQzTNnFI.YEi7mwJ1dmNB2JFSPKGpwBDOU383En.',
        null,
        'all',
        'password,client_credentials,authorization_code,refresh_token,check_token',
        'http://127.0.0.1:8848',
        null,
        7200,
        86400,
        null,
        'true');
