ALTER USER 'escola_web_user'@'localhost' IDENTIFIED BY 'D7vFg9Lp$W2s';

GRANT ALL PRIVILEGES ON security_app.* TO 'escola_web_user'@'localhost';

REVOKE SELECT ON security_app.tabela_de_senhas FROM 'escola_web_user'@'localhost';

FLUSH PRIVILEGES;
