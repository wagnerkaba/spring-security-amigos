

# Métodos de autenticação

Na classe _ApplicationSecurityConfig_, podemos configurar o método de autenticação.


## Basic Auth

```
.httpBasic();
```

- É preciso enviar login e senha em todo request
- Não é possível fazer logout, uma vez que em todo request envia-se login e senha

## Form Based Authentication

```
.formLogin();
```

- Se um usuário faz um request e não está logado, o Spring envia um formulário de login e senha.
- É possível fazer logout
- Quando o usuário é autenticado, o Spring envia um cookie para o usuário com a SESSIONID. Por default, essa SESSIONID é gravada na memória do servidor pelo Spring. Mas a SESSIONID também pode ser gravada de outras formas, tais como POSTGRES  e REDIS.

![](F:\Workspace\spring-security-amigoscode\spring-security-amigos\README-SECURITYCONFIG - form based auth.jpg)

### Página de login customizada

Para customizar a página de login adicione:

```
.formLogin()
.loginPage("/inicio"); // endereço da pagina de login
```

Adicione thymeleaf nas dependências, para fazer a customização.

Thymeleaf is a Java template engine for processing and creating HTML, XML, JavaScript, CSS, and text.

```
<dependency>
   <groupId>org.springframework.boot</groupId>
   <artifactId>spring-boot-starter-thymeleaf</artifactId>
</dependency>
```

É preciso adicionar também a classe "TemplateController" (vide: package com.wagner.springsecurityamigos.controller; )

