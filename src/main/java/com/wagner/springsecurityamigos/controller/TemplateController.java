package com.wagner.springsecurityamigos.controller;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/")
public class TemplateController {

    @GetMapping("/inicio/login") // vide classe ApplicationSecurityConfig. Lá indica a pagina de login (.loginPage("/inicio"))
    public String getLoginView(){
        System.out.println("pagina de login");
        return "pagina_de_login"; //esta String deve corresponder ao nome da pagina de login no diretório "resources/templates"
    }

    @GetMapping("/courses")
    public String getCourses(){

        System.out.println("courses");
        return "courses";
    }



//  endpoint de teste para verificar se o usuário está autenticado ou não no sistema
    @GetMapping("/autenticado")
    public String getAutenticado(){
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (!(auth instanceof AnonymousAuthenticationToken)) {
            System.out.println(auth.getPrincipal());
            System.out.println("AUTENTICADO");
            return "courses";
        }
        System.out.println("NÃO autenticado");
        return "pagina_de_login";
    }




}
