package com.wagner.springsecurityamigos.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/")
public class TemplateController {

    @GetMapping("/inicio/login") // vide classe ApplicationSecurityConfig. Lá indica a pagina de login (.loginPage("/inicio"))
    public String getLoginView(){
        return "pagina_de_login"; //esta String deve corresponder ao nome da pagina de login no diretório "resources/templates"
    }

    @GetMapping("courses")
    public String getCourses(){
        return "courses";
    }

}
