

package cl.harf.springboot.client.client.controllers;

import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.springframework.web.bind.annotation.RestController;

import cl.harf.springboot.client.client.models.Message;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * Controlador principal de la aplicación.
 */
@RestController
public class AppController {
    
    /**
     * Devuelve una lista de mensajes.
     *
     * @return Una lista que contiene un solo mensaje de prueba.
     */
    @GetMapping("/list")
    public List<Message> list() {
        return Collections.singletonList(new Message("Test list"));
    }
    
    /**
     * Crea un nuevo mensaje.
     *
     * @param message El mensaje a crear.
     * @return El mensaje creado.
     */
    @PostMapping("/create")
    public Message create(@RequestBody Message message) {
        System.out.println("Mensaje guardado: " + message);
        return message;
    }
    
    /**
     * Endpoint autorizado que recibe un código de autorización.
     *
     * @param code El código de autorización recibido.
     * @return Un mapa que contiene el código de autorización.
     */
    @GetMapping("/authorized")
    public Map<String, String> authorized(@RequestParam String code) {
        return Collections.singletonMap("code", code);
    }
    
}

// package cl.harf.springboot.client.client.controllers;

// import java.util.Collections;
// import java.util.List;
// import java.util.Map;

// import org.springframework.web.bind.annotation.RestController;

// import cl.harf.springboot.client.client.models.Message;
// import org.springframework.web.bind.annotation.GetMapping;
// import org.springframework.web.bind.annotation.PostMapping;
// import org.springframework.web.bind.annotation.RequestBody;
// import org.springframework.web.bind.annotation.RequestParam;


// @RestController
// public class AppController {


//     @GetMapping("/list")
//     public List<Message> list() {
//         return Collections.singletonList(new Message("Test list"));
//     }

//     @PostMapping("/create")
//     public Message create(@RequestBody Message message){
//         System.out.println("mensaje guardado: " + message );
//         return message;
//     }

//     @GetMapping("/authorized")
//     public Map<String,String> authorized(@RequestParam String code){
//         return Collections.singletonMap("code", code);

//     }

// }
// package cl.harf.springboot.client.client.controllers;

// import java.util.Collections;
// import java.util.List;
// import java.util.Map;

// import org.springframework.web.bind.annotation.RestController;

// import cl.harf.springboot.client.client.models.Message;
// import org.springframework.web.bind.annotation.GetMapping;
// import org.springframework.web.bind.annotation.PostMapping;
// import org.springframework.web.bind.annotation.RequestBody;
// import org.springframework.web.bind.annotation.RequestParam;


// @RestController
// public class AppController {


//     @GetMapping("/list")
//     public List<Message> list() {
//         return Collections.singletonList(new Message("Test list"));
//     }

//     @PostMapping("/create")
//     public Message create(@RequestBody Message message){
//         System.out.println("mensaje guardado: " + message );
//         return message;
//     }

//     @GetMapping("/authorized")
//     public Map<String,String> authorized(@RequestParam String code){
//         return Collections.singletonMap("code", code);

//     }

// }
