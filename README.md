### Ejemplo de securización de endpoints REST con JWT



* Versión simplficada del tutorial (https://www.bezkoder.com/spring-boot-jwt-authentication/)
* Pendiente: lado cliente con REACT (ver (https://www.bezkoder.com/react-hooks-jwt-auth/))

### Ejemplo de uso


En un temrinal
```sh
cd ejemplo-jwt
mvn spring-boot:run
```

En otro terminal
```sh
curl -v --header 'Content-Type: application/json' --data '{"login":"pedro", "password":"pedro"}' --request POST  http://localhost:8080/api/auth/login

Note: Unnecessary use of -X or --request, POST is already inferred.
*   Trying 127.0.0.1:8080...
* Connected to localhost (127.0.0.1) port 8080 (#0)
> POST /api/auth/login HTTP/1.1
> Host: localhost:8080
> User-Agent: curl/7.74.0
> Accept: */*
> Content-Type: application/json
> Content-Length: 37
> 
* upload completely sent off: 37 out of 37 bytes
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 
< Vary: Origin
< Vary: Access-Control-Request-Method
< Vary: Access-Control-Request-Headers
< X-Content-Type-Options: nosniff
< X-XSS-Protection: 1; mode=block
< Cache-Control: no-cache, no-store, max-age=0, must-revalidate
< Pragma: no-cache
< Expires: 0
< X-Frame-Options: DENY
< Content-Type: application/json
< Transfer-Encoding: chunked
< Date: Thu, 16 Dec 2021 15:38:02 GMT
< 
* Connection #0 to host localhost left intact
{"token":"XXXXXXXXXXXXXXXX.YYYYYYYYYYYYYYYYYYYYYYY","id":3,"login":"pedro","roles":["ROLE_GERENTE","ROLE_USUARIO"]}

export TOKEN=XXXXXXXXXXXXXXXX.YYYYYYYYYYYYYYYYYYYYYYY

curl -v -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/prueba/usuario
curl -v -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/prueba/gerente
curl -v -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/prueba/administrador

curl -v http://localhost:8080/api/prueba/usuario









```

