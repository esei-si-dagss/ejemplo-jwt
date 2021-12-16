package es.uvigo.mei.jwt;

import java.util.Arrays;
import java.util.HashSet;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.crypto.password.PasswordEncoder;

import es.uvigo.mei.jwt.daos.UsuarioDAO;
import es.uvigo.mei.jwt.entidades.Rol;
import es.uvigo.mei.jwt.entidades.Usuario;

@SpringBootApplication
public class EjemploJWTApplication implements CommandLineRunner {

	@Autowired
	UsuarioDAO dao;

	@Autowired
	PasswordEncoder passwordEncoder;

	public static void main(String[] args) {
		SpringApplication.run(EjemploJWTApplication.class, args);
	}

	@Override
	public void run(String... args) throws Exception {
		// Creacion de usuario de ejemplo

		if (!dao.existsByLogin("juan")) {
			Usuario juan = new Usuario("juan", passwordEncoder.encode("juan"), "Juan Juanez", "juan@juan.com");
			juan.setRoles(new HashSet<>(Arrays.asList(Rol.ROLE_USUARIO)));
			dao.save(juan);
		}

		if (!dao.existsByLogin("ana")) {
			Usuario ana = new Usuario("ana", passwordEncoder.encode("ana"), "Ana Anido", "ana@ana.com");
			ana.setRoles(new HashSet<>(Arrays.asList(Rol.ROLE_USUARIO)));
			dao.save(ana);
		}
		if (!dao.existsByLogin("pedro")) {
			Usuario pedro = new Usuario("pedro", passwordEncoder.encode("pedro"), "Pedro Pedrez", "pedro@pedro.com");
			pedro.setRoles(new HashSet<>(Arrays.asList(Rol.ROLE_USUARIO, Rol.ROLE_GERENTE)));
			dao.save(pedro);
		}

		if (!dao.existsByLogin("admin")) {
			Usuario admin = new Usuario("admin", passwordEncoder.encode("admin"), "Administrador", "admin@admin.com");
			admin.setRoles(new HashSet<>(Arrays.asList(Rol.ROLE_ADMINISTRADOR)));
			dao.save(admin);
		}
	}

}
