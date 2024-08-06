package com.diefthyntis.TwoautJwtApi.auth;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;


import com.diefthyntis.TwoautJwtApi.service.UserService;

/*
 What we do inside doFilterInternal():
– get JWT from the Authorization header (by removing Bearer prefix)
– if the request has JWT, validate it, parse username from it
– from username, get UserDetails to create an Authentication object
– set the current UserDetails in SecurityContext using setAuthentication(authentication) method.
 */

/*
 En résumé, ce filtre vérifie la présence et la validité d'un JWT dans chaque requête HTTP entrante. 
 Si le JWT est valide, il extrait les détails de l'utilisateur, 
 crée un objet d'authentification et l'authentifie dans le contexte de sécurité de Spring. 
 Cela permet de sécuriser les routes de l'application en vérifiant les autorisations des utilisateurs à chaque requête.
 */

public class Watchdog extends OncePerRequestFilter {
	@Autowired
	private Toolbox toolbox;

	@Autowired
	private UserService userDetailsService;

	private static final Logger logger = LoggerFactory.getLogger(Watchdog.class);

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		try {
			String jwt = parseJwt(request);

			/*
			 * 2 - Validation du JWT : Si un JWT est présent et valide (vérifié par
			 * jwtUtils.validateJwtToken(jwt)), le nom d'utilisateur est extrait du token
			 * (jwtUtils.getUserNameFromJwtToken(jwt)).
			 */
			if (jwt != null && toolbox.validateJwtToken(jwt)) {
				String username = toolbox.getUserNameFromJwtToken(jwt);

				/*
				 * 3 - Chargement des détails de l'utilisateur : Les détails de l'utilisateur
				 * sont chargés en utilisant le nom d'utilisateur extrait.
				 */
				UserDetails userDetails = userDetailsService.loadUserByUsername(username);

				/*
				 * 4 - Création de l'objet Authentication : Un objet
				 * UsernamePasswordAuthenticationToken est créé avec les détails de
				 * l'utilisateur et les autorités associées.
				 */
				UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
						userDetails, null, userDetails.getAuthorities());
				authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

				/*
				 * 5 - Stockage de l'authentification dans le contexte de sécurité : L'objet
				 * d'authentification est stocké dans le SecurityContextHolder pour que
				 * l'utilisateur authentifié soit disponible dans le contexte de sécurité de
				 * Spring.
				 */
				SecurityContextHolder.getContext().setAuthentication(authentication);
			}
		} catch (Exception e) {
			logger.error("Cannot set user authentication: {}", e);
		}

		/*
		 * Passage au filtre suivant : La chaîne de filtres est continuée avec
		 * filterChain.doFilter(request, response).
		 */
		filterChain.doFilter(request, response);
	}

	private String parseJwt(HttpServletRequest request) {
		/*
		 * 1 - La méthode parseJwt est appelée pour extraire le JWT de l'en-tête
		 * Authorization de la requête HTTP. Le JWT est supposé être précédé du préfixe
		 * Bearer .
		 */
		String headerAuth = request.getHeader("Authorization");

		if (StringUtils.hasText(headerAuth) && headerAuth.startsWith("Bearer ")) {
			return headerAuth.substring(7);
		}

		return null;
	}
}