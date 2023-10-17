package msrfyl.app.oauth.security

import msrfyl.app.oauth.U
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
import org.springframework.security.web.SecurityFilterChain
import org.springframework.stereotype.Component

@EnableWebSecurity
class DefaultSecurityConfig {
    @Autowired
    lateinit var authProvider: MyAuthProvider

    @Bean
    @Throws(Exception::class)
    fun defaultSecurityFilterChain(http: HttpSecurity): SecurityFilterChain? {
        http.authenticationProvider(authProvider).authorizeHttpRequests {
            it.antMatchers("/login").permitAll()
                .antMatchers("/bg").permitAll()
                .anyRequest().authenticated()
        }.formLogin {
            it.loginPage("/login")
                .failureUrl("/login?error=true")
        }
        return http.build()
    }

}

@Component
class MyAuthProvider : AuthenticationProvider {
    private val logger = LoggerFactory.getLogger(MyAuthProvider::class.java)
    @Throws(AuthenticationException::class)
    override fun authenticate(authentication: Authentication): Authentication? {
        val name: String = authentication.name
        val password: String = authentication.credentials.toString()
        val urlApi = "${U.clientUrl}/api/authenticate"
        val res = U.accessClient.post(urlApi)
            .field("username", name)
            .field("password", password)
            .asString()
        logger.info("authenticate user $name [${res.status}]")
        when (res.status) {
            200 -> {
                logger.info("success login $name")
                return UsernamePasswordAuthenticationToken(name, password, ArrayList())
            }

            401 -> throw BadCredentialsException("authorization server cant connecting with resource")
            else -> throw BadCredentialsException("username and password didn't match")
        }
    }

    override fun supports(authentication: Class<*>): Boolean {
        return authentication == UsernamePasswordAuthenticationToken::class.java
    }

}
