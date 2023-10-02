package msrfyl.app.oauth.security

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import msrfyl.app.oauth.U
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
import org.springframework.security.web.SecurityFilterChain
import org.springframework.stereotype.Component

@Configuration
@EnableWebSecurity
class DefaultSecurityConfig {
    @Autowired
    lateinit var authProvider: MyAuthProvider

    @Bean
    @Throws(Exception::class)
    fun defaultSecurityFilterChain(http: HttpSecurity): SecurityFilterChain? {
        http.authenticationProvider(authProvider).authorizeHttpRequests {
            it.requestMatchers("/login").permitAll()
                    .requestMatchers("/bg").permitAll()
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
        val urlApi = "${U.clientUrl}/api/authenticate?username=$name&password=$password"
        val res = U.accessClient.post(urlApi)
                .field("username", name)
                .field("password", password)
                .asJson()
        logger.info("$urlApi [${res.status}]")
        logger.info("userLogin: ${res.body}")

        when (res.status) {
            200 -> {
                val rtn = UsernamePasswordAuthenticationToken(name, password, ArrayList())
                println(jacksonObjectMapper().writeValueAsString(rtn))
                return rtn
            }
            401 -> throw BadCredentialsException("authorization server cant connecting with resource")
            else -> throw BadCredentialsException("username and password didn't match")
        }
    }

    override fun supports(authentication: Class<*>): Boolean {
        return authentication == UsernamePasswordAuthenticationToken::class.java
    }

}