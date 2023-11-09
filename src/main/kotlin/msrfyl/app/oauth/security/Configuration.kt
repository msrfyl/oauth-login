package msrfyl.app.oauth.security

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import msrfyl.app.oauth.U
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.Ordered
import org.springframework.core.annotation.Order
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
import org.springframework.security.web.SecurityFilterChain
import org.springframework.stereotype.Component
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.CorsConfigurationSource
import org.springframework.web.cors.UrlBasedCorsConfigurationSource
import java.io.IOException
import javax.servlet.Filter
import javax.servlet.FilterChain
import javax.servlet.FilterConfig
import javax.servlet.ServletException
import javax.servlet.ServletRequest
import javax.servlet.ServletResponse
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse


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
        val urlApi = "${U.getResource.url}/api/authenticate"
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

@Configuration
@Order(Ordered.HIGHEST_PRECEDENCE)
class SimpleCORSFilter : Filter {
    @Throws(ServletException::class)
    override fun init(fc: FilterConfig) {
    }

    @Throws(IOException::class, ServletException::class)
    override fun doFilter(req: ServletRequest, resp: ServletResponse, chain: FilterChain) {
        val response = resp as HttpServletResponse
        val request = req as HttpServletRequest
        response.setHeader("Access-Control-Allow-Origin", "*")
        response.setHeader("Access-Control-Allow-Methods", "PATCH,PUT,POST,GET,OPTIONS,DELETE")
        response.setHeader("Access-Control-Max-Age", "3600")
        response.setHeader(
            "Access-Control-Allow-Headers",
            "x-requested-with, authorization, Content-Type, Authorization, credential, X-XSRF-TOKEN"
        )
        if ("OPTIONS".equals(request.method, ignoreCase = true)) {
            response.status = HttpServletResponse.SC_OK
        } else {
            chain.doFilter(req, resp)
        }
    }

    override fun destroy() {}
}
