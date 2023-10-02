package msrfyl.app.oauth.security

import com.nimbusds.jose.jwk.JWKSelector
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import kong.unirest.HttpResponse
import msrfyl.app.oauth.OauthApplication
import msrfyl.app.oauth.U
import org.slf4j.LoggerFactory
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.Ordered
import org.springframework.core.annotation.Order
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint
import org.springframework.web.context.request.RequestContextHolder
import org.springframework.web.context.request.ServletRequestAttributes
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.time.Duration
import java.util.*


@Configuration(proxyBeanMethods = false)
class AuthorizationServerConfig {

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    @Throws(Exception::class)
    fun authServerSecurityFilterChain(http: HttpSecurity): SecurityFilterChain? {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http)
        http.formLogin { it.loginPage("/login") }
        http.sessionManagement { it.sessionCreationPolicy(SessionCreationPolicy.NEVER) }
        return http.build()
    }


    @Bean
    fun registeredClientRepository(): RegisteredClientRepository? {
        val client: MutableList<RegisteredClient> = U.registerClient().map {
            LoggerFactory.getLogger(AuthorizationServerConfig::class.java).info("register client: ${it.clientId}")
            val r = RegisteredClient.withId(UUID.randomUUID().toString())
                    .clientId(it.clientId)
                    .clientSecret("{noop}${it.clientSecret}")
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            it.authorizationGrantTypes.forEach { ag ->
                r.authorizationGrantType(
                        when (ag) {
                            "client_credentials" -> AuthorizationGrantType.CLIENT_CREDENTIALS
                            "refresh_token" -> AuthorizationGrantType.REFRESH_TOKEN
                            "authorization_code" -> AuthorizationGrantType.AUTHORIZATION_CODE
                            "jwt_bearer" -> AuthorizationGrantType.JWT_BEARER
                            else -> AuthorizationGrantType.PASSWORD
                        }
                )
            }
            it.redirectUrl?.let { re -> r.redirectUri(re) }
            it.scopes.forEach { sc -> r.scope(sc) }
            r.tokenSettings(
                    TokenSettings.builder().accessTokenTimeToLive(Duration.ofSeconds(it.accessTokenExpired)).refreshTokenTimeToLive(Duration.ofSeconds(it.refreshTokenExpired)).build()
            ).build()
        }.toMutableList()

        return InMemoryRegisteredClientRepository(*client.toTypedArray())
    }

    @Bean
    fun jwkSource(): JWKSource<SecurityContext?>? {
        val rsaKey = generateRsa()
        val jwkSet = JWKSet(rsaKey)
        return JWKSource { jwkSelector: JWKSelector, _: SecurityContext? ->
            jwkSelector.select(
                    jwkSet
            )
        }
    }

    private fun generateRsa(): RSAKey {
        val keyPair = generateRsaKey()
        val publicKey = keyPair.public as RSAPublicKey
        val privateKey = keyPair.private as RSAPrivateKey
        return RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build()
    }

    private fun generateRsaKey(): KeyPair {
        val keyPair: KeyPair = try {
            val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
            keyPairGenerator.initialize(2048)
            keyPairGenerator.generateKeyPair()
        } catch (ex: java.lang.Exception) {
            throw IllegalStateException(ex)
        }
        return keyPair
    }

    @Bean
    fun authorizationServerSettings(): AuthorizationServerSettings {
        return AuthorizationServerSettings.builder()
                .issuer(U.authUrl)
                .build()
    }

    @Bean
    fun jwtCustomizer(): OAuth2TokenCustomizer<JwtEncodingContext>? {
        return OAuth2TokenCustomizer { context: JwtEncodingContext ->
            println("OAuth2TokenCustomizer...")
            if ((AuthorizationGrantType.AUTHORIZATION_CODE == context.authorizationGrantType || AuthorizationGrantType.REFRESH_TOKEN == context.authorizationGrantType) && OAuth2TokenType.ACCESS_TOKEN == context.tokenType) {
                println("if...")
                val principal: Authentication = context.getPrincipal()
                val res: HttpResponse<Map<*, *>> = U.accessClient.post("${U.clientUrl}/tokenData")
                        .field("username", principal.name)
                        .asObject(Map::class.java)
                res.body.entries.forEach {
                    context.claims.claim(it.key.toString(), it.value)
                }
            }

            val requestAttributes = RequestContextHolder.getRequestAttributes()
            val request = (requestAttributes as ServletRequestAttributes).request
            val prt = if (request.isSecure) "https" else "http"
            context.claims.claim("iss", "$prt://${request.serverName}:${request.serverPort}")
        }
    }

}