package msrfyl.app.oauth

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory
import com.fasterxml.jackson.dataformat.yaml.YAMLMapper
import kong.unirest.Unirest
import kong.unirest.UnirestInstance
import org.slf4j.LoggerFactory
import java.io.File
import kotlin.system.exitProcess


object U {
    private val logger = LoggerFactory.getLogger(U::class.java)
    const val configRunningPath = "configuration/tmp/running-configuration.yml"
    private const val configPath = "configuration/configuration.yml"

    private val configYml: Map<String, Any>? by lazy {
        try {
            ObjectMapper(YAMLFactory()).readValue(File(configPath), Map::class.java) as Map<String, Any>
        } catch (e: Exception) {
            logger.error("failed read configuration.yml", e)
            null
        }
    }

    fun buildConfiguration() {
        val fileConfig = File(configPath)
        if (!fileConfig.exists()) {
            logger.info("file configuration not found")
            exitProcess(1)
        }
        logger.info("build running configuration")
        val fileTemp = File(configRunningPath)
        if (fileTemp.exists()) {
            fileTemp.delete()
        }

        if (!File("configuration/tmp").exists()) {
            File("configuration/tmp").mkdirs()
        }

        configYml?.let {
            val mapConfig: MutableMap<String, Any> = mutableMapOf()
            mapConfig["server"] = mutableMapOf(Pair("port", it["port"] ?: 8080))
            mapConfig["spring"] = mutableMapOf(
                    Pair(
                            "security", pair("oauth2", pair("client",
                            mutableMapOf(Pair("registration", pair("auth-client", mutableMapOf(
                                    Pair("authorization-grant-type", "client_credentials"),
                                    Pair("client-id", "auth-client"),
                                    Pair("client-secret", "secret"),
                                    Pair("scope", "internal"),
                                    Pair("client-name", "auth-client")
                            ))),
                            Pair(
                                    "provider",
                                    pair("auth-client", pair("token-uri", "http://192.168.100.18:${it["port"] ?: 8080}"))
                            )
                    ))))
            )
            mapConfig["clients"] = registerClient()
            YAMLMapper().writeValue(File(configRunningPath), mapConfig)
        } ?: exitProcess(1)

    }

    private fun pair(key: String, obj: Any): MutableMap<String, Any> = mutableMapOf(Pair(key, obj))

    fun registerClient(): MutableList<Clients> {
        return configYml?.let { ci ->
            val cMap = ci["clients"] as ArrayList<Map<String, Any>>
            val client: List<Clients> = cMap.map {
                Clients(
                        (it["client-id"] ?: it["clientId"]).toString(),
                        (it["client-secret"] ?: it["clientSecret"]).toString(),
                        (it["authorization-grant-types"] ?: it["authorizationGrantTypes"]) as List<String>,
                        it["scopes"] as List<String>,
                        (it["access-token-expired"] ?: it["accessTokenExpired"]).toString().toLong(),
                        (it["refresh-token-expired"] ?: it["refreshTokenExpired"]).toString().toLong(),
                        (it["redirect-url"] ?: it["redirectUrl"]).toString()
                )
            }.toList()
            client.toMutableList()
        } ?: mutableListOf()
    }

    val authUrl: String by lazy {
        configYml?.let {
            "http://192.168.100.18:${it["port"] ?: "8080"}"
        } ?: "http://192.168.100.18:8080"
    }

    val accessClient: UnirestInstance by lazy {
        val ni = Unirest.spawnInstance()
        ni.config().interceptor(UInterceptor())
        ni
    }

    val clientUrl: String by lazy {
        configYml?.let {
            "http://${it["resource"] ?: "192.168.100.18:8080"}"
        } ?: "http://192.168.100.18:8080"
    }

    @Synchronized
    fun loadToken(): String {
        val clientAuth = registerClient().first()
        val resp = Unirest.post("$authUrl/oauth2/token")
                .basicAuth(clientAuth.clientId, clientAuth.clientSecret)
                .field("grant_type", clientAuth.authorizationGrantTypes)
                .asJson().ifFailure {
                    logger.info("load token failed")
                }
        return resp.body.`object`["access_token"].toString()
    }

}

class Clients(
        val clientId: String, val clientSecret: String, val authorizationGrantTypes: List<String>,
        val scopes: List<String>, val accessTokenExpired: Long, val refreshTokenExpired: Long,
        var redirectUrl: String?
)