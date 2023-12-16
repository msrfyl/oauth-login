package msrfyl.app.oauth

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
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
    private const val clientPath = "configuration/client.yml"

    private val configYml: JsonNode? by lazy {
        val ymlMap: ObjectMapper = YAMLMapper()
        val fi = File(configPath)
        if (fi.exists()) ymlMap.readTree(fi) else null
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
            mapConfig["server"] = mutableMapOf(Pair("port", getAuth.port))
            mapConfig["spring"] = mutableMapOf(Pair(
                    "security", pair(
                    "oauth2", pair(
                    "client", mutableMapOf(Pair(
                    "registration", arrayListOf(pair(
                    "auth-client", mutableMapOf(
                    Pair("authorization-grant-type", "client_credentials"),
                    Pair("client-id", "auth-client"),
                    Pair("client-secret", "secret"),
                    Pair("scope", "internal"),
                    Pair("client-name", "auth-client")
            )))),
                    Pair("provider", pair("auth-client", pair("token-uri", getAuth.url)))
            )))))
            mapConfig["logging"] = mutableMapOf(
                Pair("level", pair("root", "INFO")),
                Pair("file", pair("name", "logs/oauth2/oauth2.log")),
                Pair(
                    "logback.rollingpolicy", mutableMapOf(
                        Pair("file-name-pattern", "logs/oauth2/oauth2-%d{yyyy-MM-dd}.%i.log"),
                        Pair("max-file-size", "1MB"),
                        Pair("total-size-cap", "128MB"),
                    )
                )
            )
            mapConfig["clients"] = registerClient()
            YAMLMapper().writeValue(File(configRunningPath), mapConfig)
        } ?: exitProcess(1)

    }

    private fun pair(key: String, obj: Any): MutableMap<String, Any> = mutableMapOf(Pair(key, obj))

    private val clientConfig: JsonNode? by lazy {
        val ymlMap: ObjectMapper = YAMLMapper()
        val fi = File(clientPath)
        if (fi.exists()) ymlMap.readTree(fi) else null
    }

    fun registerClient(): MutableList<Clients> {
        return clientConfig?.let { gc ->
            val client = gc.get("clients")
            if (client.isNull) {
                mutableListOf()
            } else {
                client.map {
                    Clients(
                            it.get("client-id").asText(),
                            it.get("client-secret").asText(),
                            it.get("authorization-grant-types").toList().map { m -> m.toString().replace("\"", "") },
                            it.get("scopes").toList().map { m -> m.toString().replace("\"", "")  },
                            it.get("access-token-expired").asText().toLong(),
                            it.get("refresh-token-expired").asText().toLong(),
                            it.get("redirect-url")?.asText()
                    )
                }.toMutableList()
            }

        } ?: mutableListOf()
    }

    val getAuth: Auth by lazy {
        configYml?.let {
            val ip = it.get("auth").get("ip")
            val port = it.get("auth").get("port")
            Auth(if (ip.isNull) "localhost" else ip.asText(), if (port.isNull) "8080" else port.asText())
        } ?: Auth("localhost", "8080")
    }

    val accessClient: UnirestInstance by lazy {
        val ni = Unirest.spawnInstance()
        ni.config().interceptor(UInterceptor())
        ni
    }

    val getResource: Resource by lazy {
        configYml?.let {
            val ip = it.get("resource").get("ip")
            val port = it.get("resource").get("port")
            Resource(if (ip.isNull) "localhost" else ip.asText(), if (port.isNull) "8081" else port.asText())
        } ?: Resource("localhost", "8081")
    }

}

class Clients(
        val clientId: String, val clientSecret: String, val authorizationGrantTypes: List<String>,
        val scopes: List<String>, val accessTokenExpired: Long, val refreshTokenExpired: Long,
        var redirectUrl: String?
)

class Auth(val ip: String, val port: String) {
    var url: String = ""

    init {
        url = if (ip.startsWith("http")) "$ip:$port" else "http://$ip:$port"
    }
}

class Resource(val ip: String, val port: String) {
    var url: String = ""

    init {
        url = if (ip.startsWith("http")) "$ip:$port" else "http://$ip:$port"
    }
}