package msrfyl.app.oauth

import kong.unirest.*
import org.slf4j.LoggerFactory

class UInterceptor : Interceptor {
    private val logger = LoggerFactory.getLogger(UInterceptor::class.java)
    override fun onRequest(request: HttpRequest<*>, config: Config) {
        val token = loadToken()
        request.header("Authorization", "Bearer $token")
//        println(token)
        super.onRequest(request, config)
    }

    override fun onResponse(response: HttpResponse<*>, request: HttpRequestSummary, config: Config) {
        response.ifFailure { it.parsingError.ifPresent { e -> logger.error("error response", e) } }
        super.onResponse(response, request, config)
    }

    @Synchronized
    fun loadToken(): String {
        val clientAuth = U.registerClient().first()
        val resp = Unirest.post("${U.authUrl}/oauth2/token")
            .basicAuth(clientAuth.clientId, clientAuth.clientSecret)
            .field("grant_type", clientAuth.authorizationGrantTypes)
            .asJson().ifFailure {
                logger.info("load token failed")
            }
        return resp.body.`object`["access_token"].toString()
    }
}