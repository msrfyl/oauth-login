package msrfyl.app.oauth

import kong.unirest.*
import org.slf4j.LoggerFactory

class UInterceptor : Interceptor {
    private val logger = LoggerFactory.getLogger(UInterceptor::class.java)
    override fun onRequest(request: HttpRequest<*>, config: Config) {
        val token = U.loadToken()
        println("token: $token")
        request.header("Authorization", "Bearer $token")
        request.header("Content-Type", "application/json")
        super.onRequest(request, config)
    }

    override fun onResponse(response: HttpResponse<*>, request: HttpRequestSummary, config: Config) {
        response.ifFailure { it.parsingError.ifPresent { e -> logger.error("error response", e) } }
        super.onResponse(response, request, config)
    }
}