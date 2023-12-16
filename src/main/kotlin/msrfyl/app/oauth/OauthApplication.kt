package msrfyl.app.oauth

import org.slf4j.LoggerFactory
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken
import org.springframework.security.web.WebAttributes
import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestParam
import java.io.File
import java.io.OutputStream
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

@SpringBootApplication
class OauthApplication

fun main(args: Array<String>) {
    System.setProperty("user.timezone", "Asia/Jakarta")
    val logger = LoggerFactory.getLogger(OauthApplication::class.java)
    logger.info("starting application")
    U.buildConfiguration()
    runApplication<OauthApplication>(*args, "--spring.config.location=./${U.configRunningPath}")
}

@Controller
class LoginController {
    @GetMapping("/login")
    fun getLoginPage(
        model: Model, req: HttpServletRequest,
        @RequestParam(value = "error", defaultValue = "false") loginError: Boolean
    ): String {
        if (loginError) {
            val message = try {
                val ex = req.session.getAttribute(WebAttributes.AUTHENTICATION_EXCEPTION) as BadCredentialsException
                ex.message ?: "username and password didn't match"
            } catch (e: Exception) {
                e.printStackTrace()
                "username and password didn't match"
            }
            model.addAttribute("errorMessage", message)
        }
        return "login"
    }

    @GetMapping("/bg")
    fun bg(response: HttpServletResponse) {
        response.contentType = "image/jpg"
        val file = File("bg.jpg")
        val outputStream: OutputStream = response.outputStream
        outputStream.write(file.readBytes())
    }

}
