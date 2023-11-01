package msrfyl.app.oauth

import org.slf4j.LoggerFactory
import org.springframework.boot.context.event.ApplicationReadyEvent
import org.springframework.context.event.EventListener
import org.springframework.stereotype.Component

@Component
class EventListeners() {

    @EventListener(ApplicationReadyEvent::class)
    fun onAppReady() {
        val logger = LoggerFactory.getLogger(OauthApplication::class.java)
        logger.info("application is ready")
    }

}