# Keycloak REST events
 
Send keycloak events to configure URL.

## Installation

Build jar:

```bash
mvn clean install
```

Add module to Keycloak:

```bash
KEYCLOAK_HOME/bin/jboss-cli.sh --command="module add --name=io.signmykey.keycloak.events.pusher --resources=/opt/keycloak/keycloak-events-pusher.jar --dependencies=org.keycloak.keycloak-core,org.keycloak.keycloak-server-spi,org.keycloak.keycloak-server-spi-private,org.apache.httpcomponents,com.fasterxml.jackson.core.jackson-databind"
```

In configuration file (```standalone/configuration/standalone.xml```) add:

```xml
<providers>
    ...
    <provider>module:io.signmykey.keycloak.events.pusher</provider>
</providers>
```

Configuration module:

```xml
<subsystem xmlns="urn:jboss:domain:keycloak-server:1.1">
    ...
    <spi name="eventsListener">
        <provider name="events-pusher" enabled="true">
            <properties>
                <property name="excludes" value="[]"/>
                <property name="eventsUrl" value="http://signmykey.redzone.trustinnotech.agency/v1/webhooks/keycloack-events"/>
                <property name="excludesOperations" value="[]"/>
                <property name="operationsUrl" value="http://signmykey.redzone.trustinnotech.agency/v1/webhooks/keycloack-admin-events"/>
                <property name="authKey" value="${auth key you add in signmykey config}"/>
            </properties>
        </provider>
    </spi>
</subsystem>
```

In Admin Console (Events menu) add Event Listener:  "events-rest"
