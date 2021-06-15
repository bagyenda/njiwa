FROM jboss/wildfly
ADD standalone.xml           /opt/jboss/wildfly/standalone/configuration/standalone.xml
ADD module.xml               /opt/jboss/wildfly/modules/io/njiwa/main/
ADD njiwa.settings           /opt/jboss/wildfly/modules/io/njiwa/main/
ADD postgresql-42.2.21.jar   /opt/jboss/wildfly/standalone/deployments/postgresql.jar
ADD build/libs/njiwa-0.8.war /opt/jboss/wildfly/standalone/deployments/njiwa.war
RUN /opt/jboss/wildfly/bin/add-user.sh admin Pa5avohm --silent
CMD ["/opt/jboss/wildfly/bin/standalone.sh", "-b", "0.0.0.0", "-bmanagement", "0.0.0.0"]
