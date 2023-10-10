compile:
	mvn clean compile -DskipUnitTests -DskipITtests -s WebAPIConfig/settings.xml -P webapi-postgresql

package: compile
	mvn package -DskipUnitTests -DskipITtests -s WebAPIConfig/settings.xml -P webapi-postgresql

deploy: package
	sudo /home/ubuntu/Downloads/apache-tomcat-8.5.84-Gen3/bin/shutdown.sh 
	sudo mv /home/ubuntu/Downloads/apache-tomcat-8.5.84-Gen3/webapps/WebAPI /mnt/disk1/webapi-dev-tmp/WebAPI-FOLDER-`date +%m%d%H%S`
	sudo mv /home/ubuntu/Downloads/apache-tomcat-8.5.84-Gen3/webapps/WebAPI.war /mnt/disk1/webapi-dev-tmp/WebAPI.war-`date +%m%d%H%S`
	sudo mv target/WebAPI.war /home/ubuntu/Downloads/apache-tomcat-8.5.84-Gen3/webapps/
	echo "Now run sudo /home/ubuntu/Downloads/apache-tomcat-8.5.84-Gen3/bin/startup.sh"

git-push:
	git push

test:
	wget -O /tmp/tests/test-drug-rollup-branded-drug.json "http://api.ohdsi.org/WebAPI/CS1/evidence/drugrollup/brandeddrug/1000640"

test-public:
	wget -O /tmp/tests/test-drug-rollup-branded-drug.json "http://api.ohdsi.org/WebAPI/CS1/evidence/drugrollup/brandeddrug/1000640"
